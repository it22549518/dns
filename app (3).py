from flask import Flask, render_template, request, jsonify, send_file
import subprocess
import csv
import json
import os
import io
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

app = Flask(__name__)

RECORDS_FILE = "data/dns_records.json"
CHANGE_LOG   = "logs/change_history.json"
DNS_SERVER   = "192.168.13.80"
DNS_USER     = "user1"          # username on the DNS server
DNS_PASS     = "12345com@-"     # password  (kept only in this file, never sent to browser)
BIND_HOST    = "127.0.0.1"
BIND_PORT    = 5000
PARALLEL_WORKERS = 10   # simultaneous DNS changes (safe for most DNS servers)

# ── helpers ───────────────────────────────────────────────────────────────────

def load_records():
    if not os.path.exists(RECORDS_FILE):
        return []
    with open(RECORDS_FILE) as f:
        return json.load(f)

def save_records(records):
    with open(RECORDS_FILE, "w") as f:
        json.dump(records, f, indent=2)

def load_change_log():
    if not os.path.exists(CHANGE_LOG):
        return []
    with open(CHANGE_LOG) as f:
        return json.load(f)

def append_change_log(entry):
    log = load_change_log()
    log.insert(0, entry)
    with open(CHANGE_LOG, "w") as f:
        json.dump(log[:500], f, indent=2)

# ── PowerShell runner ─────────────────────────────────────────────────────────

def run_ps(script: str, timeout: int = 30):
    """
    Run a PowerShell script and return (stdout+stderr, returncode).
    Credentials are injected as SecureString — password never echoed in logs.
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout
        )
        return (result.stdout + result.stderr).strip(), result.returncode
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s", -1
    except FileNotFoundError:
        return "ERROR: PowerShell not found on this PC", -1
    except Exception as e:
        return f"ERROR: {e}", -1


def make_cred_block():
    """
    Returns a PowerShell snippet that builds a PSCredential from the
    hardcoded user/pass.  Password becomes a SecureString in memory.
    """
    return f"""
$pass = ConvertTo-SecureString '{DNS_PASS}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('{DNS_USER}', $pass)
"""


# ── connection test ───────────────────────────────────────────────────────────

def test_winrm_connection():
    """
    Returns (ok: bool, message: str, detail: str)
    Tries three methods in order:
      1. WinRM Invoke-Command (preferred)
      2. DNS module with -ComputerName (RSAT)
      3. Plain ping + port test
    """
    # Step 1 — ping
    ping_ps = f"Test-Connection -ComputerName {DNS_SERVER} -Count 1 -Quiet"
    out, rc = run_ps(ping_ps, timeout=10)
    ping_ok = "True" in out or rc == 0

    # Step 2 — TCP port 5985 (WinRM)
    port_ps = f"""
$tcp = New-Object System.Net.Sockets.TcpClient
try {{
    $tcp.Connect('{DNS_SERVER}', 5985)
    Write-Output "PORT_OPEN"
}} catch {{
    Write-Output "PORT_CLOSED:$($_.Exception.Message)"
}} finally {{ $tcp.Close() }}
"""
    port_out, _ = run_ps(port_ps, timeout=8)
    winrm_port_open = "PORT_OPEN" in port_out

    # Step 3 — WinRM Invoke-Command test
    winrm_ps = make_cred_block() + f"""
try {{
    $r = Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred `
         -ScriptBlock {{ "WINRM_OK" }} -ErrorAction Stop
    Write-Output $r
}} catch {{
    Write-Output "WINRM_FAIL:$($_.Exception.Message)"
}}
"""
    winrm_out, _ = run_ps(winrm_ps, timeout=20)
    winrm_ok = "WINRM_OK" in winrm_out

    # Step 4 — DNS module via WinRM
    dns_ps = make_cred_block() + f"""
try {{
    $zones = Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred -ScriptBlock {{
        Import-Module DnsServer -ErrorAction SilentlyContinue
        (Get-DnsServerZone -ErrorAction Stop | Where-Object {{ !$_.IsAutoCreated }} | Select-Object -First 5 ZoneName).ZoneName
    }} -ErrorAction Stop
    Write-Output "ZONES:$($zones -join ',')"
}} catch {{
    Write-Output "DNS_FAIL:$($_.Exception.Message)"
}}
"""
    dns_out, _ = run_ps(dns_ps, timeout=25)
    dns_ok = "ZONES:" in dns_out

    zones = []
    if dns_ok:
        zones = dns_out.replace("ZONES:", "").split(",")

    return {
        "ping":          ping_ok,
        "winrm_port":    winrm_port_open,
        "winrm_auth":    winrm_ok,
        "dns_module":    dns_ok,
        "zones":         zones,
        "winrm_detail":  winrm_out if not winrm_ok else "",
        "dns_detail":    dns_out   if not dns_ok   else "",
        "port_detail":   port_out  if not winrm_port_open else "",
        "overall":       winrm_ok or dns_ok,
    }


# ── DNS read / write ──────────────────────────────────────────────────────────

def dns_get_record(zone, record_name):
    """
    Query current A-record IP for one record.
    Returns (ip_string, None) or (None, error_string).
    """
    ps = make_cred_block() + f"""
$ErrorActionPreference = 'Stop'
try {{
    $r = Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred -ScriptBlock {{
        param($z, $n)
        Import-Module DnsServer -ErrorAction SilentlyContinue
        $rec = Get-DnsServerResourceRecord -ZoneName $z -Name $n -RRType A -ErrorAction Stop
        ($rec | Select-Object -First 1).RecordData.IPv4Address.ToString()
    }} -ArgumentList '{zone}', '{record_name}' -ErrorAction Stop
    Write-Output "IP:$r"
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
}}
"""
    out, _ = run_ps(ps, timeout=20)
    if out.startswith("IP:"):
        return out[3:].strip(), None
    return None, out.replace("ERROR:", "").strip() or "Unknown error"


def dns_set_record(zone, record_name, new_ip):
    """
    Update an A record.
    Returns (True, 'Updated successfully') or (False, error_string).
    """
    ps = make_cred_block() + f"""
$ErrorActionPreference = 'Stop'
try {{
    $result = Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred -ScriptBlock {{
        param($zone, $name, $newip)
        Import-Module DnsServer -ErrorAction SilentlyContinue
        $ErrorActionPreference = 'Stop'
        $existing = Get-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType A
        $updated  = $existing.Clone()
        $updated.RecordData.IPv4Address = [System.Net.IPAddress]::Parse($newip)
        Set-DnsServerResourceRecord -ZoneName $zone -OldInputObject $existing -NewInputObject $updated
        "SUCCESS"
    }} -ArgumentList '{zone}', '{record_name}', '{new_ip}' -ErrorAction Stop
    Write-Output $result
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
}}
"""
    out, _ = run_ps(ps, timeout=30)
    if "SUCCESS" in out:
        return True, "Updated successfully"
    return False, out.replace("ERROR:", "").strip() or "Unknown error"


# ── background job ────────────────────────────────────────────────────────────

job_state = {
    "running": False, "direction": None, "total": 0,
    "done": 0, "results": [], "started_at": None,
    "finished_at": None, "logged_user": DNS_USER,
}
job_lock = threading.Lock()


def _change_one(rec, direction):
    """Change a single DNS record. Runs inside thread pool."""
    target_ip = rec["dr_ip"] if direction == "DR" else rec["ho_ip"]
    from_ip   = rec["ho_ip"] if direction == "DR" else rec["dr_ip"]
    ok, msg   = dns_set_record(rec["zone"], rec["record_name"], target_ip)
    return {
        "app_name":    rec["app_name"],
        "record_name": rec["record_name"],
        "zone":        rec["zone"],
        "from_ip":     from_ip,
        "to_ip":       target_ip,
        "status":      "success" if ok else "failed",
        "message":     msg,
        "timestamp":   datetime.now().isoformat(),
    }


def run_bulk_job(direction, records_to_change):
    """
    Parallel DNS bulk change using ThreadPoolExecutor.
    PARALLEL_WORKERS records are updated simultaneously.
    600 records @ 10 workers ~ 1-2 minutes instead of 10-15 minutes.
    """
    session_results = []

    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        # Submit all jobs
        future_map = {}
        for rec in records_to_change:
            with job_lock:
                if not job_state["running"]:
                    break
            future = executor.submit(_change_one, rec, direction)
            future_map[future] = rec

        # Collect results as they complete
        for future in as_completed(future_map):
            with job_lock:
                if not job_state["running"]:
                    # Abort — cancel pending futures
                    for f in future_map:
                        f.cancel()
                    break
            try:
                entry = future.result(timeout=35)
            except Exception as e:
                rec = future_map[future]
                entry = {
                    "app_name":    rec["app_name"],
                    "record_name": rec["record_name"],
                    "zone":        rec["zone"],
                    "from_ip":     rec["ho_ip"] if direction == "DR" else rec["dr_ip"],
                    "to_ip":       rec["dr_ip"] if direction == "DR" else rec["ho_ip"],
                    "status":      "failed",
                    "message":     str(e),
                    "timestamp":   datetime.now().isoformat(),
                }

            session_results.append(entry)
            with job_lock:
                job_state["done"] += 1
                job_state["results"].append(entry)

    with job_lock:
        job_state["running"] = False
        job_state["finished_at"] = datetime.now().isoformat()

    append_change_log({
        "session":    datetime.now().isoformat(),
        "direction":  direction,
        "dns_server": DNS_SERVER,
        "logged_as":  DNS_USER,
        "total":      len(records_to_change),
        "success":    sum(1 for r in session_results if r["status"] == "success"),
        "failed":     sum(1 for r in session_results if r["status"] == "failed"),
        "records":    session_results,
    })


import re

# ── IP validation ─────────────────────────────────────────────────────────────

def is_valid_ip(ip):
    """Check if string is a valid IPv4 address."""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    m = re.match(pattern, str(ip).strip())
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def validate_record_fields(rec):
    """
    Check all fields of a record locally (no DNS query).
    Returns list of error strings — empty list means OK.
    """
    errors = []
    if not str(rec.get("app_name","")).strip():
        errors.append("App name is empty")
    if not str(rec.get("record_name","")).strip():
        errors.append("Record name is empty")
    if not str(rec.get("zone","")).strip():
        errors.append("Zone is empty")
    ho = str(rec.get("ho_ip","")).strip()
    dr = str(rec.get("dr_ip","")).strip()
    if not ho:
        errors.append("HO IP is empty")
    elif not is_valid_ip(ho):
        errors.append(f"HO IP '{ho}' is not a valid IPv4 address")
    if not dr:
        errors.append("DR IP is empty")
    elif not is_valid_ip(dr):
        errors.append(f"DR IP '{dr}' is not a valid IPv4 address")
    if ho and dr and is_valid_ip(ho) and is_valid_ip(dr) and ho == dr:
        errors.append("HO IP and DR IP are the same — nothing would change")
    return errors


def verify_one_record(rec, direction):
    """
    Full verification of one record against the live DNS server:
    1. Local field validation
    2. Check record exists in DNS
    3. Check current IP matches expected source IP
    4. Check target IP is reachable (optional ping)
    Returns dict with status, current_ip, issues list
    """
    issues = []

    # Step 1 — local validation
    field_errors = validate_record_fields(rec)
    if field_errors:
        return {
            "id":          rec.get("id"),
            "app_name":    rec.get("app_name"),
            "record_name": rec.get("record_name"),
            "zone":        rec.get("zone"),
            "ho_ip":       rec.get("ho_ip"),
            "dr_ip":       rec.get("dr_ip"),
            "current_ip":  None,
            "target_ip":   rec.get("dr_ip") if direction == "DR" else rec.get("ho_ip"),
            "status":      "invalid",
            "issues":      field_errors,
            "can_change":  False,
        }

    # Step 2 — check record exists in DNS and get current IP
    current_ip, err = dns_get_record(rec.get("zone",""), rec.get("record_name",""))

    if err:
        # Check if it's a "not found" error vs connection error
        not_found = any(x in err.lower() for x in [
            "not found", "does not exist", "no records",
            "record not found", "objectnotfound"
        ])
        issues.append(("NOT FOUND" if not_found else "DNS ERROR") + ": " + err)
        return {
            "id":          rec.get("id"),
            "app_name":    rec.get("app_name"),
            "record_name": rec.get("record_name"),
            "zone":        rec.get("zone"),
            "ho_ip":       rec.get("ho_ip"),
            "dr_ip":       rec.get("dr_ip"),
            "current_ip":  None,
            "target_ip":   rec.get("dr_ip") if direction == "DR" else rec.get("ho_ip"),
            "status":      "not_found" if not_found else "error",
            "issues":      issues,
            "can_change":  False,
        }

    # Step 3 — check if already pointing to target
    target_ip = rec.get("dr_ip") if direction == "DR" else rec.get("ho_ip")
    source_ip = rec.get("ho_ip") if direction == "DR" else rec.get("dr_ip")

    if current_ip == target_ip:
        issues.append(f"Already pointing to {target_ip} — no change needed")
        status = "already_done"
        can_change = False
    elif current_ip != source_ip:
        # Current IP is neither HO nor DR — unexpected
        issues.append(
            f"Current IP {current_ip} doesn't match expected "
            f"{'HO' if direction=='DR' else 'DR'} IP {source_ip}. "
            f"This record may have been changed manually."
        )
        status = "warning"
        can_change = True   # allow it but warn
    else:
        status = "ready"
        can_change = True

    return {
        "id":          rec.get("id"),
        "app_name":    rec.get("app_name"),
        "record_name": rec.get("record_name"),
        "zone":        rec.get("zone"),
        "ho_ip":       rec.get("ho_ip"),
        "dr_ip":       rec.get("dr_ip"),
        "current_ip":  current_ip,
        "target_ip":   target_ip,
        "status":      status,
        "issues":      issues,
        "can_change":  can_change,
    }


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", dns_server=DNS_SERVER)

@app.route("/api/test-connection", methods=["GET"])
def test_connection():
    result = test_winrm_connection()
    return jsonify(result)

@app.route("/api/records", methods=["GET"])
def get_records():
    q = request.args.get("q", "").lower()
    records = load_records()
    if q:
        records = [r for r in records if
                   q in r["app_name"].lower() or
                   q in r["record_name"].lower() or
                   q in r["zone"].lower() or
                   q in r.get("ho_ip", "") or
                   q in r.get("dr_ip", "")]
    return jsonify(records)

@app.route("/api/records", methods=["POST"])
def add_record():
    data = request.json
    if not all(k in data for k in ["app_name", "record_name", "zone", "ho_ip", "dr_ip"]):
        return jsonify({"error": "Missing fields"}), 400
    records = load_records()
    data["id"] = datetime.now().timestamp()
    records.append(data)
    save_records(records)
    return jsonify({"ok": True})

@app.route("/api/records/<record_id>", methods=["DELETE"])
def delete_record(record_id):
    records = [r for r in load_records() if str(r.get("id")) != record_id]
    save_records(records)
    return jsonify({"ok": True})

@app.route("/api/records/import", methods=["POST"])
def import_csv():
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file"}), 400
    stream = io.StringIO(f.stream.read().decode("utf-8"))
    reader = csv.DictReader(stream)
    records = load_records()
    added, errors = 0, []
    for i, row in enumerate(reader, 1):
        try:
            records.append({
                "id":          datetime.now().timestamp() + i,
                "app_name":    row["app_name"].strip(),
                "record_name": row["record_name"].strip(),
                "zone":        row["zone"].strip(),
                "ho_ip":       row["ho_ip"].strip(),
                "dr_ip":       row["dr_ip"].strip(),
            })
            added += 1
        except Exception as e:
            errors.append(f"Row {i}: {e}")
    save_records(records)
    return jsonify({"added": added, "errors": errors})

@app.route("/api/records/export", methods=["GET"])
def export_csv():
    records = load_records()
    si = io.StringIO()
    w = csv.DictWriter(si, fieldnames=["app_name", "record_name", "zone", "ho_ip", "dr_ip"])
    w.writeheader()
    for r in records:
        w.writerow({k: r.get(k, "") for k in ["app_name", "record_name", "zone", "ho_ip", "dr_ip"]})
    out = io.BytesIO(si.getvalue().encode())
    out.seek(0)
    return send_file(out, mimetype="text/csv", download_name="dns_records.csv", as_attachment=True)

def _fetch_one(rec):
    """Fetch current IP for one record. Runs inside thread pool."""
    ip, err = dns_get_record(rec.get("zone", ""), rec.get("record_name", ""))
    return {
        "id":          rec.get("id"),
        "app_name":    rec.get("app_name"),
        "record_name": rec.get("record_name"),
        "zone":        rec.get("zone"),
        "ho_ip":       rec.get("ho_ip"),
        "dr_ip":       rec.get("dr_ip"),
        "current_ip":  ip,
        "error":       err,
    }


@app.route("/api/records/live", methods=["POST"])
def live_dns():
    """Query DNS server for current A-record IP — parallel fetch."""
    data = request.json or {}
    record_ids = data.get("record_ids", [])
    all_recs = load_records()
    targets = (
        [r for r in all_recs if str(r.get("id")) in [str(x) for x in record_ids]]
        if record_ids else all_recs
    )

    results = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        future_map = {executor.submit(_fetch_one, rec): i
                      for i, rec in enumerate(targets)}
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                results[idx] = future.result(timeout=25)
            except Exception as e:
                rec = targets[idx]
                results[idx] = {
                    "id": rec.get("id"), "app_name": rec.get("app_name"),
                    "record_name": rec.get("record_name"), "zone": rec.get("zone"),
                    "ho_ip": rec.get("ho_ip"), "dr_ip": rec.get("dr_ip"),
                    "current_ip": None, "error": str(e),
                }
    return jsonify([r for r in results if r is not None])

@app.route("/api/job/start", methods=["POST"])
def start_job():
    global job_state
    with job_lock:
        if job_state["running"]:
            return jsonify({"error": "A job is already running"}), 409

    data      = request.json
    direction = data.get("direction")
    record_ids = data.get("record_ids", [])

    if direction not in ("DR", "HO"):
        return jsonify({"error": "direction must be DR or HO"}), 400

    all_recs = load_records()
    to_change = (
        [r for r in all_recs if str(r.get("id")) in [str(x) for x in record_ids]]
        if record_ids else all_recs
    )

    with job_lock:
        job_state = {
            "running":     True,
            "direction":   direction,
            "total":       len(to_change),
            "done":        0,
            "results":     [],
            "started_at":  datetime.now().isoformat(),
            "finished_at": None,
            "logged_user": DNS_USER,
        }

    threading.Thread(
        target=run_bulk_job,
        args=(direction, to_change),
        daemon=True
    ).start()

    return jsonify({"ok": True, "total": len(to_change), "logged_as": DNS_USER})

@app.route("/api/job/status", methods=["GET"])
def job_status():
    with job_lock:
        return jsonify(dict(job_state))

@app.route("/api/job/abort", methods=["POST"])
def abort_job():
    with job_lock:
        job_state["running"] = False
    return jsonify({"ok": True})

@app.route("/api/history", methods=["GET"])
def history():
    return jsonify(load_change_log())


@app.route("/api/dns/zones", methods=["GET"])
def get_dns_zones():
    """Get all Forward Lookup Zones from the DNS server."""
    ps = make_cred_block() + f"""
$ErrorActionPreference = 'Stop'
try {{
    $zones = Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred -ScriptBlock {{
        Import-Module DnsServer -ErrorAction SilentlyContinue
        Get-DnsServerZone | Where-Object {{
            -not $_.IsAutoCreated -and -not $_.IsReverseLookupZone
        }} | Select-Object ZoneName, ZoneType, IsDsIntegrated
    }} -ErrorAction Stop
    foreach ($z in $zones) {{
        Write-Output "ZONE:$($z.ZoneName)|$($z.ZoneType)|$($z.IsDsIntegrated)"
    }}
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
}}
"""
    out, _ = run_ps(ps, timeout=30)
    if "ERROR:" in out and "ZONE:" not in out:
        return jsonify({"error": out.replace("ERROR:","").strip()}), 500
    zones = []
    for line in out.splitlines():
        if line.startswith("ZONE:"):
            parts = line[5:].split("|")
            zones.append({
                "name": parts[0] if len(parts) > 0 else "",
                "type": parts[1] if len(parts) > 1 else "",
                "ds_integrated": parts[2] if len(parts) > 2 else "",
            })
    return jsonify(zones)


@app.route("/api/dns/records", methods=["GET"])
def get_dns_zone_records():
    """Get all A records from a specific zone."""
    zone = request.args.get("zone", "")
    if not zone:
        return jsonify({"error": "zone parameter required"}), 400
    ps = make_cred_block() + f"""
$ErrorActionPreference = 'Stop'
try {{
    $records = Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred -ScriptBlock {{
        param($z)
        Import-Module DnsServer -ErrorAction SilentlyContinue
        Get-DnsServerResourceRecord -ZoneName $z -RRType A -ErrorAction Stop |
            Select-Object HostName, @{{N='IP';E={{$_.RecordData.IPv4Address.ToString()}}}}, TimeToLive
    }} -ArgumentList '{zone}' -ErrorAction Stop
    foreach ($r in $records) {{
        Write-Output "REC:$($r.HostName)|$($r.IP)|$($r.TimeToLive)"
    }}
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
}}
"""
    out, _ = run_ps(ps, timeout=40)
    if "ERROR:" in out and "REC:" not in out:
        return jsonify({"error": out.replace("ERROR:","").strip()}), 500
    records = []
    for line in out.splitlines():
        if line.startswith("REC:"):
            parts = line[4:].split("|")
            records.append({
                "hostname": parts[0] if len(parts) > 0 else "",
                "ip":       parts[1] if len(parts) > 1 else "",
                "ttl":      parts[2] if len(parts) > 2 else "",
            })
    return jsonify({"zone": zone, "records": records})

@app.route("/api/job/speed", methods=["POST"])
def set_speed():
    """Adjust parallel workers on the fly."""
    global PARALLEL_WORKERS
    w = request.json.get("workers", 10)
    PARALLEL_WORKERS = max(1, min(int(w), 30))
    return jsonify({"workers": PARALLEL_WORKERS})


@app.route("/api/job/speed", methods=["GET"])
def get_speed():
    return jsonify({"workers": PARALLEL_WORKERS})



@app.route("/api/records/verify", methods=["POST"])
def verify_records():
    """
    Pre-flight check: validate all records before a DR/HO switch.
    Runs in parallel. Returns per-record status:
      ready       — exists in DNS, current IP matches expected source
      warning     — exists but current IP is unexpected (changed manually)
      already_done — already pointing to target IP
      not_found   — record name/zone doesn't exist in DNS
      invalid     — bad field data (empty, bad IP format)
      error       — DNS query failed
    """
    data      = request.json or {}
    direction = data.get("direction", "DR")
    record_ids = data.get("record_ids", [])
    all_recs  = load_records()
    targets   = (
        [r for r in all_recs if str(r.get("id")) in [str(x) for x in record_ids]]
        if record_ids else all_recs
    )

    results = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        future_map = {
            executor.submit(verify_one_record, rec, direction): i
            for i, rec in enumerate(targets)
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                results[idx] = future.result(timeout=25)
            except Exception as e:
                rec = targets[idx]
                results[idx] = {
                    "id": rec.get("id"), "app_name": rec.get("app_name"),
                    "record_name": rec.get("record_name"), "zone": rec.get("zone"),
                    "ho_ip": rec.get("ho_ip"), "dr_ip": rec.get("dr_ip"),
                    "current_ip": None, "target_ip": None,
                    "status": "error", "issues": [str(e)], "can_change": False,
                }

    valid_results = [r for r in results if r is not None]
    summary = {
        "total":        len(valid_results),
        "ready":        sum(1 for r in valid_results if r["status"] == "ready"),
        "warning":      sum(1 for r in valid_results if r["status"] == "warning"),
        "already_done": sum(1 for r in valid_results if r["status"] == "already_done"),
        "not_found":    sum(1 for r in valid_results if r["status"] == "not_found"),
        "invalid":      sum(1 for r in valid_results if r["status"] == "invalid"),
        "error":        sum(1 for r in valid_results if r["status"] == "error"),
        "can_change":   sum(1 for r in valid_results if r["can_change"]),
    }
    return jsonify({"summary": summary, "records": valid_results})

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    print(f"\n{'='*52}")
    print(f"  DNS DR Control Panel")
    print(f"  Dashboard : http://localhost:{BIND_PORT}")
    print(f"  DNS Server: {DNS_SERVER}  (user: {DNS_USER})")
    print(f"{'='*52}\n")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
