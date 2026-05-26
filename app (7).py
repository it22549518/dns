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
import openpyxl

app = Flask(__name__)

RECORDS_FILE = "data/dns_records.json"
CHANGE_LOG   = "logs/change_history.json"
DNS_SERVER   = "192.168.13.80"
DNS_USER     = "user1"          # username on the DNS server
DNS_PASS     = "12345com@-"     # password  (kept only in this file, never sent to browser)
BIND_HOST    = "127.0.0.1"
BIND_PORT    = 5000
PARALLEL_WORKERS = 20   # simultaneous DNS changes
BATCH_SIZE = 25          # records per single PowerShell call

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



def batch_dns_get_records(records):
    """
    Fetch IPs for a batch — all queries embedded directly in PS scriptblock.
    No argument passing = no WinRM serialization issues.
    Returns: dict of str(id) -> (ip, error)
    """
    if not records:
        return {}

    # Build one PS try/catch block per record, all hardcoded
    stmts = ""
    # Use a stable integer index as the PS-side key to avoid float precision issues.
    # We keep a mapping from index -> record id for result parsing.
    idx_to_rid = {}
    for idx, r in enumerate(records):
        rid  = str(r["id"])
        safe_idx = str(idx)
        idx_to_rid[safe_idx] = rid
        zone = str(r.get("zone","")).replace("'","").replace('"',"")
        name = str(r.get("record_name","")).replace("'","").replace('"',"")
        stmts += (
            f"try{{"
            f"$ip=(Get-DnsServerResourceRecord -ZoneName '{zone}' -Name '{name}' -RRType A -EA Stop"
            f"|Select -First 1).RecordData.IPv4Address.ToString();"
            f"Write-Output 'OK|{safe_idx}|'+$ip"
            f"}}catch{{Write-Output 'ERR|{safe_idx}|'+$_.Exception.Message}}\n"
        )

    ps = make_cred_block() + f"""
$ErrorActionPreference = 'Continue'
Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred -ScriptBlock {{
    Import-Module DnsServer -ErrorAction SilentlyContinue
    {stmts}
}}
"""
    out, _ = run_ps(ps, timeout=max(60, len(records) * 5))

    results = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("OK|"):
            parts = line.split("|", 2)
            if len(parts) == 3:
                safe_idx = parts[1].strip()
                rid = idx_to_rid.get(safe_idx, safe_idx)
                results[rid] = (parts[2].strip(), None)
        elif line.startswith("ERR|"):
            parts = line.split("|", 2)
            if len(parts) == 3:
                safe_idx = parts[1].strip()
                rid = idx_to_rid.get(safe_idx, safe_idx)
                err = parts[2].strip()
                not_found = any(x in err.lower() for x in
                    ["not found","does not exist","no records","objectnotfound"])
                results[rid] = (
                    None, ("NOT_FOUND:" if not_found else "") + err
                )
    for r in records:
        rid = str(r["id"])
        if rid not in results:
            results[rid] = (None, "No response from DNS server")
    return results

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
import openpyxl

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

def _normalise_col(name):
    """Normalise column header: lowercase, strip spaces/underscores."""
    return str(name).lower().strip().replace(" ", "_").replace("-", "_")


def _find_col(headers, *candidates):
    """Find first matching column from a list of candidate names."""
    norm = {_normalise_col(h): h for h in headers}
    for c in candidates:
        if _normalise_col(c) in norm:
            return norm[_normalise_col(c)]
    return None


def _parse_rows(rows, headers):
    """
    Parse rows into DNS records.
    Accepts columns in any order, with flexible naming.
    Required: app_name, zone, ho_ip, dr_ip
    Optional: record_name (defaults to app_name if missing)
    Returns (records_list, errors_list)
    """
    col_app  = _find_col(headers, "app_name","app","application","name","app name","application name")
    col_zone = _find_col(headers, "zone","dns_zone","dns zone","zone_name","zonename")
    col_ho   = _find_col(headers, "ho_ip","ho","head_office_ip","head office ip","primary_ip","primary","hq_ip","hq","production_ip","prod_ip")
    col_dr   = _find_col(headers, "dr_ip","dr","disaster_recovery_ip","disaster recovery ip","secondary_ip","secondary","backup_ip","dr site ip")
    col_rec  = _find_col(headers, "record_name","record","hostname","host","dns_record","dns record","fqdn")

    missing = []
    if not col_app:  missing.append("app_name")
    if not col_zone: missing.append("zone")
    if not col_ho:   missing.append("ho_ip")
    if not col_dr:   missing.append("dr_ip")
    if missing:
        return [], [f"Missing required columns: {', '.join(missing)}. Found columns: {', '.join(str(h) for h in headers)}"]

    records, errors = [], []
    for i, row in enumerate(rows, 1):
        try:
            app_name    = str(row.get(col_app,  "") or "").strip()
            zone        = str(row.get(col_zone, "") or "").strip()
            ho_ip       = str(row.get(col_ho,   "") or "").strip()
            dr_ip       = str(row.get(col_dr,   "") or "").strip()
            record_name = str(row.get(col_rec,  "") or "").strip() if col_rec else ""

            # Skip completely empty rows
            if not any([app_name, zone, ho_ip, dr_ip]):
                continue

            row_errors = []
            if not app_name:  row_errors.append("app_name empty")
            if not zone:      row_errors.append("zone empty")
            if not ho_ip:     row_errors.append("ho_ip empty")
            elif not is_valid_ip(ho_ip): row_errors.append(f"ho_ip '{ho_ip}' invalid")
            if not dr_ip:     row_errors.append("dr_ip empty")
            elif not is_valid_ip(dr_ip): row_errors.append(f"dr_ip '{dr_ip}' invalid")

            if row_errors:
                errors.append(f"Row {i} ({app_name or '?'}): {'; '.join(row_errors)}")
                continue

            # record_name defaults to app_name if not provided
            if not record_name:
                record_name = app_name

            records.append({
                "id":          datetime.now().timestamp() + i,
                "app_name":    app_name,
                "record_name": record_name,
                "zone":        zone,
                "ho_ip":       ho_ip,
                "dr_ip":       dr_ip,
            })
        except Exception as e:
            errors.append(f"Row {i}: {e}")

    return records, errors


@app.route("/api/records/import", methods=["POST"])
def import_csv():
    """
    Import DNS records from CSV or XLSX.
    Required columns (flexible naming): app_name, zone, ho_ip, dr_ip
    Optional: record_name (defaults to app_name)
    Replaces existing records if replace=true in query string.
    """
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file uploaded"}), 400

    filename  = (f.filename or "").lower()
    replace   = request.args.get("replace", "false").lower() == "true"
    new_records, errors = [], []

    try:
        # ── XLSX ──────────────────────────────────────────────────────────────
        if filename.endswith(".xlsx") or filename.endswith(".xls"):
            raw = f.stream.read()
            wb  = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
            ws  = wb.active
            all_rows = list(ws.iter_rows(values_only=True))
            if not all_rows:
                return jsonify({"error": "Excel file is empty"}), 400

            # Find header row — first row that has at least 3 non-empty cells
            header_idx = 0
            for idx, row in enumerate(all_rows):
                non_empty = [c for c in row if c is not None and str(c).strip()]
                if len(non_empty) >= 3:
                    header_idx = idx
                    break

            headers = [str(c) if c is not None else "" for c in all_rows[header_idx]]
            data_rows = []
            for row in all_rows[header_idx+1:]:
                row_dict = {headers[i]: (str(row[i]).strip() if row[i] is not None else "")
                            for i in range(min(len(headers), len(row)))}
                data_rows.append(row_dict)

            new_records, errors = _parse_rows(data_rows, headers)

        # ── CSV ───────────────────────────────────────────────────────────────
        else:
            raw_bytes = f.stream.read()
            # Try UTF-8 first, fall back to latin-1
            try:
                text = raw_bytes.decode("utf-8-sig")  # handles BOM
            except UnicodeDecodeError:
                text = raw_bytes.decode("latin-1")

            # Auto-detect delimiter (comma or semicolon or tab)
            sample = text[:2000]
            delimiter = ","
            if sample.count(";") > sample.count(","):
                delimiter = ";"
            elif sample.count("	") > sample.count(","):
                delimiter = "	"

            reader  = csv.DictReader(io.StringIO(text), delimiter=delimiter)
            headers = reader.fieldnames or []
            rows    = list(reader)
            new_records, errors = _parse_rows(rows, headers)

    except Exception as e:
        return jsonify({"error": f"Failed to read file: {e}"}), 500

    if not new_records and errors:
        return jsonify({"added": 0, "errors": errors, "replaced": False}), 400

    existing = [] if replace else load_records()
    save_records(existing + new_records)

    return jsonify({
        "added":    len(new_records),
        "errors":   errors,
        "replaced": replace,
        "message":  f"{'Replaced all records with' if replace else 'Added'} {len(new_records)} records" +
                    (f" ({len(errors)} rows skipped)" if errors else "")
    })

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

@app.route("/api/records/live", methods=["POST"])
def live_dns():
    """
    Query DNS for current IPs — uses batch queries.
    600 records in ~15s instead of minutes.
    """
    data = request.json or {}
    record_ids = data.get("record_ids", [])
    all_recs = load_records()
    targets = (
        [r for r in all_recs if str(r.get("id")) in [str(x) for x in record_ids]]
        if record_ids else all_recs
    )

    batches = [targets[i:i+BATCH_SIZE] for i in range(0, len(targets), BATCH_SIZE)]
    ip_map  = {}
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        future_map = {executor.submit(batch_dns_get_records, b): b for b in batches}
        for future in as_completed(future_map):
            try:
                ip_map.update(future.result(timeout=120))
            except Exception as e:
                for rec in future_map[future]:
                    ip_map[str(rec["id"])] = (None, str(e))

    results = []
    for rec in targets:
        rid = str(rec.get("id"))
        ip, err = ip_map.get(rid, (None, "No result"))
        results.append({
            "id":          rec.get("id"),
            "app_name":    rec.get("app_name"),
            "record_name": rec.get("record_name"),
            "zone":        rec.get("zone"),
            "ho_ip":       rec.get("ho_ip"),
            "dr_ip":       rec.get("dr_ip"),
            "current_ip":  ip,
            "error":       err,
        })
    return jsonify(results)

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
    Pre-flight check using BATCH queries.
    Splits records into batches of BATCH_SIZE, runs batches in parallel.
    600 records: ~25 batches of 25, run 20 at a time = ~15s total.
    """
    data       = request.json or {}
    direction  = data.get("direction", "DR")
    record_ids = data.get("record_ids", [])
    all_recs   = load_records()
    targets    = (
        [r for r in all_recs if str(r.get("id")) in [str(x) for x in record_ids]]
        if record_ids else all_recs
    )

    # Step 1: local field validation (instant, no DNS needed)
    invalid_ids = set()
    pre_results = {}
    for rec in targets:
        errs = validate_record_fields(rec)
        if errs:
            invalid_ids.add(str(rec.get("id")))
            pre_results[str(rec.get("id"))] = {
                "id": rec.get("id"), "app_name": rec.get("app_name"),
                "record_name": rec.get("record_name"), "zone": rec.get("zone"),
                "ho_ip": rec.get("ho_ip"), "dr_ip": rec.get("dr_ip"),
                "current_ip": None,
                "target_ip": rec.get("dr_ip") if direction=="DR" else rec.get("ho_ip"),
                "status": "invalid", "issues": errs, "can_change": False,
            }

    # Step 2: batch DNS queries for valid records only
    valid_targets = [r for r in targets if str(r.get("id")) not in invalid_ids]

    # Split into batches
    batches = [valid_targets[i:i+BATCH_SIZE]
               for i in range(0, len(valid_targets), BATCH_SIZE)]

    # Fetch all batches in parallel
    ip_map = {}   # id -> (ip, error)
    with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as executor:
        future_map = {
            executor.submit(batch_dns_get_records, batch): batch
            for batch in batches
        }
        for future in as_completed(future_map):
            try:
                batch_result = future.result(timeout=120)
                ip_map.update(batch_result)
            except Exception as e:
                # Mark entire batch as error
                for rec in future_map[future]:
                    ip_map[str(rec["id"])] = (None, f"Batch error: {e}")

    # Step 3: interpret results
    dns_results = {}
    for rec in valid_targets:
        rid        = str(rec.get("id"))
        target_ip  = rec.get("dr_ip") if direction=="DR" else rec.get("ho_ip")
        source_ip  = rec.get("ho_ip") if direction=="DR" else rec.get("dr_ip")
        current_ip, err = ip_map.get(rid, (None, "No result"))
        issues = []

        if err:
            not_found = "NOT_FOUND:" in str(err)
            status    = "not_found" if not_found else "error"
            issues.append(err.replace("NOT_FOUND:",""))
            can_change = False
        elif current_ip == target_ip:
            status     = "already_done"
            issues.append(f"Already pointing to {target_ip}")
            can_change = False
        elif current_ip != source_ip:
            status     = "warning"
            issues.append(
                f"Current IP {current_ip} doesn't match expected "
                f"{'HO' if direction=='DR' else 'DR'} IP {source_ip} — may have been changed manually"
            )
            can_change = True
        else:
            status     = "ready"
            can_change = True

        dns_results[rid] = {
            "id": rec.get("id"), "app_name": rec.get("app_name"),
            "record_name": rec.get("record_name"), "zone": rec.get("zone"),
            "ho_ip": rec.get("ho_ip"), "dr_ip": rec.get("dr_ip"),
            "current_ip": current_ip, "target_ip": target_ip,
            "status": status, "issues": issues, "can_change": can_change,
        }

    # Merge and preserve original order
    all_results = []
    for rec in targets:
        rid = str(rec.get("id"))
        if rid in pre_results:
            all_results.append(pre_results[rid])
        elif rid in dns_results:
            all_results.append(dns_results[rid])

    summary = {
        "total":        len(all_results),
        "ready":        sum(1 for r in all_results if r["status"] == "ready"),
        "warning":      sum(1 for r in all_results if r["status"] == "warning"),
        "already_done": sum(1 for r in all_results if r["status"] == "already_done"),
        "not_found":    sum(1 for r in all_results if r["status"] == "not_found"),
        "invalid":      sum(1 for r in all_results if r["status"] == "invalid"),
        "error":        sum(1 for r in all_results if r["status"] == "error"),
        "can_change":   sum(1 for r in all_results if r["can_change"]),
    }
    return jsonify({"summary": summary, "records": all_results})


@app.route("/api/debug/single", methods=["GET"])
def debug_single():
    """Test querying ONE record directly — shows raw PS output for diagnosis."""
    zone = request.args.get("zone","")
    name = request.args.get("name","")
    if not zone or not name:
        return jsonify({"error": "Pass ?zone=...&name=... in URL"}), 400

    ps = make_cred_block() + f"""
$ErrorActionPreference = 'Continue'
try {{
    $rec = Invoke-Command -ComputerName '{DNS_SERVER}' -Credential $cred -ScriptBlock {{
        param($z,$n)
        Import-Module DnsServer -ErrorAction SilentlyContinue
        $r = Get-DnsServerResourceRecord -ZoneName $z -Name $n -RRType A -ErrorAction Stop
        ($r | Select-Object -First 1).RecordData.IPv4Address.ToString()
    }} -ArgumentList '{zone}','{name}'
    Write-Output "IP:$rec"
}} catch {{
    Write-Output "ERROR:$($_.Exception.Message)"
}}
"""
    out, rc = run_ps(ps, timeout=20)
    return jsonify({"zone": zone, "name": name, "raw_output": out, "returncode": rc})


@app.route("/api/debug/batch", methods=["POST"])
def debug_batch():
    """Test batch query — shows raw PS output for up to 3 records."""
    recs = load_records()[:3]
    if not recs:
        return jsonify({"error": "No records loaded"}), 400
    result = batch_dns_get_records(recs)
    return jsonify({"records_tested": len(recs), "results": {k: list(v) for k,v in result.items()}})


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    print(f"\n{'='*52}")
    print(f"  DNS DR Control Panel")
    print(f"  Dashboard : http://localhost:{BIND_PORT}")
    print(f"  DNS Server: {DNS_SERVER}  (user: {DNS_USER})")
    print(f"{'='*52}\n")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
