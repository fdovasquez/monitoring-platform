#!/usr/bin/env python3
import json
import os
import re
import socket
import ssl
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


CONFIG_PATH = "/etc/oracle-monitoring-agent.env"
AGENT_VERSION = "1.0.3-oracle"


def load_env_file(path):
    env_path = Path(path)
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file(CONFIG_PATH)

API_URL = os.environ.get("ORACLE_API_URL") or os.environ.get("MONITORING_ORACLE_API_URL")
TOKEN = os.environ.get("ORACLE_AGENT_TOKEN") or os.environ.get("MONITORING_AGENT_TOKEN")
INTERVAL = int(os.environ.get("ORACLE_INTERVAL", "60"))
VERIFY_TLS = os.environ.get("ORACLE_VERIFY_TLS", "true").lower() not in ["0", "false", "no"]
CA_FILE = os.environ.get("ORACLE_CA_FILE", "")
ORACLE_RUN_AS_USER = os.environ.get("ORACLE_RUN_AS_USER", "oracle")
ORACLE_HOME = os.environ.get("ORACLE_HOME", "/opt/oracle/190000")
ORACLE_SID = os.environ.get("ORACLE_SID", "")
SQLPLUS = os.environ.get("ORACLE_SQLPLUS", f"{ORACLE_HOME}/bin/sqlplus")
LSNRCTL = os.environ.get("ORACLE_LSNRCTL", f"{ORACLE_HOME}/bin/lsnrctl")
RMAN = os.environ.get("ORACLE_RMAN", f"{ORACLE_HOME}/bin/rman")
ALERT_LOG_PATH = os.environ.get("ORACLE_ALERT_LOG_PATH", "")
BACKUP_WARNING_HOURS = int(os.environ.get("ORACLE_BACKUP_WARNING_HOURS", "24"))
BACKUP_CRITICAL_HOURS = int(os.environ.get("ORACLE_BACKUP_CRITICAL_HOURS", "48"))
TABLESPACE_WARNING_PERCENT = float(os.environ.get("ORACLE_TABLESPACE_WARNING_PERCENT", "85"))
TABLESPACE_CRITICAL_PERCENT = float(os.environ.get("ORACLE_TABLESPACE_CRITICAL_PERCENT", "95"))
FRA_WARNING_PERCENT = float(os.environ.get("ORACLE_FRA_WARNING_PERCENT", "80"))
FRA_CRITICAL_PERCENT = float(os.environ.get("ORACLE_FRA_CRITICAL_PERCENT", "90"))


def run_command(command, timeout=25, as_oracle=True):
    env_prefix = f"export ORACLE_HOME={shell_quote(ORACLE_HOME)}; "
    if ORACLE_SID:
        env_prefix += f"export ORACLE_SID={shell_quote(ORACLE_SID)}; "
    env_prefix += f"export PATH={shell_quote(ORACLE_HOME + '/bin')}:$PATH; "
    full_command = env_prefix + command
    try:
        if as_oracle and ORACLE_RUN_AS_USER and os.geteuid() == 0:
            args = ["su", "-", ORACLE_RUN_AS_USER, "-c", full_command]
            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
            )
        else:
            result = subprocess.run(
                full_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=timeout,
            )
    except Exception as exc:
        return "", str(exc), 1
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def shell_quote(value):
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def sql_query(sql, timeout=30):
    script = f"""
whenever sqlerror exit sql.sqlcode
set heading off
set feedback off
set pagesize 0
set verify off
set echo off
set trimspool on
set linesize 32767
{sql}
exit
"""
    script_path = write_temp_script(script, suffix=".sql")
    try:
        command = f"{shell_quote(SQLPLUS)} -s {shell_quote('/ as sysdba')} @{shell_quote(script_path)}"
        stdout, stderr, code = run_command(command, timeout=timeout)
        if code != 0:
            return "", (stderr or stdout)[-1000:]
        return stdout.strip(), ""
    finally:
        safe_unlink(script_path)


def write_temp_script(content, suffix):
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="oracle-agent-",
        suffix=suffix,
        delete=False,
    )
    with handle:
        handle.write(content)
    os.chmod(handle.name, 0o644)
    return handle.name


def safe_unlink(path):
    try:
        temp_path = Path(path)
        if temp_path.exists():
            temp_path.unlink()
    except OSError:
        pass


def clean_lines(output):
    return [line.strip() for line in output.splitlines() if line.strip()]


def first_line(output):
    lines = clean_lines(output)
    return lines[0] if lines else ""


def collect_database():
    output, error = sql_query(
        """
select
  (select name from v$database) || '|' ||
  (select database_role from v$database) || '|' ||
  (select instance_name from v$instance) || '|' ||
  (select status from v$instance) || '|' ||
  (select version from v$instance) || '|' ||
  (select to_char(startup_time,'YYYY-MM-DD HH24:MI:SS') from v$instance) || '|' ||
  (select value from v$diag_info where name = 'Diag Trace') || '|' ||
  (select value || '/alert_' || instance_name || '.log'
   from v$diag_info cross join v$instance where name = 'Diag Trace')
from dual;
"""
    )
    values = first_line(output).split("|") if output else []
    return {
        "database_name": values[0].strip() if len(values) > 0 else "",
        "database_role": values[1].strip() if len(values) > 1 else "",
        "instance_name": values[2].strip() if len(values) > 2 else "",
        "instance_status": values[3].strip() if len(values) > 3 else "",
        "version": values[4].strip() if len(values) > 4 else "",
        "startup_time": values[5].strip() if len(values) > 5 else "",
        "diag_trace": values[6].strip() if len(values) > 6 else "",
        "alert_log": ALERT_LOG_PATH or (values[7].strip() if len(values) > 7 else ""),
        "error": error,
    }


def collect_listener():
    stdout, stderr, code = run_command(f"{shell_quote(LSNRCTL)} status", timeout=20)
    output = stdout or stderr
    port_match = re.search(r"PORT=(\d+)", output)
    services = re.findall(r'Service "([^"]+)" has', output)
    return {
        "ok": code == 0 and "The command completed successfully" in output,
        "port": port_match.group(1) if port_match else "",
        "services": sorted(set(services))[:30],
        "summary": "Activo" if code == 0 else "No disponible",
        "error": "" if code == 0 else (stderr or stdout)[-1000:],
    }


def collect_tablespaces():
    output, error = sql_query(
        """
select tablespace_name || '|' || round(used_percent,2)
from dba_tablespace_usage_metrics
order by used_percent desc;
"""
    )
    tablespaces = []
    for line in clean_lines(output):
        if "|" not in line:
            continue
        name, percent = line.split("|", 1)
        try:
            used_percent = float(percent.strip())
        except ValueError:
            continue
        tablespaces.append({"name": name.strip(), "used_percent": used_percent})
    return {"items": tablespaces, "error": error}


def collect_fra():
    output, error = sql_query(
        """
select name || '|' ||
       round(space_used/1024/1024/1024,2) || '|' ||
       round(space_limit/1024/1024/1024,2) || '|' ||
       case when space_limit > 0 then round((space_used/space_limit)*100,2) else 0 end
from v$recovery_file_dest;
"""
    )
    items = []
    for line in clean_lines(output):
        parts = [part.strip() for part in line.split("|")]
        if len(parts) != 4:
            continue
        try:
            items.append(
                {
                    "name": parts[0],
                    "used_gb": float(parts[1]),
                    "limit_gb": float(parts[2]),
                    "used_percent": float(parts[3]),
                }
            )
        except ValueError:
            continue
    return {"items": items, "error": error}


def collect_blocking_sessions():
    output, error = sql_query("select count(*) from v$session where blocking_session is not null;")
    try:
        count = int(first_line(output) or "0")
    except ValueError:
        count = 0
    return {"count": count, "error": error}


def collect_rman_backups():
    script_path = write_temp_script("LIST BACKUP SUMMARY;\nEXIT;\n", suffix=".rman")
    try:
        stdout, stderr, code = run_command(f"{shell_quote(RMAN)} target / cmdfile {shell_quote(script_path)}", timeout=60)
    finally:
        safe_unlink(script_path)
    output = stdout or stderr
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not re.match(r"^\d+\s+", line):
            continue
        parts = line.split()
        if len(parts) < 10:
            continue
        completion = parts[5]
        entry = {
            "key": parts[0],
            "type": parts[1],
            "level": parts[2],
            "status": parts[3],
            "device_type": parts[4],
            "completion_time": completion,
            "pieces": parts[6],
            "copies": parts[7],
            "compressed": parts[8],
            "tag": " ".join(parts[9:]),
        }
        parsed_completion = parse_rman_date(completion)
        if parsed_completion:
            entry["completion_iso"] = parsed_completion.isoformat()
            entry["age_hours"] = round((datetime.now(timezone.utc) - parsed_completion).total_seconds() / 3600, 2)
        entries.append(entry)
    latest = entries[-1] if entries else None
    return {
        "ok": code == 0 and bool(entries),
        "latest": latest,
        "recent": entries[-10:],
        "count": len(entries),
        "error": "" if code == 0 else (stderr or stdout)[-500:],
    }


def parse_rman_date(value):
    month_map = {
        "JAN": 1, "ENE": 1,
        "FEB": 2,
        "MAR": 3,
        "APR": 4, "ABR": 4,
        "MAY": 5,
        "JUN": 6,
        "JUL": 7,
        "AUG": 8, "AGO": 8,
        "SEP": 9,
        "OCT": 10,
        "NOV": 11,
        "DEC": 12, "DIC": 12,
    }
    match = re.match(r"^(\d{2})-([A-Z]{3})-(\d{2})$", value.upper())
    if not match:
        return None
    day = int(match.group(1))
    month = month_map.get(match.group(2))
    year = 2000 + int(match.group(3))
    if not month:
        return None
    return datetime(year, month, day, tzinfo=timezone.utc)


def collect_alert_log(path):
    if not path:
        return {"path": "", "findings": [], "error": "Ruta de alert log no detectada."}
    log_path = Path(path)
    if not log_path.exists():
        return {"path": path, "findings": [], "error": "Archivo no encontrado."}
    try:
        lines = tail_lines(log_path, 500)
    except OSError as exc:
        return {"path": path, "findings": [], "error": str(exc)}
    findings = []
    pattern = re.compile(r"\b(ORA-\d{5}|TNS-\d{5}|RMAN-\d{5})\b")
    ignored = {"ORA-00000"}
    for line in lines:
        matches = [item for item in pattern.findall(line) if item not in ignored]
        if matches:
            findings.append({"code": matches[0], "message": line[-700:]})
            if len(findings) >= 30:
                break
    return {"path": path, "findings": findings, "error": ""}


def tail_lines(path, limit):
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        block_size = 4096
        data = b""
        while end > 0 and data.count(b"\n") <= limit:
            step = min(block_size, end)
            end -= step
            handle.seek(end)
            data = handle.read(step) + data
        return data.decode("utf-8", errors="replace").splitlines()[-limit:]


def evaluate_status(database, listener, tablespaces, fra, backups, blocking, alert_log):
    critical = []
    warnings = []
    if database.get("instance_status") != "OPEN":
        critical.append(f"Instancia {database.get('instance_name') or ''} no esta OPEN.")
    if not listener.get("ok"):
        critical.append("Listener no disponible.")
    for tablespace in tablespaces.get("items", []):
        percent = tablespace.get("used_percent", 0)
        if percent >= TABLESPACE_CRITICAL_PERCENT:
            critical.append(f"Tablespace {tablespace.get('name')} en {percent}%.")
        elif percent >= TABLESPACE_WARNING_PERCENT:
            warnings.append(f"Tablespace {tablespace.get('name')} en {percent}%.")
    for fra_item in fra.get("items", []):
        percent = fra_item.get("used_percent", 0)
        if percent >= FRA_CRITICAL_PERCENT:
            critical.append(f"FRA {fra_item.get('name')} en {percent}%.")
        elif percent >= FRA_WARNING_PERCENT:
            warnings.append(f"FRA {fra_item.get('name')} en {percent}%.")
    latest_backup = backups.get("latest") or {}
    age_hours = latest_backup.get("age_hours")
    if not backups.get("ok"):
        critical.append("No se detectaron respaldos RMAN.")
    elif age_hours is not None and age_hours > BACKUP_CRITICAL_HOURS:
        critical.append(f"Ultimo respaldo RMAN hace {age_hours} horas.")
    elif age_hours is not None and age_hours > BACKUP_WARNING_HOURS:
        warnings.append(f"Ultimo respaldo RMAN hace {age_hours} horas.")
    if blocking.get("count", 0) > 0:
        warnings.append(f"{blocking.get('count')} sesiones bloqueadas.")
    if alert_log.get("findings"):
        warnings.append(f"{len(alert_log['findings'])} hallazgo(s) recientes en alert log.")

    if critical:
        return "critical", "; ".join(critical[:3])
    if warnings:
        return "warning", "; ".join(warnings[:3])
    return "healthy", "Base Oracle operativa, listener activo y respaldos RMAN detectados."


def build_payload():
    database = collect_database()
    listener = collect_listener()
    tablespaces = collect_tablespaces()
    fra = collect_fra()
    backups = collect_rman_backups()
    blocking = collect_blocking_sessions()
    alert_log = collect_alert_log(database.get("alert_log"))
    status, summary = evaluate_status(database, listener, tablespaces, fra, backups, blocking, alert_log)
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "agent_version": AGENT_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "summary": summary,
        "database": database,
        "listener": listener,
        "tablespaces": tablespaces,
        "fra": fra,
        "backups": backups,
        "blocking_sessions": blocking,
        "alert_log": alert_log,
        "thresholds": {
            "tablespace_warning_percent": TABLESPACE_WARNING_PERCENT,
            "tablespace_critical_percent": TABLESPACE_CRITICAL_PERCENT,
            "fra_warning_percent": FRA_WARNING_PERCENT,
            "fra_critical_percent": FRA_CRITICAL_PERCENT,
            "backup_warning_hours": BACKUP_WARNING_HOURS,
            "backup_critical_hours": BACKUP_CRITICAL_HOURS,
        },
    }


def ssl_context():
    if not VERIFY_TLS:
        return ssl._create_unverified_context()
    if CA_FILE:
        return ssl.create_default_context(cafile=CA_FILE)
    return ssl.create_default_context()


def send_report():
    if not API_URL or not TOKEN:
        raise RuntimeError("ORACLE_API_URL y ORACLE_AGENT_TOKEN son requeridos.")
    payload = build_payload()
    errors = collection_errors(payload)
    if errors:
        print(
            f"{datetime.now(timezone.utc).isoformat()} diagnostics=" + " | ".join(errors[:4]),
            flush=True,
        )
    data = json.dumps(payload).encode("utf-8")
    request = Request(
        API_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=25, context=ssl_context()) as response:
        response.read()
        return response.status


def collection_errors(payload):
    checks = [
        ("database", payload.get("database", {}).get("error")),
        ("listener", payload.get("listener", {}).get("error")),
        ("tablespaces", payload.get("tablespaces", {}).get("error")),
        ("fra", payload.get("fra", {}).get("error")),
        ("backups", payload.get("backups", {}).get("error")),
        ("blocking", payload.get("blocking_sessions", {}).get("error")),
        ("alert_log", payload.get("alert_log", {}).get("error")),
    ]
    errors = []
    for label, value in checks:
        if value:
            compact_value = " ".join(str(value).split())[:240]
            errors.append(f"{label}: {compact_value}")
    return errors


def main():
    while True:
        try:
            status_code = send_report()
            print(f"{datetime.now(timezone.utc).isoformat()} status=ok http={status_code}", flush=True)
        except Exception as exc:
            print(f"{datetime.now(timezone.utc).isoformat()} error={exc}", flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
