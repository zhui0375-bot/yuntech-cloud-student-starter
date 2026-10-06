#!/usr/bin/env python3
"""Run the W5 persistence/idempotency checks against this group's host and RDS."""
import json
from pathlib import Path
import secrets
import shlex
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "deploy"))
sys.path.insert(0, str(ROOT / "tests"))
import lab
import w04_ops
from w04_rejection_matrix import safe_body, send


def read_tokens(path):
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit(".local/app.env must exist with mode 600; token contents are withheld")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"REPORTER_TOKEN", "OPERATOR_TOKEN"}:
            values[key] = value
    reporter = values.get("REPORTER_TOKEN", "")
    operator = values.get("OPERATOR_TOKEN", "")
    if not reporter or not operator or secrets.compare_digest(reporter, operator):
        raise SystemExit("app.env must contain two distinct tokens; contents are withheld")
    return reporter, operator


def read_database_secrets(path):
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise SystemExit(".local/db.env must exist with mode 600; contents are withheld")
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"DB_HOST", "DB_NAME", "DB_USER"}:
            values[key] = value
    if not all(values.get(key) for key in ("DB_HOST", "DB_NAME", "DB_USER")):
        raise SystemExit("db.env lacks required database connection fields; contents are withheld")
    return values


def remote_command(public_ip, key_path, command, input_data=None):
    result = subprocess.run(
        ["ssh", "-i", str(key_path), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
         f"ec2-user@{public_ip}", command],
        input=input_data,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if result.returncode:
        raise SystemExit("Remote W5 verification failed; output withheld")
    return result.stdout.decode("utf-8", errors="replace").strip()


def main():
    context = lab.verify()
    if context["region"] != w04_ops.REGION:
        raise SystemExit(f"W5 requires {w04_ops.REGION}; verified region differs")
    resources = w04_ops.resources()
    if resources.get("group") != "group5" or resources.get("owner") != "ww":
        raise SystemExit("resources.json does not identify the expected owner; refusing W5 checks")
    read_database_secrets(w04_ops.DATABASE_SECRET_FILE)
    reporter, operator = read_tokens(w04_ops.SECRET_FILE)
    key_path = Path.home() / ".ssh" / "id_ed25519"
    if not key_path.is_file() or stat.S_IMODE(key_path.stat().st_mode) != 0o600:
        raise SystemExit("SSH private key is missing or mode is not 600")

    instance = w04_ops.verified_instance(resources)
    if instance.get("State", {}).get("Name") != "running":
        raise SystemExit("W5 matrix requires the listed EC2 instance to be running")
    public_ip = instance.get("PublicIpAddress")
    if not public_ip:
        raise SystemExit("The listed EC2 instance has no public IPv4")
    base_url = f"http://{public_ip}"

    health_status, health = send(base_url, "GET", "/health")
    if (health_status != 200 or health.get("auth_configured") is not True
            or health.get("db_configured") is not True):
        raise SystemExit("Host /health must confirm auth and database configuration before testing")
    print(json.dumps({"version": health["version"], "db_configured": health["db_configured"]},
                     sort_keys=True))

    event = {
        "event_id": f"group5-ww-w5-{secrets.token_hex(6)}",
        "device_id": "group5-d01",
        "observed_at": "2026-10-06T10:00:00+08:00",
        "type": "status",
        "note": "W5 persistence check",
    }
    altered = dict(event, note="W5 idempotency conflict check")
    description = f"""W5 T3 冪等矩陣將對既有資源執行：
EC2：{resources['instance_id']}（既有 running 主機，只重啟 inspection 服務）
RDS：{resources.get('db_instance_identifier', '資料庫 ID 尚未記入資源清單')}（只寫入一筆 W5 測試事件；相同 ID 重送及異內容衝突測試）
事件 ID：{event['event_id']}；結果保留在資料庫作為繳交證據，不自動刪除。
費用：不建立 AWS 資源；EC2/RDS 既有運行費用持續計算，資料庫只增加極少量資料。
網路暴露：不修改安全組、不開新連接埠；沿用主機既有 TCP 22/80 規則及 EC2→RDS 既有 5432 規則。
回復：本矩陣不刪除事件或資源；如需清理，僅能在你確認 event_id 後執行精確 SQL 刪除。"""
    lab.approve(description, "RUN-W5-MATRIX")

    cases = (
        (1, 201, event),
        (2, 200, event),
        (3, 409, altered),
    )
    failed = False
    for number, expected, payload in cases:
        status, body = send(base_url, "POST", "/events", reporter, payload)
        valid = status == expected
        if number in (1, 2):
            valid = valid and body.get("event_id") == event["event_id"]
        if number == 3:
            valid = valid and body.get("field") == "event_id"
        failed = failed or not valid
        print(f"#{number} expected={expected} actual={status} body={safe_body(body, (reporter, operator))}")

    remote_command(public_ip, key_path, "sudo systemctl restart inspection")
    status, body = send(base_url, "GET", "/events/" + event["event_id"], operator)
    valid = status == 200 and body.get("event_id") == event["event_id"]
    failed = failed or not valid
    print(f"#4 expected=200 actual={status} body={safe_body(body, (reporter, operator))}")

    sql = f"SELECT count(*) FROM events WHERE event_id = '{event['event_id']}';"
    remote_script = (
        "set -euo pipefail; set -a; . /etc/inspection/app.env; set +a; "
        "PGPASSWORD=\"$DB_PASSWORD\" psql "
        "\"host=$DB_HOST dbname=$DB_NAME user=$DB_USER sslmode=verify-full "
        "sslrootcert=/etc/inspection/rds-ca.pem\" -At -c " + shlex.quote(sql)
    )
    count = remote_command(public_ip, key_path, "sudo bash -c " + shlex.quote(remote_script))
    valid = count == "1"
    failed = failed or not valid
    print(f"#5 expected=1 actual={count}")
    if failed:
        raise SystemExit("One or more W5 idempotency expectations failed")


if __name__ == "__main__":
    main()
