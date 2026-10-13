#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$ROOT/scripts/verify-aws.sh"

exec python3 - "$ROOT" <<'PY'
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "scripts"))
import lab

REGION = "us-east-1"
CODE = "group5-ww"
RESOURCE_FILE = ROOT / ".local" / "resources.json"
IOT_DIR = ROOT / ".local" / "iot"
CA_URL = "https://www.amazontrust.com/repository/AmazonRootCA1.pem"
EXPECTED_TAGS = {
    "course": "yuntech-115-1",
    "week": "w03",
    "group": "group5",
    "owner": "ww",
}


def stop(message):
    raise SystemExit(message)


def approve(description, token):
    print(description, file=sys.stderr, flush=True)
    try:
        terminal = open("/dev/tty", "r+", encoding="utf-8")
    except OSError as error:
        raise lab.LabError(
            "Interactive approval requires a terminal; no IoT resources were changed."
        ) from error
    with terminal:
        terminal.write(f"Type exactly {token} to proceed: ")
        terminal.flush()
        if terminal.readline().strip() != token:
            stop("Cancelled; no IoT resources were changed")


def resources():
    if RESOURCE_FILE.is_symlink() or not RESOURCE_FILE.is_file():
        stop("Missing or unsafe .local/resources.json; refusing IoT provisioning")
    if ROOT.joinpath(".local").is_symlink():
        stop("Refusing a symlink at .local")
    value = json.loads(RESOURCE_FILE.read_text(encoding="utf-8"))
    if (value.get("group") != "group5" or value.get("owner") != "ww"
            or value.get("tags") != EXPECTED_TAGS):
        stop("resources.json does not identify the expected group5-ww resources")
    return value


def save_resources(value):
    lab.atomic_write(RESOURCE_FILE, json.dumps(value, indent=2, sort_keys=True) + "\n")


def secure_iot_dir():
    if IOT_DIR.is_symlink():
        stop("Refusing a symlink at .local/iot")
    IOT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(IOT_DIR, 0o700)


def acquire_lock():
    lock_path = IOT_DIR / ".iot-up.lock"
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    try:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        stop("Another iot-up.sh process is active; refusing concurrent provisioning")
    return descriptor


def write_new_file(path, content):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def save_or_check_public_file(path, content):
    if path.is_symlink():
        stop(f"Refusing a symlink at {path.name}")
    if path.exists():
        if path.read_text(encoding="utf-8").strip() != content.strip():
            stop(f"Existing {path.name} does not match the verified value; refusing overwrite")
        return
    write_new_file(path, content.rstrip() + "\n")


def policy_document(account, role):
    topic = f"cxe/{CODE}/gw/events"
    client = "gw" if role == "gw" else "consumer"
    statements = [
        {
            "Effect": "Allow",
            "Action": "iot:Connect",
            "Resource": [f"arn:aws:iot:{REGION}:{account}:client/{client}-{CODE}"],
        }
    ]
    if role == "gw":
        statements.append({
            "Effect": "Allow",
            "Action": "iot:Publish",
            "Resource": [f"arn:aws:iot:{REGION}:{account}:topic/{topic}"],
        })
    else:
        statements.extend([
            {
                "Effect": "Allow",
                "Action": "iot:Subscribe",
                "Resource": [f"arn:aws:iot:{REGION}:{account}:topicfilter/{topic}"],
            },
            {
                "Effect": "Allow",
                "Action": "iot:Receive",
                "Resource": [f"arn:aws:iot:{REGION}:{account}:topic/{topic}"],
            },
        ])
    return {"Version": "2012-10-17", "Statement": statements}


def canonical_policy(document):
    if isinstance(document, str):
        document = json.loads(document)
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def get_policy(name):
    try:
        return lab.run_aws(["iot", "get-policy", "--policy-name", name], REGION)
    except lab.LabError as error:
        if "ResourceNotFoundException" in str(error):
            return None
        raise


def ensure_policy(name, document, resources_value, resource_key):
    expected = canonical_policy(document)
    existing = get_policy(name)
    if resource_key in resources_value:
        if resources_value[resource_key] != name:
            stop(f"Stored {resource_key} does not match the expected policy name")
        if existing is None:
            stop(f"Stored policy {name} no longer exists; refusing changes")
        actual = existing.get("policyDocument", existing.get("PolicyDocument"))
        if actual is None or canonical_policy(actual) != expected:
            stop(f"Stored policy {name} differs from the exact W6 policy; refusing changes")
        return

    if existing is None:
        created = lab.run_aws([
            "iot", "create-policy", "--policy-name", name,
            "--policy-document", json.dumps(document, separators=(",", ":")),
        ], REGION)
        policy_arn = created.get("policyArn", created.get("PolicyArn"))
    else:
        actual = existing.get("policyDocument", existing.get("PolicyDocument"))
        if actual is None or canonical_policy(actual) != expected:
            stop(f"An unrelated policy already uses {name}; refusing changes")
        policy_arn = existing.get("policyArn", existing.get("PolicyArn"))

    expected_arn = f"arn:aws:iot:{REGION}:{ACCOUNT}:policy/{name}"
    if policy_arn and policy_arn != expected_arn:
        stop(f"Policy ARN mismatch for {name}; refusing attachment")
    resources_value[resource_key] = name
    save_resources(resources_value)


def ensure_certificate(role, resources_value):
    is_gateway = role == "gw"
    cert_key = "iot_gw_cert_id" if is_gateway else "iot_consumer_cert_id"
    cert_path = IOT_DIR / ("gw.cert.pem" if is_gateway else "consumer.cert.pem")
    private_path = IOT_DIR / ("gw.private.key" if is_gateway else "consumer.private.key")

    if cert_key in resources_value:
        certificate_id = resources_value[cert_key]
        if not isinstance(certificate_id, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", certificate_id):
            stop(f"Stored {cert_key} is invalid; refusing to create a replacement")
        if cert_path.is_symlink() or private_path.is_symlink():
            stop(f"Refusing a symlink in the {role} certificate files")
        if not private_path.is_file():
            stop(f"Recorded {role} certificate is missing its private key; refusing replacement")
        if stat.S_IMODE(private_path.stat().st_mode) != 0o600:
            stop(f"{private_path.name} must have mode 600; refusing to change its contents")
        if not cert_path.exists():
            response = lab.run_aws(
                ["iot", "describe-certificate", "--certificate-id", certificate_id], REGION
            )
            certificate = response.get("certificateDescription", {}).get("certificatePem")
            if not isinstance(certificate, str) or not certificate.startswith("-----BEGIN CERTIFICATE-----"):
                stop(f"Recorded {role} certificate PEM is unavailable; refusing replacement")
            write_new_file(cert_path, certificate.rstrip() + "\n")
        elif not cert_path.is_file():
            stop(f"Recorded {role} certificate path is not a regular file")
        elif stat.S_IMODE(cert_path.stat().st_mode) != 0o600:
            os.chmod(cert_path, 0o600)
        return certificate_id

    if cert_path.exists() or private_path.exists():
        stop(f"Unrecorded {role} certificate files already exist; refusing to overwrite or create another")

    descriptor, response_name = tempfile.mkstemp(prefix=".iot-certificate-", dir=IOT_DIR)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as response_file:
            result = subprocess.run(
                [
                    "aws", "--profile", lab.PROFILE, "--region", REGION,
                    "--no-cli-pager", "--output", "json",
                    "iot", "create-keys-and-certificate", "--set-as-active",
                ],
                env=lab.clean_env(REGION),
                stdout=response_file,
                stderr=subprocess.PIPE,
                text=True,
                timeout=90,
                check=False,
            )
        if result.returncode:
            error = lab.error_code(result.stderr)
            raise lab.LabError(f"iot create-keys-and-certificate: {error}. Stop and inspect before retrying.")
        result = json.loads(Path(response_name).read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise lab.LabError("AWS CLI missing; open the devcontainer.") from error
    except subprocess.TimeoutExpired as error:
        raise lab.LabError("AWS certificate creation timed out; inspect before retrying.") from error
    finally:
        Path(response_name).unlink(missing_ok=True)

    certificate = result.get("certificatePem")
    private_key = result.get("keyPair", {}).get("PrivateKey")
    certificate_id = result.get("certificateId")
    if (not isinstance(certificate, str) or not certificate.startswith("-----BEGIN CERTIFICATE-----")
            or not isinstance(private_key, str) or not private_key.startswith("-----BEGIN RSA PRIVATE KEY-----")
            or not isinstance(certificate_id, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", certificate_id)):
        stop("AWS returned an unexpected certificate response; output was withheld and no files were written")

    resources_value[cert_key] = certificate_id
    save_resources(resources_value)
    # Capture the private key without sending AWS's response to the terminal or a log.
    write_new_file(private_path, private_key.rstrip() + "\n")
    write_new_file(cert_path, certificate.rstrip() + "\n")
    return certificate_id


def ensure_attachment(certificate_id, policy_name):
    described = lab.run_aws(
        ["iot", "describe-certificate", "--certificate-id", certificate_id], REGION
    ).get("certificateDescription", {})
    certificate_arn = described.get("certificateArn")
    if described.get("status") != "ACTIVE" or not certificate_arn:
        stop("An IoT certificate is not ACTIVE; refusing policy attachment")
    attached = lab.run_aws(
        ["iot", "list-attached-policies", "--target", certificate_arn], REGION
    ).get("policies", [])
    attached_names = {item.get("policyName") for item in attached}
    unexpected = attached_names - {policy_name}
    if unexpected:
        stop(f"Certificate has unexpected attached IoT policies; refusing broader access")
    if policy_name in attached_names:
        return
    lab.run_aws([
        "iot", "attach-policy", "--policy-name", policy_name, "--target", certificate_arn
    ], REGION)


def main():
    global ACCOUNT
    context = lab.context()
    if context.get("region") != REGION:
        stop(f"W6 requires {REGION}; verified Learner Lab region differs")
    ACCOUNT = context["account"]
    resources_value = resources()

    if set(("iot_gw_cert_id", "iot_consumer_cert_id", "iot_gw_policy", "iot_consumer_policy")) & resources_value.keys():
        print("Existing W6 IoT entries will be retained; missing items only will be provisioned.")

    plan = (
        f"W6 IoT provisioning for {CODE} in {REGION}:\n"
        "Resources: at most two ACTIVE IoT certificates and two narrowly scoped IoT policies; "
        "reuse the existing EC2 and RDS without modifying them.\n"
        "Network exposure: no inbound ports, security-group changes, public database, or IAM changes; "
        "the Codespace connects outbound to the regional IoT endpoint on TCP 8883.\n"
        "Cost: certificates and policies have no hourly charge while idle; IoT Core messaging "
        "charges depend on later message volume. This setup command sends no MQTT messages.\n"
        "Recovery: stop using these credentials; after verifying the exact certificate IDs and "
        "policy names in .local/resources.json, revoke only these two certificates and delete only "
        "the matching cxe-group5-ww-gw and cxe-group5-ww-consumer policies."
    )
    approve(plan, "CREATE-IOT")
    secure_iot_dir()
    lock_descriptor = acquire_lock()

    try:
        endpoint_response = lab.run_aws(
            ["iot", "describe-endpoint", "--endpoint-type", "iot:Data-ATS"], REGION
        )
        endpoint = endpoint_response.get("endpointAddress")
        if (not isinstance(endpoint, str)
                or not re.fullmatch(r"[A-Za-z0-9-]+\.iot\.us-east-1\.amazonaws\.com", endpoint)):
            stop("AWS returned an invalid regional IoT endpoint; refusing to save it")
        save_or_check_public_file(IOT_DIR / "endpoint", endpoint)

        ca_path = IOT_DIR / "AmazonRootCA1.pem"
        if ca_path.is_symlink():
            stop("Refusing a symlink at AmazonRootCA1.pem")
        if ca_path.exists():
            if stat.S_IMODE(ca_path.stat().st_mode) != 0o600:
                os.chmod(ca_path, 0o600)
        else:
            try:
                with urllib.request.urlopen(CA_URL, timeout=20) as response:
                    ca_pem = response.read(65536).decode("ascii")
            except (urllib.error.URLError, TimeoutError, UnicodeDecodeError) as error:
                stop(f"Could not download Amazon Root CA 1 ({type(error).__name__}); no certificate files changed")
            if "-----BEGIN CERTIFICATE-----" not in ca_pem:
                stop("Amazon Root CA 1 download was not a PEM certificate; refusing to save it")
            write_new_file(ca_path, ca_pem.rstrip() + "\n")

        gateway_id = ensure_certificate("gw", resources_value)
        consumer_id = ensure_certificate("consumer", resources_value)

        for role, certificate_id, key in (
            ("gw", gateway_id, "iot_gw_policy"),
            ("consumer", consumer_id, "iot_consumer_policy"),
        ):
            policy_name = f"cxe-{CODE}-{role}"
            ensure_policy(policy_name, policy_document(ACCOUNT, role), resources_value, key)
            ensure_attachment(certificate_id, policy_name)

        for label, certificate_id in (("gateway", gateway_id), ("consumer", consumer_id)):
            response = lab.run_aws(
                ["iot", "describe-certificate", "--certificate-id", certificate_id], REGION
            )
            status = response.get("certificateDescription", {}).get("status")
            if status != "ACTIVE":
                stop(f"The {label} IoT certificate is not ACTIVE; inspect it before retrying")

        print("W6 IoT endpoint, certificates, exact policies, and attachments are ready; secret material withheld.")
    finally:
        os.close(lock_descriptor)


try:
    main()
except (lab.LabError, OSError, ValueError, json.JSONDecodeError) as error:
    print(f"STOP: {error}", file=sys.stderr)
    sys.exit(1)
PY
