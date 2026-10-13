"""Offline tests for W6 deployment configuration and file permissions."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w04_ops_w06", ROOT / "deploy/w04_ops.py")
w04_ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w04_ops)


class W06DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.iot_dir = Path(self.tempdir.name) / "iot"
        self.iot_dir.mkdir(mode=0o700)
        self.iot_dir.chmod(0o700)
        self.iot_patch = patch.object(w04_ops, "IOT_DIR", self.iot_dir)
        self.iot_patch.start()
        for name, content in {
            "endpoint": "a1b2c3.iot.us-east-1.amazonaws.com\n",
            "AmazonRootCA1.pem": "-----BEGIN CERTIFICATE-----\nca\n",
            "consumer.cert.pem": "-----BEGIN CERTIFICATE-----\ncert\n",
            "consumer.private.key": "-----BEGIN RSA PRIVATE KEY-----\nprivate\n",
        }.items():
            path = self.iot_dir / name
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)

    def tearDown(self):
        self.iot_patch.stop()
        self.tempdir.cleanup()

    def test_loads_only_recorded_consumer_identity_and_private_material(self):
        resources = {
            "iot_gw_cert_id": "a" * 64,
            "iot_consumer_cert_id": "b" * 64,
            "iot_gw_policy": "cxe-group5-ww-gw",
            "iot_consumer_policy": "cxe-group5-ww-consumer",
        }
        endpoint, files = w04_ops.load_iot_bundle(resources)
        self.assertEqual(endpoint, "a1b2c3.iot.us-east-1.amazonaws.com")
        self.assertEqual(set(files), {
            "AmazonRootCA1.pem", "consumer.cert.pem", "consumer.private.key",
        })
        self.assertIn(b"private", files["consumer.private.key"])

    def test_refuses_private_key_with_broad_permissions(self):
        (self.iot_dir / "consumer.private.key").chmod(0o644)
        with self.assertRaisesRegex(SystemExit, "mode-600"):
            w04_ops.load_iot_bundle({
                "iot_gw_cert_id": "a" * 64,
                "iot_consumer_cert_id": "b" * 64,
                "iot_gw_policy": "cxe-group5-ww-gw",
                "iot_consumer_policy": "cxe-group5-ww-consumer",
            })

    def test_merges_iot_settings_without_duplicate_stale_entries(self):
        existing = (
            b"REPORTER_TOKEN=reporter-secret\n"
            b"OPERATOR_TOKEN=operator-secret\n"
            b"DB_PASSWORD=database-secret\n"
            b"IOT_ENDPOINT=old.iot.us-east-1.amazonaws.com\n"
        )
        result = w04_ops.app_env_with_iot(existing, "new.iot.us-east-1.amazonaws.com")
        lines = result.decode("utf-8").splitlines()
        self.assertEqual(sum(line.startswith("IOT_ENDPOINT=") for line in lines), 1)
        self.assertIn("IOT_ENDPOINT=new.iot.us-east-1.amazonaws.com", lines)
        self.assertIn("IOT_CLIENT_ID=consumer-group5-ww", lines)
        self.assertIn("IOT_CA=/etc/inspection/iot/AmazonRootCA1.pem", lines)
        self.assertIn("IOT_CERT=/etc/inspection/iot/consumer.cert.pem", lines)
        self.assertIn("IOT_KEY=/etc/inspection/iot/consumer.private.key", lines)
        self.assertIn("IOT_DEVICE_IDS=" + ",".join(w04_ops.IOT_DEVICE_IDS), lines)
        self.assertIn("DB_PASSWORD=database-secret", lines)
        self.assertIn("REPORTER_TOKEN=reporter-secret", lines)
        self.assertIn("OPERATOR_TOKEN=operator-secret", lines)

    def test_installs_only_allowlisted_iot_files_with_restricted_permissions(self):
        with patch.object(w04_ops, "run_ssh") as run_ssh:
            w04_ops.install_iot_file("192.0.2.10", Path("/tmp/key"), "consumer.private.key", b"key")
        remote_command = run_ssh.call_args.args[2]
        self.assertIn("umask 077", remote_command)
        self.assertIn("install -d -o inspection -g inspection -m 700", remote_command)
        self.assertIn("chown inspection:inspection", remote_command)
        self.assertIn("chmod 600", remote_command)
        self.assertEqual(run_ssh.call_args.args[3], b"key")
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            w04_ops.install_iot_file("192.0.2.10", Path("/tmp/key"), "unexpected", b"")


if __name__ == "__main__":
    unittest.main()
