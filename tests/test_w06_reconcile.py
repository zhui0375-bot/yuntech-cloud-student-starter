"""Offline tests for W6 evidence collection and secret handling."""
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w06_reconcile", ROOT / "tests/w06_reconcile.py")
reconcile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reconcile)


class ReconcileTests(unittest.TestCase):
    def test_validates_run_prefix_before_remote_command_construction(self):
        prefix = reconcile.make_prefix("group5-ww", "r1")
        self.assertEqual(prefix, "group5-ww-r1")
        with self.assertRaisesRegex(ValueError, "configured"):
            reconcile.make_prefix("group5-other", "r1")
        with self.assertRaisesRegex(ValueError, "run must match"):
            reconcile.make_prefix("group5-ww", "r1;id")

        command = reconcile.remote_query(prefix)
        self.assertIn("-v prefix=group5-ww-r1-", command)
        sql = command.split("<<'SQL'\n", 1)[1]
        self.assertIn("length(:'prefix')", sql)
        self.assertNotIn(prefix, sql)
        self.assertIn("sslmode=verify-full", command)

    def test_parses_consumer_counts_and_database_count(self):
        output = (
            "     30 result=created\n"
            "      1 result=duplicate\n"
            "      1 result=rejected\n"
            "\nDB_COUNT=30\n"
        )
        counts, database_count = reconcile.parse_remote_output(output)
        self.assertEqual(counts, {
            "created": 30, "duplicate": 1, "rejected": 1, "error": 0,
        })
        self.assertEqual(database_count, 30)

    def test_rejects_incomplete_or_unexpected_remote_counts(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            reconcile.parse_remote_output("30 result=created")
        with self.assertRaisesRegex(ValueError, "unexpected format"):
            reconcile.parse_remote_output("30 result=unexpected\nDB_COUNT=30\n")

    def test_reads_matching_run_record_without_accepting_boolean_count(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "last-run.json"
            with patch.object(reconcile, "LAST_RUN_FILE", record):
                record.write_text(
                    json.dumps({"prefix": "group5-ww-r1", "puback_ok": 32}),
                    encoding="utf-8",
                )
                self.assertEqual(reconcile.read_last_run("group5-ww-r1"), 32)
                with self.assertRaisesRegex(ValueError, "does not match"):
                    reconcile.read_last_run("group5-ww-r2")
                record.write_text(
                    json.dumps({"prefix": "group5-ww-r1", "puback_ok": True}),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "invalid"):
                    reconcile.read_last_run("group5-ww-r1")

    def test_reads_operator_token_from_private_file_without_displaying_it(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "app.env"
            secret.write_text("OPERATOR_TOKEN=placeholder-secret\n", encoding="utf-8")
            secret.chmod(0o600)
            with patch.object(reconcile, "ROOT", Path(directory)), \
                    patch.object(reconcile, "SECRET_FILE", secret):
                self.assertEqual(reconcile.read_operator_token(), "placeholder-secret")
                secret.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "mode 600"):
                    reconcile.read_operator_token()

    def test_calls_operator_filter_and_selects_only_current_prefix_events(self):
        response = io.BytesIO(json.dumps({
            "events": [
                {"event_id": "group5-ww-r1-d01-01", "device_id": "group5-ww-d01"},
                {"event_id": "group5-ww-r2-d01-01", "device_id": "group5-ww-d01"},
            ],
        }).encode("utf-8"))
        with patch.object(reconcile, "urlopen", return_value=response) as open_url:
            result = reconcile.get_filtered_events(
                "192.0.2.10",
                "group5-ww-d01",
                "placeholder-secret",
                "group5-ww-r1",
            )
        self.assertEqual(result, ["group5-ww-r1-d01-01"])
        request = open_url.call_args.args[0]
        self.assertIn("device_id=group5-ww-d01", request.full_url)
        self.assertEqual(request.get_header("Authorization"), "Bearer placeholder-secret")


    def test_remote_poll_passes_remaining_sixty_second_budget_to_ssh(self):
        with patch.object(reconcile.time, "monotonic", side_effect=[100.0, 100.0]), \
                patch.object(
                    reconcile.w04_ops,
                    "run_ssh",
                    side_effect=TimeoutError("SSH step timed out; output withheld"),
                ) as run_ssh:
            with self.assertRaisesRegex(TimeoutError, "within 60 seconds"):
                reconcile.collect_remote("192.0.2.10", Path("/tmp/key"), "group5-ww-r1")
        self.assertEqual(run_ssh.call_args.kwargs["timeout"], 60)

    def test_ssh_helper_accepts_an_explicit_timeout(self):
        completed = SimpleNamespace(returncode=0, stdout=b"safe output")
        with patch.object(reconcile.w04_ops.subprocess, "run", return_value=completed) as run:
            result = reconcile.w04_ops.run_ssh(
                "192.0.2.10", Path("/tmp/key"), "true", timeout=12
            )
        self.assertEqual(result, "safe output")
        self.assertEqual(run.call_args.kwargs["timeout"], 12)


if __name__ == "__main__":
    unittest.main()
