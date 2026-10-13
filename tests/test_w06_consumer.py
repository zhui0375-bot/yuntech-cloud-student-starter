"""Offline tests for the W6 consumer's device allowlist boundary."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w06_consumer", ROOT / "app/consumer.py")
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class ConsumerAllowlistTests(unittest.TestCase):
    def setUp(self):
        self.instance = consumer.InspectionConsumer.__new__(consumer.InspectionConsumer)
        self.instance.config = {
            "device_ids": {f"{consumer.CODE}-d{number:02d}" for number in range(1, 11)},
            "reporter_token": "reporter-test-token",
        }

    def send(self, event):
        message = types.SimpleNamespace(
            payload=json.dumps(event).encode("utf-8"),
        )
        with patch.object(consumer, "post_event", return_value="created") as post:
            output = io.StringIO()
            with redirect_stdout(output):
                self.instance.on_message(None, None, message)
        return post, output.getvalue()

    def test_rejects_device_outside_allowlist_without_calling_api(self):
        event = {
            "event_id": "group5-ww-r1-d99-01",
            "device_id": "group5-ww-d99",
            "observed_at": "2026-10-13T01:00:00+00:00",
            "type": "status",
        }
        post, log_line = self.send(event)
        post.assert_not_called()
        self.assertEqual(log_line, "event_id=group5-ww-r1-d99-01 result=rejected\n")

    def test_posts_allowlisted_event_and_emits_only_result_line(self):
        event = {
            "event_id": "group5-ww-r1-d01-01",
            "device_id": "group5-ww-d01",
            "observed_at": "2026-10-13T01:00:00+00:00",
            "type": "status",
        }
        post, log_line = self.send(event)
        post.assert_called_once_with(event, "reporter-test-token")
        self.assertEqual(log_line, "event_id=group5-ww-r1-d01-01 result=created\n")
        self.assertNotIn("reporter-test-token", log_line)
        self.assertNotIn("observed_at", log_line)

    def test_malformed_device_value_is_rejected_without_type_error(self):
        event = {
            "event_id": "group5-ww-r1-d01-01",
            "device_id": ["group5-ww-d01"],
            "observed_at": "2026-10-13T01:00:00+00:00",
            "type": "status",
        }
        post, log_line = self.send(event)
        post.assert_not_called()
        self.assertEqual(log_line, "event_id=group5-ww-r1-d01-01 result=rejected\n")


if __name__ == "__main__":
    unittest.main()
