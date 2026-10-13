"""Offline tests for W6 gateway event generation and run-prefix safety."""
import importlib.util
import json
from datetime import datetime
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("w06_gateway_sim", ROOT / "tools/gateway_sim.py")
gateway_sim = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway_sim)


class GatewaySimulationTests(unittest.TestCase):
    def test_builds_thirty_unique_events_then_duplicate_and_unlisted_device(self):
        prefix, events = gateway_sim.build_events("group5-ww", "r1")
        self.assertEqual(prefix, "group5-ww-r1")
        self.assertEqual(len(events), 32)
        self.assertEqual(len({event["event_id"] for event in events[:30]}), 30)
        self.assertEqual(events[30], events[0])
        self.assertEqual(events[31]["device_id"], "group5-ww-d99")
        self.assertEqual(events[31]["event_id"], "group5-ww-r1-d99-01")
        self.assertEqual({event["type"] for event in events}, {"status"})
        self.assertTrue(all(datetime.fromisoformat(event["observed_at"]).utcoffset()
                            is not None for event in events))

    def test_rejects_invalid_code_run_and_reused_prefix(self):
        with self.assertRaisesRegex(ValueError, "configured W6"):
            gateway_sim.build_events("other", "r1")
        with self.assertRaisesRegex(ValueError, "run must match"):
            gateway_sim.build_events("group5-ww", "../r2")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local_dir = root / ".local"
            local_dir.mkdir(mode=0o700)
            run_file = local_dir / "w06-last-run.json"
            run_file.write_text(json.dumps({"prefix": "group5-ww-r1"}), encoding="utf-8")
            with patch.object(gateway_sim, "ROOT", root), \
                    patch.object(gateway_sim, "LAST_RUN_FILE", run_file):
                with self.assertRaisesRegex(ValueError, "already used"):
                    gateway_sim.reserve_run("group5-ww-r1")
                self.assertEqual(
                    gateway_sim.previous_prefixes(),
                    {"group5-ww-r1"},
                )
                gateway_sim.reserve_run("group5-ww-r2")
                run_file.write_text(json.dumps({
                    "prefix": "group5-ww-r2",
                    "used_prefixes": ["group5-ww-r1", "group5-ww-r2"],
                }), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "already used"):
                    gateway_sim.reserve_run("group5-ww-r1")

    def test_waits_for_the_puback_matching_the_publish_message_id(self):
        simulator = gateway_sim.GatewaySimulator.__new__(gateway_sim.GatewaySimulator)
        simulator.condition = threading.Condition()
        simulator.publish_reasons = {}

        class FakeClient:
            def publish(self, *_args, **_kwargs):
                simulator.on_publish(None, None, 99, 135, None)
                simulator.on_publish(None, None, 7, 0, None)
                return SimpleNamespace(
                    mid=7,
                    rc=gateway_sim.mqtt_check.mqtt.MQTT_ERR_SUCCESS,
                )

        simulator.client = FakeClient()
        self.assertEqual(
            simulator.publish_wait("cxe/group5-ww/gw/events", {"event_id": "test"}),
            0,
        )


if __name__ == "__main__":
    unittest.main()
