from __future__ import annotations

from datetime import datetime, timezone
import unittest

from megalodon.config import BlockingSettings, DetectionSettings, Settings
from megalodon.models import PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import Store


class ServiceTests(unittest.TestCase):
    def test_observe_mode_records_detection_without_firewall_change(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                db_path=Path(directory) / "events.db",
                detection=DetectionSettings(dns_query_length=10),
                blocking=BlockingSettings(enabled=False, dry_run=True),
            )
            event = PacketEvent(
                observed_at=datetime.now(timezone.utc),
                src_ip="8.8.8.8",
                dst_ip="192.0.2.53",
                protocol="DNS",
                dst_port=53,
                dns_query_length=12,
            )
            with Store(settings.db_path) as store:
                service = MegalodonService(settings, store)
                results = service.process(event)
                self.assertEqual(results[0].rule_id, "DNS_TUNNELING")
                self.assertEqual(store.summary()["detections"], 1)
                self.assertEqual(store.summary()["actions"], 1)
                self.assertTrue(store.recent()[0]["message"])

    def test_dry_run_auto_block_records_planned_action(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                db_path=Path(directory) / "events.db",
                detection=DetectionSettings(dns_query_length=10),
                blocking=BlockingSettings(
                    enabled=True,
                    dry_run=True,
                    auto_block=True,
                    auto_block_min_severity="CRITICAL",
                    public_only=False,
                ),
            )
            event = PacketEvent(
                observed_at=datetime.now(timezone.utc),
                src_ip="8.8.8.8",
                dst_ip="192.0.2.53",
                protocol="DNS",
                dst_port=53,
                dns_query_length=12,
            )
            with Store(settings.db_path) as store:
                service = MegalodonService(settings, store)
                service.process(event)
                action = store.connection.execute(
                    "SELECT action, status, target FROM actions ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(tuple(action), ("block", "planned", "8.8.8.8"))
