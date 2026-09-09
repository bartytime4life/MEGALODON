from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import Mock

from megalodon.config import BlockingSettings, DetectionSettings, Settings
from megalodon.firewall import FirewallOperation, NftablesFirewall
from megalodon.models import PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.validation import ValidationError


class ServiceTests(unittest.TestCase):
    def test_reordered_event_is_rejected_before_persistence(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(db_path=Path(directory) / "events.db")
            now = datetime.now(timezone.utc)
            first = PacketEvent(now, "8.8.8.8", "192.0.2.53", "TCP")
            reordered = PacketEvent(
                now - timedelta(seconds=1),
                "8.8.8.8",
                "192.0.2.53",
                "TCP",
            )
            with Store(settings.db_path) as store:
                service = MegalodonService(settings, store)
                self.assertEqual(service.process(first), [])
                with self.assertRaisesRegex(ValidationError, "source high watermark"):
                    service.process(reordered)
                self.assertEqual(store.summary()["events"], 1)

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

    def test_detection_policy_never_supplies_live_apply_or_confirmation(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                db_path=Path(directory) / "events.db",
                detection=DetectionSettings(dns_query_length=10),
                # Direct construction bypasses TOML validation, so the service
                # must still preserve the operator-only application boundary.
                blocking=BlockingSettings(
                    enabled=True,
                    dry_run=False,
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
            firewall = Mock(spec=NftablesFirewall)
            firewall.plan_block.return_value = FirewallOperation(
                "planned",
                "8.8.8.8",
                "DNS_TUNNELING: review required",
                ("nft", "add", "element"),
                "would add a time-limited set element",
            )
            with Store(settings.db_path) as store:
                MegalodonService(settings, store, firewall=firewall).process(event)
                action = store.connection.execute(
                    "SELECT status FROM actions ORDER BY id DESC LIMIT 1"
                ).fetchone()

            self.assertEqual(action["status"], "planned")
            firewall.plan_block.assert_called_once()
            firewall.block.assert_not_called()
