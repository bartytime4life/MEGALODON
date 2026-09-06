"""Composition root connecting capture, detection, storage, and policy."""

from __future__ import annotations

from datetime import datetime, timezone
import logging

from .config import Settings
from .detector import Detector
from .firewall import FirewallError, NftablesFirewall
from .models import ActionRecord, DetectionResult, PacketEvent
from .storage import Store


class MegalodonService:
    def __init__(self, settings: Settings, store: Store, firewall: NftablesFirewall | None = None):
        self.settings = settings
        self.store = store
        self.detector = Detector(settings.detection, settings.blocking.allowlist)
        self.firewall = firewall or NftablesFirewall(
            allowlist=settings.blocking.allowlist,
            public_only=settings.blocking.public_only,
            timeout_seconds=settings.blocking.timeout_seconds,
            dry_run=settings.blocking.dry_run,
        )
        self.logger = logging.getLogger("megalodon.service")

    def process(self, event: PacketEvent) -> list[DetectionResult]:
        event_id = self.store.record_event(event)
        detections = self.detector.analyze(event)
        for detection in detections:
            self.store.record_detection(event_id, detection)
            self._handle_detection(detection)
            self.logger.info(
                "%s %s from %s: %s",
                detection.severity,
                detection.rule_id,
                detection.src_ip,
                detection.message,
            )
        return detections

    def _handle_detection(self, detection: DetectionResult) -> None:
        if detection.suppressed_reason:
            self._record_action(
                action="block",
                target=detection.src_ip,
                status="suppressed",
                reason=detection.suppressed_reason,
            )
            return

        minimum = self.settings.blocking.auto_block_min_severity
        should_block = (
            self.settings.blocking.enabled
            and self.settings.blocking.auto_block
            and self._severity_rank(detection.severity) >= self._severity_rank(minimum)
        )
        if not should_block:
            self._record_action(
                action="block",
                target=detection.src_ip,
                status="not_attempted",
                reason="automatic blocking disabled by policy",
            )
            return

        try:
            operation = self.firewall.block(
                detection.src_ip,
                f"{detection.rule_id}: {detection.message}",
                apply=not self.settings.blocking.dry_run,
                confirm=detection.src_ip if not self.settings.blocking.dry_run else None,
            )
            self._record_action(
                action="block",
                target=detection.src_ip,
                status=operation.status,
                reason=operation.reason,
                expires_at=operation.expires_at,
                details=operation.to_dict(),
            )
        except FirewallError as exc:
            self._record_action(
                action="block",
                target=detection.src_ip,
                status="failed",
                reason=str(exc),
            )
            self.logger.error("firewall action refused: %s", exc)

    def _record_action(
        self,
        *,
        action: str,
        target: str,
        status: str,
        reason: str,
        expires_at: datetime | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        self.store.record_action(
            ActionRecord(
                created_at=datetime.now(timezone.utc),
                action=action,
                target=target,
                status=status,
                reason=reason,
                expires_at=expires_at,
                details=details or {},
            )
        )

    @staticmethod
    def _severity_rank(value: str) -> int:
        return {"LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 40}.get(value.upper(), 0)
