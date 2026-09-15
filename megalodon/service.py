"""Composition root connecting capture, detection, storage, and policy."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from threading import RLock

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
        self._process_lock = RLock()

    def process(
        self, event: PacketEvent, *, run_id: int | None = None
    ) -> list[DetectionResult]:
        with self._process_lock:
            return self._process_one(event, run_id=run_id)

    def _process_one(
        self, event: PacketEvent, *, run_id: int | None = None
    ) -> list[DetectionResult]:
        # Evaluation is staged so failed persistence never consumes detector
        # windows, source high-water marks, or alert cooldowns.
        pending_before = self.detector._pending_token
        prepared = None
        try:
            prepared = self.detector.prepare(event)
            detections = list(prepared.results)
            actions = [self._action_for_detection(item) for item in detections]
            self.store.record_event_bundle(
                event, detections, actions, run_id=run_id
            )
        except BaseException:
            if prepared is not None:
                prepared.rollback()
            elif pending_before is None:
                self.detector.rollback_pending()
            raise
        prepared.commit()
        for detection, action in zip(detections, actions, strict=True):
            if action.status == "failed":
                self.logger.error("firewall action refused: %s", action.reason)
            self.logger.info(
                "%s %s from %s: %s",
                detection.severity,
                detection.rule_id,
                detection.src_ip,
                detection.message,
            )
        return detections

    def _action_for_detection(self, detection: DetectionResult) -> ActionRecord:
        if detection.suppressed_reason:
            return self._action(
                action="block",
                target=detection.src_ip,
                status="suppressed",
                reason=detection.suppressed_reason,
            )

        minimum = self.settings.blocking.auto_block_min_severity
        should_plan = (
            self.settings.blocking.enabled
            and self.settings.blocking.auto_block
            and self._severity_rank(detection.severity) >= self._severity_rank(minimum)
        )
        if not should_plan:
            return self._action(
                action="block",
                target=detection.src_ip,
                status="not_attempted",
                reason="automatic block planning disabled by policy",
            )

        try:
            # A detection is evidence, not operator authorization.  This path may
            # prepare an auditable plan; the evaluation candidate cannot apply it.
            operation = self.firewall.plan_block(
                detection.src_ip,
                f"{detection.rule_id}: {detection.message}",
            )
            return self._action(
                action="block",
                target=detection.src_ip,
                status=operation.status,
                reason=operation.reason,
                expires_at=operation.expires_at,
                details=operation.to_dict(),
            )
        except FirewallError as exc:
            return self._action(
                action="block",
                target=detection.src_ip,
                status="failed",
                reason=str(exc),
            )

    @staticmethod
    def _action(
        *,
        action: str,
        target: str,
        status: str,
        reason: str,
        expires_at: datetime | None = None,
        details: dict[str, object] | None = None,
    ) -> ActionRecord:
        return ActionRecord(
            created_at=datetime.now(timezone.utc),
            action=action,
            target=target,
            status=status,
            reason=reason,
            expires_at=expires_at,
            details=details or {},
        )

    @staticmethod
    def _severity_rank(value: str) -> int:
        return {"LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 40}.get(value.upper(), 0)
