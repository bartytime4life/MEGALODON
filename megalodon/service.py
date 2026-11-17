"""Composition root connecting capture, detection, storage, and policy."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from pathlib import Path
from threading import RLock

from .config import Settings
from .detector import Detector
from .firewall import FirewallError, NftablesFirewall
from .models import ActionRecord, DetectionResult, PacketEvent
from .storage import Store
from .threat_detector import ThreatDetector
from .watchlist import load_watchlist


class MegalodonService:
    def __init__(self, settings: Settings, store: Store, firewall: NftablesFirewall | None = None):
        self.settings = settings
        self.store = store
        self.detector = Detector(settings.detection, settings.blocking.allowlist)
        threat = settings.threat
        watchlist = None
        if threat.enabled and threat.watchlist_path:
            # A configured watchlist that cannot be read refuses startup instead
            # of silently running without the indicators the operator expects.
            watchlist = load_watchlist(
                Path(threat.watchlist_path).expanduser(),
                severity=threat.watchlist_severity,
            )
        self.threat_detector = ThreatDetector(
            threat, settings.blocking.allowlist, watchlist
        )
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
        # Both layers stage behind undo journals; neither commits unless the
        # event's complete audit bundle does.
        pending_before = self.detector._pending_token
        # A re-entrant call must never unwind the outer call's preparation.
        threat_pending_before = self.threat_detector._pending
        prepared = None
        threat_prepared = None
        try:
            prepared = self.detector.prepare(event)
            threat_prepared = self.threat_detector.prepare(event)
            detections = list(prepared.results) + list(threat_prepared.results)
            actions = [self._action_for_detection(item) for item in detections]
            self.store.record_event_bundle(
                event, detections, actions, run_id=run_id
            )
        except BaseException:
            if threat_prepared is not None:
                threat_prepared.rollback()
            elif threat_pending_before is None:
                self.threat_detector.rollback_pending()
            if prepared is not None:
                prepared.rollback()
            elif pending_before is None:
                self.detector.rollback_pending()
            raise
        prepared.commit()
        threat_prepared.commit()
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

    @staticmethod
    def _response_target(detection: DetectionResult) -> str:
        """The remote party a block plan would name; never an unrelated address."""
        target = detection.evidence.get("response_target")
        if target in {detection.src_ip, detection.dst_ip}:
            return target
        return detection.src_ip

    def _action_for_detection(self, detection: DetectionResult) -> ActionRecord:
        target = self._response_target(detection)
        if detection.suppressed_reason:
            return self._action(
                action="block",
                target=target,
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
                target=target,
                status="not_attempted",
                reason="automatic block planning disabled by policy",
            )

        try:
            # A detection is evidence, not operator authorization.  This path may
            # prepare an auditable plan; the evaluation candidate cannot apply it.
            operation = self.firewall.plan_block(
                target,
                f"{detection.rule_id}: {detection.message}",
            )
            return self._action(
                action="block",
                target=target,
                status=operation.status,
                reason=operation.reason,
                expires_at=operation.expires_at,
                details=operation.to_dict(),
            )
        except FirewallError as exc:
            return self._action(
                action="block",
                target=target,
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
