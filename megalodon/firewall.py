"""Explicit, validated, non-mutating nftables planning.

Detection-driven service calls and operator CLI calls are plan-only. Live
firewall application is unsupported in this evaluation-release candidate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import shutil

from .capabilities import runtime_platform
from .validation import is_global_unicast, parse_ip, safe_text


class FirewallError(RuntimeError):
    """Raised when a firewall operation cannot be safely completed."""


LIVE_APPLY_UNSUPPORTED = "live firewall application is unsupported in this evaluation release"


@dataclass(frozen=True)
class FirewallOperation:
    status: str
    target: str
    reason: str
    command: tuple[str, ...]
    message: str
    expires_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "target": self.target,
            "reason": self.reason,
            "command": list(self.command),
            "message": self.message,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


NFTABLES_TABLE = """table inet megalodon {
    set blocked_v4 {
        type ipv4_addr
        flags timeout
    }
    set blocked_v6 {
        type ipv6_addr
        flags timeout
    }
    chain input {
        type filter hook input priority -100; policy accept;
        ip saddr @blocked_v4 drop
        ip6 saddr @blocked_v6 drop
    }
    chain output {
        type filter hook output priority -100; policy accept;
        ip daddr @blocked_v4 drop
        ip6 daddr @blocked_v6 drop
    }
}
"""


class NftablesFirewall:
    def __init__(
        self,
        *,
        allowlist: tuple[ipaddress._BaseNetwork, ...] = (),
        public_only: bool = True,
        timeout_seconds: int = 900,
        dry_run: bool = True,
    ):
        self.allowlist = allowlist
        self.public_only = public_only
        self.timeout_seconds = timeout_seconds
        self.dry_run = dry_run

    @staticmethod
    def available() -> bool:
        """Report tool discoverability only; this never authorizes live apply."""
        return runtime_platform() == "linux" and shutil.which("nft") is not None

    def validate_target(self, value: str) -> str:
        target = parse_ip(value)
        address = ipaddress.ip_address(target)
        if any(address in network for network in self.allowlist):
            raise FirewallError(f"refusing to block allowlisted address {target}")
        if self.public_only and not is_global_unicast(target):
            raise FirewallError(f"refusing to block non-global address {target} under public_only policy")
        return target

    def install(self, *, apply: bool = False, confirm: str | None = None) -> FirewallOperation:
        if apply:
            raise FirewallError(LIVE_APPLY_UNSUPPORTED)
        self._require_linux()
        command = ("nft", "-f", "-")
        return FirewallOperation("planned", "table:megalodon", "install isolated table", command, NFTABLES_TABLE)

    def plan_block(self, value: str, reason: str) -> FirewallOperation:
        self._require_linux()
        target = self.validate_target(value)
        clean_reason = safe_text(reason, "reason", 200)
        set_name = "blocked_v6" if ":" in target else "blocked_v4"
        command = (
            "nft",
            "add",
            "element",
            "inet",
            "megalodon",
            set_name,
            "{",
            target,
            "timeout",
            f"{self.timeout_seconds}s",
            "}",
        )
        expiry = datetime.now(timezone.utc) + timedelta(seconds=self.timeout_seconds)
        return FirewallOperation("planned", target, clean_reason, command, "would add a time-limited set element", expiry)

    def block(self, value: str, reason: str, *, apply: bool = False, confirm: str | None = None) -> FirewallOperation:
        if apply:
            raise FirewallError(LIVE_APPLY_UNSUPPORTED)
        return self.plan_block(value, reason)

    @staticmethod
    def _require_linux() -> None:
        if runtime_platform() != "linux":
            raise FirewallError("nftables operations are supported only on Linux")
