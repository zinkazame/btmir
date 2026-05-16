# btmir/security/hijack.py

import ipaddress
import logging
from dataclasses import dataclass
from typing import Callable, List, Optional

from btmir.trust.models import BGPUpdate
from btmir.trust.store  import TrustStore

log = logging.getLogger("btmir.hijack")


@dataclass
class HijackAlert:
    """Fired when a suspected prefix hijack is detected."""
    prefix:       str
    legit_origin: int    # AS that historically owns this prefix
    seen_origin:  int    # AS we just saw announcing it
    peer_asn:     int
    timestamp:    float
    confidence:   float  # 0.0 to 1.0
    attack_type:  str    # "ORIGIN_CHANGE" or "MORE_SPECIFIC"

    @property
    def severity(self) -> str:
        if self.confidence >= 0.85:
            return "CRITICAL"
        if self.confidence >= 0.60:
            return "HIGH"
        return "MEDIUM"

    def __str__(self):
        return (
            f"[{self.severity}] {self.attack_type} | "
            f"prefix={self.prefix} | "
            f"legit=AS{self.legit_origin} | "
            f"rogue=AS{self.seen_origin} | "
            f"confidence={self.confidence:.0%}"
        )


def _parse_prefix(prefix: str) -> Optional[ipaddress.IPv4Network]:
    """Safely parse a prefix string into a network object."""
    try:
        return ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None


class HijackDetector:
    """
    Real-time BGP hijack detector.

    Runs on every incoming BGP update and checks for:
    1. Origin change   — known prefix now coming from a different AS
    2. More specific   — sub-prefix appearing from a different AS
    """

    def __init__(self,
                 store: TrustStore,
                 on_alert: Optional[Callable[[HijackAlert], None]] = None):
        self.store    = store
        self.on_alert = on_alert

        # Recent announcements kept in memory for more-specific detection
        # prefix → origin_asn
        self._recent: dict = {}

        self.alerts_fired = 0

    # ── Main entry point ───────────────────────────────────

    def inspect(self, update: BGPUpdate) -> Optional[HijackAlert]:
        """
        Inspect a single BGP update for hijack patterns.
        Returns a HijackAlert if suspicious, None if clean.
        """
        if not update.announced:
            # Withdrawal — remove from recent
            self._recent.pop(update.prefix, None)
            return None

        alert = (
            self._check_origin_change(update) or
            self._check_more_specific(update)
        )

        # Update state after checks
        self._recent[update.prefix] = update.origin_asn
        self.store.record_prefix(update.prefix, update.origin_asn)

        if alert:
            self.alerts_fired += 1
            log.warning(str(alert))
            if self.on_alert:
                self.on_alert(alert)

        return alert

    # ── Detection: Origin Change ───────────────────────────

    def _check_origin_change(self,
                              update: BGPUpdate
                              ) -> Optional[HijackAlert]:
        """
        Check if this prefix is being announced by a different
        AS than the one that historically owns it.

        Confidence is based on how established the historical
        origin is — a prefix seen 1000 times from AS13335 and
        now appearing from AS99999 is very high confidence.
        A prefix seen only twice is low confidence.
        """
        known_origins = self.store.get_prefix_origins(update.prefix)

        if not known_origins:
            # First time we've seen this prefix — no history to compare
            return None

        # The dominant origin is whoever announced it most
        dominant = known_origins[0]
        legit_asn = dominant["origin_asn"]

        if legit_asn == update.origin_asn:
            # Same origin as always — no change
            return None

        # How confident are we this is a hijack?
        # Based on how dominant the historical origin was
        total_seen  = sum(o["count"] for o in known_origins)
        legit_count = dominant["count"]
        confidence  = min(0.95, legit_count / (total_seen + 1))

        # Only alert if we have meaningful history
        # A prefix seen only once before is not reliable enough
        if confidence <= 0.50:
            return None

        return HijackAlert(
            prefix       = update.prefix,
            legit_origin = legit_asn,
            seen_origin  = update.origin_asn,
            peer_asn     = update.peer_asn,
            timestamp    = update.timestamp,
            confidence   = confidence,
            attack_type  = "ORIGIN_CHANGE",
        )

    # ── Detection: More Specific ───────────────────────────

    def _check_more_specific(self,
                              update: BGPUpdate
                              ) -> Optional[HijackAlert]:
        """
        Check if this announcement is a more specific prefix
        of a known prefix being announced by a different AS.

        Example:
          Known:   1.2.3.0/24  from AS13335
          Suspect: 1.2.3.0/25  from AS99999

        Routers always prefer more specific routes, so AS99999
        would steal half of Cloudflare's traffic.
        """
        suspect_net = _parse_prefix(update.prefix)
        if suspect_net is None:
            return None

        for known_prefix, known_origin in self._recent.items():
            # Skip if same origin — legitimate de-aggregation
            if known_origin == update.origin_asn:
                continue

            parent_net = _parse_prefix(known_prefix)
            if parent_net is None:
                continue

            # Is the suspect prefix a subnet of the known prefix?
            if (suspect_net != parent_net and
                    parent_net.supernet_of(suspect_net)):

                # More specific from a different AS — suspicious
                # Confidence based on how much more specific it is
                prefix_diff = suspect_net.prefixlen - parent_net.prefixlen
                confidence  = min(0.90, 0.40 + prefix_diff * 0.10)

                return HijackAlert(
                    prefix       = update.prefix,
                    legit_origin = known_origin,
                    seen_origin  = update.origin_asn,
                    peer_asn     = update.peer_asn,
                    timestamp    = update.timestamp,
                    confidence   = confidence,
                    attack_type  = "MORE_SPECIFIC",
                )

        return None

    def stats(self) -> dict:
        return {
            "alerts_fired":    self.alerts_fired,
            "tracked_prefixes": len(self._recent),
        }