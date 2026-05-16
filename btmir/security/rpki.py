# btmir/security/rpki.py
#
# RPKI Validator
# Uses RIPE Stat as the primary validation source.
# API: https://stat.ripe.net/data/rpki-validation/data.json
#       ?resource=AS{asn}&prefix={prefix}

import asyncio
import logging
import time
from typing import Dict, Optional, Tuple
from urllib.parse import quote

import aiohttp

log = logging.getLogger("btmir.rpki")

RIPE_STAT_URL = (
    "https://stat.ripe.net/data/rpki-validation/data.json"
)
TIMEOUT = aiohttp.ClientTimeout(total=10)


class RPKIResult:
    def __init__(self, asn: int, prefix: str,
                 valid: bool, reason: str):
        self.asn    = asn
        self.prefix = prefix
        self.valid  = valid
        self.reason = reason

    def __repr__(self):
        status = "VALID" if self.valid else "INVALID"
        return (f"RPKIResult({status} "
                f"AS{self.asn} {self.prefix}: {self.reason})")


class RPKIValidator:
    """
    Async RPKI validator using RIPE Stat API.
    Results cached locally for cache_ttl seconds.
    """

    def __init__(self, cache_ttl: int = 3600):
        self.cache_ttl = cache_ttl
        self._cache: Dict[
            Tuple[int, str],
            Tuple[RPKIResult, float]
        ] = {}
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=TIMEOUT
            )
        return self._session

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    # ── Public ─────────────────────────────────────────────

    async def validate(self, asn: int,
                        prefix: str) -> RPKIResult:
        """
        Validate origin AS + prefix against RPKI via RIPE Stat.
        Returns cached result if fresh.
        """
        key    = (asn, prefix)
        cached = self._cache.get(key)
        if cached:
            result, ts = cached
            if time.time() - ts < self.cache_ttl:
                return result

        result = await self._ripe(asn, prefix)

        if result is None:
            result = RPKIResult(
                asn    = asn,
                prefix = prefix,
                valid  = False,
                reason = "validation_unavailable",
            )

        self._cache[key] = (result, time.time())
        return result

    def get_cached(self, asn: int,
                    prefix: str) -> Optional[RPKIResult]:
        """Synchronous cache lookup — non-blocking."""
        key    = (asn, prefix)
        cached = self._cache.get(key)
        if cached:
            result, ts = cached
            if time.time() - ts < self.cache_ttl:
                return result
        return None

    def rpki_valid_fraction(self, asn: int) -> float:
        """
        Fraction of cached prefixes for this AS that are valid.
        Used for WB computation.
        Returns 0.5 if no data yet (neutral).
        """
        as_results = [
            r for (a, _), (r, _) in self._cache.items()
            if a == asn
        ]
        if not as_results:
            return 0.5
        valid = sum(1 for r in as_results if r.valid)
        return valid / len(as_results)

    def cache_size(self) -> int:
        return len(self._cache)

    def clear_expired(self):
        now     = time.time()
        expired = [
            k for k, (_, ts) in self._cache.items()
            if now - ts > self.cache_ttl
        ]
        for k in expired:
            del self._cache[k]

    # ── RIPE Stat ──────────────────────────────────────────

    async def _ripe(self, asn: int,
                     prefix: str) -> Optional[RPKIResult]:
        """
        Query RIPE Stat RPKI validation API.
        URL: ?resource=AS{asn}&prefix={prefix}
        """
        params = {
            "resource": f"AS{asn}",
            "prefix":   prefix,
        }
        try:
            session = await self._get_session()
            async with session.get(
                RIPE_STAT_URL, params=params
            ) as resp:
                if resp.status != 200:
                    return None

                data   = await resp.json(
                    content_type=None
                )
                status = data.get("data", {}).get(
                    "status", ""
                )
                valid  = (status == "valid")
                return RPKIResult(
                    asn    = asn,
                    prefix = prefix,
                    valid  = valid,
                    reason = status or "unknown",
                )
        except Exception as e:
            log.debug(f"RIPE RPKI error "
                      f"AS{asn} {prefix}: {e}")
            return None