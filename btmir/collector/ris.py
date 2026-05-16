# btmir/collector/ris.py
# Connects to RIPE RIS Live and streams real BGP updates.
#
# RIPE RIS (Routing Information Service) is a global network
# of route collectors operated by RIPE NCC. They peer with
# hundreds of ASes worldwide and share all BGP updates live.
#
# WebSocket endpoint: wss://ris-live.ripe.net/v1/ws/
# Documentation: https://ris-live.ripe.net/

import asyncio
import json
import logging
from typing import Callable, List, Optional

import websockets

from btmir.trust.models import BGPUpdate

log = logging.getLogger("btmir.collector")

RIS_URL = "wss://ris-live.ripe.net/v1/ws/"


def _make_subscription(filter_asn: Optional[int] = None,
                        filter_prefix: Optional[str] = None) -> str:
    """
    Build the subscription message for RIS Live.
    We can optionally filter by ASN or prefix to reduce volume.
    Without filters we receive the full global BGP feed.
    """
    data = {
        "type": "UPDATE",
        "socketOptions": {"includeRaw": False},
    }
    if filter_asn:
        data["path"] = str(filter_asn)
    if filter_prefix:
        data["prefix"] = filter_prefix

    return json.dumps({
        "type": "ris_subscribe",
        "data": data,
    })


def parse_ris_message(raw: str) -> List[BGPUpdate]:
    """
    Parse a raw RIS Live message into BGPUpdate objects.

    RIS sends one message per BGP UPDATE, but each UPDATE
    can contain multiple prefixes. We return one BGPUpdate
    per prefix so our system processes them individually.

    Returns empty list if message is not a BGP UPDATE.
    """
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        return []

    if msg.get("type") != "ris_message":
        return []

    data = msg.get("data", {})
    if data.get("type") != "UPDATE":
        return []

    # Parse AS path — handle both flat lists and AS sets
    as_path_raw = data.get("path", [])
    as_path: List[int] = []
    for hop in as_path_raw:
        if isinstance(hop, list):
            # AS set — take first AS as representative
            if hop:
                as_path.append(int(hop[0]))
        else:
            try:
                as_path.append(int(hop))
            except (ValueError, TypeError):
                pass

    if not as_path:
        return []

    peer_asn = int(data.get("peer_asn", 0))
    peer_ip  = data.get("peer",     "")
    timestamp = float(data.get("timestamp", 0))

    communities = []
    for c in data.get("community", []):
        if isinstance(c, (list, tuple)) and len(c) == 2:
            communities.append(f"{c[0]}:{c[1]}")

    updates: List[BGPUpdate] = []

    # Announced prefixes
    for ann in data.get("announcements", []):
        for prefix in ann.get("prefixes", []):
            updates.append(BGPUpdate(
                timestamp  = timestamp,
                peer_asn   = peer_asn,
                peer_ip    = peer_ip,
                prefix     = prefix,
                as_path    = as_path,
                origin_asn = as_path[-1],
                announced  = True,
            ))

    # Withdrawn prefixes
    for prefix in data.get("withdrawals", []):
        updates.append(BGPUpdate(
            timestamp  = timestamp,
            peer_asn   = peer_asn,
            peer_ip    = peer_ip,
            prefix     = prefix,
            as_path    = as_path,
            origin_asn = as_path[-1],
            announced  = False,
        ))

    return updates


class RISCollector:
    """
    Connects to RIPE RIS Live and calls on_update() for
    every real BGP announcement received.

    Automatically reconnects if the connection drops.
    """

    def __init__(self,
                 on_update: Callable[[BGPUpdate], None],
                 filter_asn:    Optional[int] = None,
                 filter_prefix: Optional[str] = None,
                 reconnect_delay: float = 5.0):
        self.on_update       = on_update
        self.filter_asn      = filter_asn
        self.filter_prefix   = filter_prefix
        self.reconnect_delay = reconnect_delay
        self._running        = False

        # Stats
        self.updates_received = 0
        self.parse_errors     = 0
        self.reconnects       = 0

    async def _connect_once(self):
        """Open one WebSocket connection and stream updates."""
        async with websockets.connect(
            RIS_URL,
            ping_interval=30,
            ping_timeout=10,
        ) as ws:
            log.info("Connected to RIPE RIS Live")

            # Send subscription
            sub = _make_subscription(self.filter_asn,
                                      self.filter_prefix)
            await ws.send(sub)
            log.info(f"Subscribed | filter_asn={self.filter_asn} "
                     f"filter_prefix={self.filter_prefix}")

            async for raw in ws:
                if not self._running:
                    break
                try:
                    updates = parse_ris_message(raw)
                    for upd in updates:
                        self.updates_received += 1
                        self.on_update(upd)
                except Exception as e:
                    self.parse_errors += 1
                    log.debug(f"Parse error: {e}")

    async def run(self):
        """
        Run forever, reconnecting on any error.
        Call stop() to terminate cleanly.
        """
        self._running = True
        while self._running:
            try:
                await self._connect_once()
            except Exception as e:
                if self._running:
                    self.reconnects += 1
                    log.warning(
                        f"RIS connection lost: {e} — "
                        f"reconnecting in {self.reconnect_delay}s"
                    )
                    await asyncio.sleep(self.reconnect_delay)

    def stop(self):
        self._running = False

    def stats(self) -> dict:
        return {
            "updates_received": self.updates_received,
            "parse_errors":     self.parse_errors,
            "reconnects":       self.reconnects,
        }