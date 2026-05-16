# btmir/bgp/exabgp.py
#
# ExaBGP integration — the enforcement layer.
# Reads BGP updates from ExaBGP via stdin,
# evaluates trust, writes decisions back via stdout.
#
# ExaBGP protocol is simple:
#   - ExaBGP writes JSON BGP events to our stdin
#   - We write text commands to stdout
#   - Commands: "announce route X" or "withdraw route X"
#
# Deployment:
#   In exabgp.conf:
#     process btmir {
#       run python3 -m btmir.bgp.exabgp;
#       encoder json;
#     }

import json
import logging
import sys
import time
from typing import List, Optional

from btmir.trust.models   import BGPUpdate
from btmir.trust.store    import TrustStore
from btmir.trust.engine   import compute_trust, TRUST_THRESHOLD
from btmir.security.hijack import HijackDetector

log = logging.getLogger("btmir.exabgp")


def parse_exabgp_message(line: str) -> List[BGPUpdate]:
    """
    Parse a JSON message from ExaBGP into BGPUpdate objects.

    ExaBGP JSON format:
    {
      "type": "update",
      "neighbor": {
        "asn": {"peer": "65001"},
        "address": {"peer": "192.168.1.1"}
      },
      "update": {
        "attribute": {
          "as-path": [[64500, 64501, 13335]]
        },
        "announce": {
          "ipv4 unicast": {
            "192.168.1.1": ["1.2.3.0/24"]
          }
        },
        "withdraw": {
          "ipv4 unicast": ["5.6.7.0/24"]
        }
      }
    }
    """
    line = line.strip()
    if not line:
        return []

    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return []

    if msg.get("type") != "update":
        return []

    neighbor    = msg.get("neighbor", {})
    peer_asn    = int(neighbor.get("asn", {}).get("peer", 0))
    peer_ip     = neighbor.get("address", {}).get("peer", "")
    update_data = msg.get("update", {})
    attributes  = update_data.get("attribute", {})

    # Parse AS path
    as_path_raw = attributes.get("as-path", [])
    as_path: List[int] = []
    for segment in as_path_raw:
        if isinstance(segment, list):
            as_path.extend(int(x) for x in segment
                           if str(x).isdigit())
        elif str(segment).isdigit():
            as_path.append(int(segment))

    updates: List[BGPUpdate] = []

    # Announced prefixes
    announce = update_data.get("announce", {})
    for family, next_hops in announce.items():
        if not isinstance(next_hops, dict):
            continue
        for next_hop, prefixes in next_hops.items():
            prefix_list = (
                prefixes if isinstance(prefixes, list)
                else [prefixes]
            )
            for prefix in prefix_list:
                updates.append(BGPUpdate(
                    timestamp  = time.time(),
                    peer_asn   = peer_asn,
                    peer_ip    = peer_ip,
                    prefix     = str(prefix),
                    as_path    = as_path,
                    origin_asn = as_path[-1] if as_path else peer_asn,
                    announced  = True,
                ))

    # Withdrawn prefixes
    withdraw = update_data.get("withdraw", {})
    for family, prefixes in withdraw.items():
        prefix_list = (
            prefixes if isinstance(prefixes, list)
            else [prefixes]
        )
        for prefix in prefix_list:
            updates.append(BGPUpdate(
                timestamp  = time.time(),
                peer_asn   = peer_asn,
                peer_ip    = peer_ip,
                prefix     = str(prefix),
                as_path    = as_path,
                origin_asn = as_path[-1] if as_path else peer_asn,
                announced  = False,
            ))

    return updates


class ExaBGPHandler:
    """
    Sits between ExaBGP and our trust system.
    Reads updates from ExaBGP, evaluates trust,
    writes route decisions back to ExaBGP.
    """

    def __init__(self, store: TrustStore,
                 next_hop: str = "self"):
        self.store    = store
        self.next_hop = next_hop
        self.detector = HijackDetector(
            store,
            on_alert=self._on_hijack,
        )

        # Stats
        self.accepted = 0
        self.rejected = 0
        self.hijacks  = 0

    def _get_recommendations(self, asn: int) -> List[dict]:
        """
        Get peer opinions about an AS from the trust store.
        Used for WR computation.
        """
        all_scores = self.store.get_all_trust()
        return [
            {
                "score":             s.final,
                "recommender_trust": s.final,
            }
            for s in all_scores
            if s.asn != asn
        ]

    def _evaluate(self, update: BGPUpdate) -> bool:
        """
        Evaluate whether to accept or reject a route.
        Returns True = accept, False = reject.
        """
        asn = update.origin_asn

        # Check for hijack first — if detected with high
        # confidence, reject regardless of trust score
        alert = self.detector.inspect(update)
        if alert and alert.confidence > 0.70:
            log.warning(
                f"REJECTED (hijack) | "
                f"prefix={update.prefix} | "
                f"origin=AS{asn} | "
                f"{alert.attack_type} confidence="
                f"{alert.confidence:.0%}"
            )
            self.hijacks += 1
            return False

        # Get interaction history and recommendations
        history = self.store.get_interactions(asn)
        recs    = self._get_recommendations(asn)

        # Check RPKI from cache (updated async by RPKI validator)
        # Default to False if no RPKI data yet — conservative
        rpki_valid = self._check_rpki_cache(asn, update.prefix)

        # Compute trust score
        result = compute_trust(
            update              = update,
            rpki_valid          = rpki_valid,
            interaction_history = history,
            recommendations     = recs,
        )

        # Save updated trust score
        self.store.save_trust(result)

        # Record this interaction
        epoch = self.store.chain_length()
        self.store.record_interaction(
            asn      = asn,
            peer_asn = update.peer_asn,
            success  = not result.is_isolated,
            epoch    = epoch,
        )

        if result.is_isolated:
            log.warning(
                f"REJECTED (trust) | "
                f"prefix={update.prefix} | "
                f"origin=AS{asn} | "
                f"T={result.final:.3f}"
            )
            return False

        return True

    def _check_rpki_cache(self, asn: int, prefix: str) -> bool:
        """
        Check RPKI validity from local cache.
        The RPKI validator updates this cache asynchronously.
        Conservative default: unknown = False.
        """
        # In production this reads from a shared cache
        # populated by the async RPKI validator.
        # For now returns False (conservative) until we
        # wire up the full RPKI component.
        return False

    def _on_hijack(self, alert):
        """Called by hijack detector when alert fires."""
        log.critical(str(alert))
        # Withdraw the hijacked route immediately
        self._write_command(
            f"withdraw route {alert.prefix}"
        )

    def _write_command(self, cmd: str):
        """Write a command to ExaBGP via stdout."""
        sys.stdout.write(cmd + "\n")
        sys.stdout.flush()

    def _announce(self, prefix: str):
        self._write_command(
            f"announce route {prefix} "
            f"next-hop {self.next_hop}"
        )

    def _withdraw(self, prefix: str):
        self._write_command(
            f"withdraw route {prefix}"
        )

    def process_line(self, line: str):
        """
        Process one line of ExaBGP input.
        This is the main entry point called for each
        message ExaBGP sends us.
        """
        updates = parse_exabgp_message(line)

        for update in updates:
            if not update.announced:
                # Pass withdrawals through unchanged
                self._withdraw(update.prefix)
                continue

            accept = self._evaluate(update)

            if accept:
                self.accepted += 1
                self._announce(update.prefix)
            else:
                self.rejected += 1
                self._withdraw(update.prefix)

    def run_forever(self):
        """
        Main loop — read from ExaBGP stdin forever.
        This is what ExaBGP calls as a process.
        """
        log.info("BTMIR ExaBGP handler started")

        # Tell ExaBGP we are ready
        sys.stdout.write("startup\n")
        sys.stdout.flush()

        for line in sys.stdin:
            try:
                self.process_line(line)
            except Exception as e:
                log.error(f"Error processing line: {e}")

    def stats(self) -> dict:
        return {
            "accepted": self.accepted,
            "rejected": self.rejected,
            "hijacks":  self.hijacks,
        }


# ── ExaBGP config generator ────────────────────────────────

def generate_config(peer_ip:   str,
                    local_ip:  str,
                    local_asn: int,
                    peer_asn:  int,
                    router_id: str,
                    db_path:   str = "btmir.db") -> str:
    """
    Generate an exabgp.conf file for this deployment.
    """
    return f"""
# exabgp.conf — generated by BTMIR
# Place this file where you run ExaBGP

process btmir {{
    run /usr/bin/env python3 -m btmir.bgp.exabgp --db {db_path};
    encoder json;
}}

neighbor {peer_ip} {{
    router-id {router_id};
    local-address {local_ip};
    local-as {local_asn};
    peer-as {peer_asn};

    family {{
        ipv4 unicast;
    }}

    process btmir;
}}
"""


if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level  = logging.INFO,
        format = "%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream = sys.stderr,
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--db",       default="btmir.db")
    parser.add_argument("--next-hop", default="self")
    args = parser.parse_args()

    store   = TrustStore(args.db)
    handler = ExaBGPHandler(store, next_hop=args.next_hop)
    handler.run_forever()