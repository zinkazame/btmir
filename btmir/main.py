# btmir/main.py
# Entry point — starts all components together.
#
# Usage:
#   python -m btmir.main                        # live BGP stream
#   python -m btmir.main --filter-asn 13335     # watch one AS
#   python -m btmir.main --port 9000            # custom API port

import asyncio
import logging
import threading
import time

import click
import uvicorn

from btmir.trust.store     import TrustStore
from btmir.trust.engine    import compute_trust
from btmir.trust.models    import BGPUpdate
from btmir.security.hijack import HijackDetector, HijackAlert
from btmir.collector.ris   import RISCollector
from btmir.api.server      import app, init, add_alert
from btmir.security.rpki   import RPKIValidator

log = logging.getLogger("btmir")


class BTMIR:
    """
    Orchestrates all components into one running system.
    """

    def __init__(self, db_path: str, api_port: int,
                 filter_asn: int = None,
                 filter_prefix: str = None):
        self.db_path       = db_path
        self.api_port      = api_port
        self.filter_asn    = filter_asn
        self.filter_prefix = filter_prefix

        # Core components
        self.store    = TrustStore(db_path)
        self.detector = HijackDetector(
            self.store,
            on_alert=self._on_hijack,
        )
        self.collector = RISCollector(
            on_update      = self._on_update,
            filter_asn     = filter_asn,
            filter_prefix  = filter_prefix,
        )

        # Wire API to store
        init(self.store)

        # Epoch counter for interaction recording
        
        self._epoch = 0
        self._update_counts = {}
        self._rpki = RPKIValidator(cache_ttl=3600)
        self._rpki_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def _get_recommendations(self, asn: int):
        all_scores = self.store.get_all_trust()
        return [
            {
                "score":             s.final,
                "recommender_trust": s.final,
            }
            for s in all_scores if s.asn != asn
        ]

    def _on_update(self, update: BGPUpdate):
        """Called for every real BGP update from RIPE RIS."""
        self._epoch += 1

        # Record prefix for hijack detection history
        self.store.record_prefix(update.prefix,
                                update.origin_asn)

        # Record real AS path for graph visualization
        self.store.record_as_path(
            update.prefix,
            update.as_path,
            update.origin_asn,
            update.peer_asn,
        )

        # Run hijack detection
        self.detector.inspect(update)

        # Throttle trust recomputation to every 5 updates per AS
        asn = update.origin_asn
        self._update_counts[asn] = \
            self._update_counts.get(asn, 0) + 1
        if self._update_counts[asn] % 5 != 0:
            self.store.record_interaction(
                asn      = asn,
                peer_asn = update.peer_asn,
                success  = True,
                epoch    = self._epoch,
            )
            return

        # Queue RPKI validation
        try:
            self._rpki_queue.put_nowait(
                (update.origin_asn, update.prefix)
            )
        except asyncio.QueueFull:
            pass

        # Get RPKI result from cache
        rpki_result  = self._rpki.get_cached(
            update.origin_asn, update.prefix
        )
        rpki_valid   = rpki_result.valid if rpki_result else False
        rpki_fraction = self._rpki.rpki_valid_fraction(asn)
        if rpki_fraction != 0.5:
            rpki_valid = rpki_fraction > 0.5

        # Compute trust for origin AS
        history = self.store.get_interactions(asn)
        recs    = self._get_recommendations(asn)
        result  = compute_trust(
            update              = update,
            rpki_valid          = rpki_valid,
            interaction_history = history,
            recommendations     = recs,
        )
        self.store.save_trust(result)

        # Record interaction
        self.store.record_interaction(
            asn      = asn,
            peer_asn = update.peer_asn,
            success  = not result.is_isolated,
            epoch    = self._epoch,
        )

        # Evaluate all transit ASes in the path
        # Evaluate all transit ASes in the path
        for hop_asn in set(update.as_path):
            if hop_asn == update.origin_asn:
                continue
            hop_update = BGPUpdate(
                timestamp  = update.timestamp,
                peer_asn   = update.peer_asn,
                peer_ip    = update.peer_ip,
                prefix     = update.prefix,
                as_path    = update.as_path,
                origin_asn = hop_asn,
                announced  = update.announced,
            )
            hop_history = self.store.get_interactions(hop_asn)
            hop_recs    = self._get_recommendations(hop_asn)
            hop_result  = compute_trust(
                update              = hop_update,
                rpki_valid          = False,
                interaction_history = hop_history,
                recommendations     = hop_recs,
                is_transit          = True,    # ← key change
            )
            self.store.save_trust(hop_result)

        if result.is_isolated:
            log.warning(
                f"ISOLATED AS{asn} | "
                f"prefix={update.prefix} | "
                f"T={result.final:.3f}"
            )

    def _on_hijack(self, alert: HijackAlert):
        """Called when hijack detector fires an alert."""
        log.critical(str(alert))
        add_alert({
            "prefix":       alert.prefix,
            "legit_origin": alert.legit_origin,
            "seen_origin":  alert.seen_origin,
            "confidence":   alert.confidence,
            "attack_type":  alert.attack_type,
            "severity":     alert.severity,
            "timestamp":    alert.timestamp,
        })

    def _start_api(self):
        """Run FastAPI in a background thread."""
        config = uvicorn.Config(
            app,
            host      = "0.0.0.0",
            port      = self.api_port,
            log_level = "warning",
        )
        uvicorn.Server(config).run()

    def _print_stats_loop(self):
        """Print stats every 30 seconds."""
        while True:
            time.sleep(30)
            s = self.store.stats()
            c = self.collector.stats()
            log.info(
                f"Stats | "
                f"ASes={s['total_asns']} "
                f"isolated={s['isolated_asns']} "
                f"prefixes={s['known_prefixes']} "
                f"updates={c['updates_received']} "
                f"alerts={self.detector.stats()['alerts_fired']} "
                f"chain={s['chain_length']} blocks"
            )

    async def run(self):
        """Start all components."""
        log.info(f"BTMIR starting | db={self.db_path}")
        log.info(f"Filter ASN    : {self.filter_asn or 'none'}")
        log.info(f"Filter prefix : {self.filter_prefix or 'none'}")

        # Start API server in background thread
        api_thread = threading.Thread(
            target=self._start_api, daemon=True
        )
        api_thread.start()
        log.info(f"API server → http://localhost:{self.api_port}")
        log.info(f"Docs       → http://localhost:{self.api_port}/docs")

        # Start stats printer in background thread
        stats_thread = threading.Thread(
            target=self._print_stats_loop, daemon=True
        )
        stats_thread.start()
        # Start RPKI background validator
        asyncio.create_task(self._rpki_worker())
        log.info("RPKI validator started")

        # Connect to RIPE RIS Live — runs forever
        log.info("Connecting to RIPE RIS Live...")
        await self.collector.run()
    async def _rpki_worker(self):
        """
        Background worker that drains the RPKI queue.
        Validates prefix/origin pairs asynchronously so
        the main BGP processing loop is never blocked.
        """
        while True:
            try:
                asn, prefix = await asyncio.wait_for(
                    self._rpki_queue.get(), timeout=1.0
                )
                await self._rpki.validate(asn, prefix)
                self._rpki_queue.task_done()
            except asyncio.TimeoutError:
                # No work — clean expired cache entries
                self._rpki.clear_expired()
            except Exception as e:
                log.debug(f"RPKI worker error: {e}")



@click.command()
@click.option("--db",      default="btmir.db", show_default=True,
              help="SQLite database path")
@click.option("--port",    default=8000, show_default=True,
              help="REST API port")
@click.option("--filter-asn",    default=None, type=int,
              help="Watch only this ASN")
@click.option("--filter-prefix", default=None,
              help="Watch only this prefix")
@click.option("--log-level", default="INFO",
              type=click.Choice(["DEBUG","INFO","WARNING"]),
              help="Log verbosity")
def main(db, port, filter_asn, filter_prefix, log_level):
    """BTMIR — Blockchain-Based BGP Trust System"""
    logging.basicConfig(
        level  = getattr(logging, log_level),
        format = "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    system = BTMIR(
        db_path       = db,
        api_port      = port,
        filter_asn    = filter_asn,
        filter_prefix = filter_prefix,
    )
    asyncio.run(system.run())


if __name__ == "__main__":
    main()