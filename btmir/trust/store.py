# btmir/trust/store.py

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from typing import Dict, List, Optional
from btmir.trust.models import TrustScore


# ── Schema ─────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_scores (
    asn          INTEGER PRIMARY KEY,
    wb           REAL    NOT NULL,
    wd           REAL    NOT NULL,
    wr           REAL    NOT NULL,
    final        REAL    NOT NULL,
    is_isolated  INTEGER NOT NULL,
    reason       TEXT    NOT NULL,
    updated_at   REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS interactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asn          INTEGER NOT NULL,
    peer_asn     INTEGER NOT NULL,
    success      INTEGER NOT NULL,
    epoch        INTEGER NOT NULL,
    recorded_at  REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_interactions_asn
    ON interactions(asn);

CREATE TABLE IF NOT EXISTS prefix_history (
    prefix       TEXT    NOT NULL,
    origin_asn   INTEGER NOT NULL,
    first_seen   REAL    NOT NULL,
    last_seen    REAL    NOT NULL,
    count        INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (prefix, origin_asn)
);

CREATE TABLE IF NOT EXISTS audit_chain (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    block_index  INTEGER NOT NULL,
    timestamp    REAL    NOT NULL,
    asn          INTEGER NOT NULL,
    final_score  REAL    NOT NULL,
    action       TEXT    NOT NULL,
    prev_hash    TEXT    NOT NULL,
    block_hash   TEXT    NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS as_paths (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix      TEXT    NOT NULL,
    as_path     TEXT    NOT NULL,
    origin_asn  INTEGER NOT NULL,
    peer_asn    INTEGER NOT NULL,
    recorded_at REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_as_paths_time
    ON as_paths(recorded_at DESC);
"""


class TrustStore:
    """
    Persistent storage for the BTMIR trust system.

    Three types of data:
    - trust_scores    : current trust state per AS
    - interactions    : raw routing history per AS
    - prefix_history  : which ASes have announced which prefixes
    - audit_chain     : immutable hash-chained record of all decisions
    """

    def __init__(self, db_path: str = "btmir.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Trust Scores ───────────────────────────────────────
    def save_trust(self, score: TrustScore):
        """
        Save or update trust score for an AS.
        Only writes a new audit block if the score changed
        meaningfully — reducing chain growth dramatically.
        """
        # Check existing score before writing
        existing = self.get_trust(score.asn)

        with self._conn() as conn:
            conn.execute("""
                INSERT INTO trust_scores
                    (asn, wb, wd, wr, final, is_isolated, reason, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asn) DO UPDATE SET
                    wb          = excluded.wb,
                    wd          = excluded.wd,
                    wr          = excluded.wr,
                    final       = excluded.final,
                    is_isolated = excluded.is_isolated,
                    reason      = excluded.reason,
                    updated_at  = excluded.updated_at
            """, (
                score.asn, score.wb, score.wd, score.wr,
                score.final, int(score.is_isolated),
                score.reason, time.time()
            ))

            # Only append audit block if something meaningful changed
            if self._score_changed(existing, score):
                action = "ISOLATED" if score.is_isolated else "UPDATE"
                if existing is None:
                    action = "NEW"
                self._append_audit_block(conn, score, action)

    def _score_changed(self, existing: Optional[TrustScore],
                        new: TrustScore) -> bool:
        """
        Returns True if the trust score changed enough to
        warrant a new audit block.
        """
        if existing is None:
            return True   # new AS — always record first block

        # Always record isolation status changes — these are critical
        if existing.is_isolated != new.is_isolated:
            return True

        # Only record if score moved by more than 15%
        # Small WR fluctuations from sampling don't need recording
        if abs(existing.final - new.final) >= 0.15:
            return True

        return False

    def get_trust(self, asn: int) -> Optional[TrustScore]:
        """Get current trust score for an AS. Returns None if unknown."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM trust_scores WHERE asn = ?", (asn,)
            ).fetchone()
        if row is None:
            return None
        return TrustScore(
            asn        = row["asn"],
            wb         = row["wb"],
            wd         = row["wd"],
            wr         = row["wr"],
            final      = row["final"],
            is_isolated = bool(row["is_isolated"]),
            reason     = row["reason"],
        )

    def get_all_trust(self) -> List[TrustScore]:
        """Get trust scores for all known ASes."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM trust_scores ORDER BY final DESC"
            ).fetchall()
        return [
            TrustScore(
                asn        = r["asn"],
                wb         = r["wb"],
                wd         = r["wd"],
                wr         = r["wr"],
                final      = r["final"],
                is_isolated = bool(r["is_isolated"]),
                reason     = r["reason"],
            ) for r in rows
        ]

    def get_isolated(self) -> List[int]:
        """Return ASNs of all currently isolated ASes."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT asn FROM trust_scores WHERE is_isolated = 1"
            ).fetchall()
        return [r["asn"] for r in rows]

    # ── Interaction History ────────────────────────────────

    def record_interaction(self, asn: int, peer_asn: int,
                           success: bool, epoch: int):
        """Record one routing interaction with an AS."""
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO interactions
                    (asn, peer_asn, success, epoch, recorded_at)
                VALUES (?, ?, ?, ?, ?)
            """, (asn, peer_asn, int(success), epoch, time.time()))

    def get_interactions(self, asn: int) -> List[Dict]:
        """
        Get interaction history for an AS.
        Returns list of dicts ready for compute_wd().
        """
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT success, epoch,
                       MAX(epoch) OVER () as max_epoch
                FROM interactions
                WHERE asn = ?
                ORDER BY recorded_at DESC
                LIMIT 200
            """, (asn,)).fetchall()
        return [
            {
                "success": bool(r["success"]),
                "age":     r["max_epoch"] - r["epoch"],
            }
            for r in rows
        ]

    # ── Prefix History ─────────────────────────────────────

    def record_prefix(self, prefix: str, origin_asn: int):
        """Record that an AS announced a prefix."""
        now = time.time()
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO prefix_history
                    (prefix, origin_asn, first_seen, last_seen, count)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(prefix, origin_asn) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    count     = count + 1
            """, (prefix, origin_asn, now, now))

    def get_prefix_origins(self, prefix: str) -> List[Dict]:
        """
        Get all ASes ever seen announcing a prefix.
        Ordered by count — most frequent first.
        Used by hijack detector.
        """
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT origin_asn, first_seen, last_seen, count
                FROM prefix_history
                WHERE prefix = ?
                ORDER BY count DESC
            """, (prefix,)).fetchall()
        return [dict(r) for r in rows]

    # ── Audit Chain ────────────────────────────────────────

    def _append_audit_block(self, conn: sqlite3.Connection,
                         score: TrustScore, action: str = "UPDATE"):
        last = conn.execute(
            "SELECT block_hash FROM audit_chain ORDER BY block_index DESC LIMIT 1"
        ).fetchone()
        prev_hash   = last["block_hash"] if last else "0" * 64
        block_index = conn.execute(
            "SELECT COUNT(*) as c FROM audit_chain"
        ).fetchone()["c"]

        # Compute timestamp ONCE — used in both payload and insert
        ts = time.time()

        payload = json.dumps({
            "index":  block_index,
            "asn":    score.asn,
            "score":  score.final,
            "action": action,
            "prev":   prev_hash,
            "ts":     ts,
        }, sort_keys=True)
        block_hash = hashlib.sha256(payload.encode()).hexdigest()

        conn.execute("""
            INSERT INTO audit_chain
                (block_index, timestamp, asn, final_score,
                action, prev_hash, block_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            block_index, ts, score.asn,
            score.final, action, prev_hash, block_hash
        ))

    def verify_chain(self) -> bool:
        """
        Verify the entire audit chain has not been tampered with.
        Returns True if valid, False if any block has been altered.
        """
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_chain ORDER BY block_index"
            ).fetchall()

        if not rows:
            return True

        prev_hash = "0" * 64
        for row in rows:
            if row["prev_hash"] != prev_hash:
                return False
            payload = json.dumps({
                "index":  row["block_index"],
                "asn":    row["asn"],
                "score":  row["final_score"],
                "action": row["action"],
                "prev":   row["prev_hash"],
                "ts":     row["timestamp"],
            }, sort_keys=True)
            expected = hashlib.sha256(payload.encode()).hexdigest()
            if expected != row["block_hash"]:
                return False
            prev_hash = row["block_hash"]

        return True

    def chain_length(self) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) as c FROM audit_chain"
            ).fetchone()["c"]

    def record_as_path(self, prefix: str, as_path: List[int],
                    origin_asn: int, peer_asn: int):
        """Store a real AS path from a BGP update."""
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO as_paths
                    (prefix, as_path, origin_asn, peer_asn, recorded_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                prefix,
                ','.join(str(a) for a in as_path),
                origin_asn, peer_asn, time.time()
            ))
            # Keep only last 500 paths to avoid bloat
            conn.execute("""
                DELETE FROM as_paths WHERE id NOT IN (
                    SELECT id FROM as_paths
                    ORDER BY recorded_at DESC LIMIT 500
                )
            """)

    def get_recent_paths(self, limit: int = 100) -> List[Dict]:
        """Get recent AS paths for graph visualization."""
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT prefix, as_path, origin_asn,
                    peer_asn, recorded_at
                FROM as_paths
                ORDER BY recorded_at DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_as_edges(self) -> List[Dict]:
        """
        Extract unique AS-to-AS edges from stored paths.
        Returns list of {source, target, count} representing
        real peering relationships seen in BGP updates.
        """
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT as_path FROM as_paths
                ORDER BY recorded_at DESC LIMIT 200
            """).fetchall()

        edge_counts = {}
        for row in rows:
            hops = [int(x) for x in row['as_path'].split(',') if x]
            for i in range(len(hops) - 1):
                key = (hops[i], hops[i+1])
                edge_counts[key] = edge_counts.get(key, 0) + 1

        return [
            {'source': s, 'target': t, 'count': c}
            for (s, t), c in edge_counts.items()
        ]



    # ── Stats ──────────────────────────────────────────────

    def stats(self) -> Dict:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) as c FROM trust_scores"
            ).fetchone()["c"]
            isolated = conn.execute(
                "SELECT COUNT(*) as c FROM trust_scores WHERE is_isolated = 1"
            ).fetchone()["c"]
            prefixes = conn.execute(
                "SELECT COUNT(DISTINCT prefix) as c FROM prefix_history"
            ).fetchone()["c"]
        return {
            "total_asns":     total,
            "isolated_asns":  isolated,
            "known_prefixes": prefixes,
            "chain_length":   self.chain_length(),
            "chain_valid":    self.verify_chain(),
        }
        