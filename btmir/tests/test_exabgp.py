# btmir/tests/test_exabgp.py

import json
import pytest
from btmir.trust.store  import TrustStore
from btmir.trust.models import TrustScore
from btmir.bgp.exabgp   import parse_exabgp_message, ExaBGPHandler


# ── Fixtures ───────────────────────────────────────────────

@pytest.fixture
def store(tmp_path):
    return TrustStore(str(tmp_path / "test.db"))

@pytest.fixture
def handler(store):
    return ExaBGPHandler(store, next_hop="192.168.1.1")


def exabgp_msg(prefixes=None, withdrawals=None,
               as_path=None, peer_asn=65001,
               peer_ip="192.168.1.1"):
    """Build a realistic ExaBGP JSON message."""
    as_path = as_path or [65001, 13335]
    data = {
        "type": "update",
        "neighbor": {
            "asn":     {"peer": str(peer_asn)},
            "address": {"peer": peer_ip},
        },
        "update": {
            "attribute": {
                "as-path": [as_path]
            },
        }
    }
    if prefixes:
        data["update"]["announce"] = {
            "ipv4 unicast": {
                peer_ip: prefixes
            }
        }
    if withdrawals:
        data["update"]["withdraw"] = {
            "ipv4 unicast": withdrawals
        }
    return json.dumps(data)


# ── Parser Tests ───────────────────────────────────────────

def test_parse_announcement():
    """ExaBGP announcement should parse correctly."""
    raw = exabgp_msg(prefixes=["1.2.3.0/24"],
                     as_path=[65001, 13335])
    updates = parse_exabgp_message(raw)
    assert len(updates) == 1
    u = updates[0]
    assert u.prefix     == "1.2.3.0/24"
    assert u.origin_asn == 13335
    assert u.announced  is True

def test_parse_withdrawal():
    """ExaBGP withdrawal should have announced=False."""
    raw = exabgp_msg(withdrawals=["1.2.3.0/24"],
                     as_path=[65001, 13335])
    updates = parse_exabgp_message(raw)
    assert len(updates) == 1
    assert updates[0].announced is False

def test_parse_multiple_prefixes():
    """Multiple prefixes in one message."""
    raw = exabgp_msg(
        prefixes=["1.2.3.0/24", "5.6.7.0/24"],
        as_path=[65001, 13335],
    )
    updates = parse_exabgp_message(raw)
    assert len(updates) == 2

def test_parse_non_update_ignored():
    """Non-update messages should return empty list."""
    raw = json.dumps({"type": "state", "neighbor": {}})
    assert parse_exabgp_message(raw) == []

def test_parse_invalid_json_ignored():
    """Invalid JSON should not crash."""
    assert parse_exabgp_message("not json") == []

def test_parse_empty_line_ignored():
    """Empty lines should return empty list."""
    assert parse_exabgp_message("") == []


# ── Handler Decision Tests ─────────────────────────────────

def test_trusted_as_accepted(handler, store):
    """
    An AS with good trust score should have its
    route accepted.
    """
    # Pre-populate with good trust score
    store.save_trust(TrustScore(
        asn=13335, wb=0.9, wd=0.9, wr=0.8,
        final=0.88, is_isolated=False,
        reason="trusted",
    ))
    # Give it good interaction history
    for i in range(10):
        store.record_interaction(13335, 65001,
                                 success=True, epoch=i)

    raw = exabgp_msg(prefixes=["1.2.3.0/24"],
                     as_path=[65001, 13335])
    updates = parse_exabgp_message(raw)
    result  = handler._evaluate(updates[0])
    assert result is True

def test_isolated_as_rejected(handler, store):
    """
    An AS already marked as isolated should be rejected.
    Its routes should be withdrawn.
    """
    # Pre-populate with bad trust score
    store.save_trust(TrustScore(
        asn=99999, wb=0.1, wd=0.1, wr=0.1,
        final=0.1, is_isolated=True,
        reason="malicious",
    ))
    for i in range(5):
        store.record_interaction(99999, 65001,
                                 success=False, epoch=i)

    raw = exabgp_msg(prefixes=["10.0.0.0/8"],
                     as_path=[65001, 99999])
    updates = parse_exabgp_message(raw)
    result  = handler._evaluate(updates[0])
    assert result is False

def test_hijack_rejected(handler, store):
    """
    A detected hijack should be rejected even if
    the AS has no prior bad trust score.
    """
    # Establish legitimate prefix history
    for _ in range(20):
        store.record_prefix("1.2.3.0/24", 13335)

    # Now a different AS announces the same prefix
    raw = exabgp_msg(prefixes=["1.2.3.0/24"],
                     as_path=[65001, 99999])
    updates = parse_exabgp_message(raw)
    result  = handler._evaluate(updates[0])
    assert result is False

def test_stats_track_decisions(handler, store):
    """Accepted and rejected counts should be tracked."""
    # Good AS
    store.save_trust(TrustScore(
        asn=13335, wb=0.9, wd=0.9, wr=0.8,
        final=0.88, is_isolated=False,
        reason="trusted",
    ))
    for i in range(10):
        store.record_interaction(13335, 65001,
                                 success=True, epoch=i)

    raw = exabgp_msg(prefixes=["1.2.3.0/24"],
                     as_path=[65001, 13335])

    # Simulate process_line without actual stdout
    updates = parse_exabgp_message(raw)
    for upd in updates:
        accept = handler._evaluate(upd)
        if accept:
            handler.accepted += 1
        else:
            handler.rejected += 1

    s = handler.stats()
    assert s["accepted"] + s["rejected"] > 0
    