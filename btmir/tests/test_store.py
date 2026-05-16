# btmir/tests/test_store.py

import os
import pytest
from btmir.trust.models import TrustScore
from btmir.trust.store  import TrustStore


# ── Fixture ────────────────────────────────────────────────
# Creates a fresh temporary database for each test.
# Deleted after the test finishes.

@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test.db"
    return TrustStore(str(db))


def make_score(asn=13335, final=0.8, isolated=False):
    return TrustScore(
        asn        = asn,
        wb         = 0.9,
        wd         = 0.8,
        wr         = 0.7,
        final      = final,
        is_isolated = isolated,
        reason     = "test",
    )


# ── Trust Score Tests ──────────────────────────────────────

def test_save_and_retrieve(store):
    """A saved trust score should be retrievable."""
    score = make_score(asn=13335, final=0.8)
    store.save_trust(score)
    result = store.get_trust(13335)
    assert result is not None
    assert result.asn   == 13335
    assert result.final == 0.8

def test_unknown_as_returns_none(store):
    """Querying an AS we've never seen should return None."""
    assert store.get_trust(99999) is None

def test_update_overwrites_score(store):
    """Saving a new score for an existing AS updates it."""
    store.save_trust(make_score(asn=13335, final=0.8))
    store.save_trust(make_score(asn=13335, final=0.3))
    result = store.get_trust(13335)
    assert result.final == 0.3

def test_isolated_flag_saved(store):
    """is_isolated flag should be stored and retrieved correctly."""
    store.save_trust(make_score(asn=99999, final=0.2, isolated=True))
    result = store.get_trust(99999)
    assert result.is_isolated is True

def test_get_isolated_returns_correct_asns(store):
    """get_isolated should return only isolated ASes."""
    store.save_trust(make_score(asn=13335, final=0.8, isolated=False))
    store.save_trust(make_score(asn=99999, final=0.2, isolated=True))
    store.save_trust(make_score(asn=88888, final=0.1, isolated=True))
    isolated = store.get_isolated()
    assert 99999 in isolated
    assert 88888 in isolated
    assert 13335 not in isolated

def test_get_all_trust(store):
    """get_all_trust should return all saved scores."""
    store.save_trust(make_score(asn=13335, final=0.8))
    store.save_trust(make_score(asn=15169, final=0.9))
    store.save_trust(make_score(asn=99999, final=0.1))
    all_scores = store.get_all_trust()
    asns = [s.asn for s in all_scores]
    assert 13335 in asns
    assert 15169 in asns
    assert 99999 in asns


# ── Interaction History Tests ──────────────────────────────

def test_record_and_retrieve_interactions(store):
    """Recorded interactions should be retrievable."""
    store.record_interaction(asn=13335, peer_asn=1299,
                             success=True, epoch=1)
    store.record_interaction(asn=13335, peer_asn=1299,
                             success=True, epoch=2)
    history = store.get_interactions(13335)
    assert len(history) == 2

def test_interactions_have_correct_fields(store):
    """Each interaction should have success and age fields."""
    store.record_interaction(asn=13335, peer_asn=1299,
                             success=True, epoch=5)
    history = store.get_interactions(13335)
    assert "success" in history[0]
    assert "age"     in history[0]

def test_interactions_age_calculated(store):
    """Age should be relative to the most recent epoch."""
    store.record_interaction(asn=13335, peer_asn=1299,
                             success=True, epoch=1)
    store.record_interaction(asn=13335, peer_asn=1299,
                             success=True, epoch=6)
    history = store.get_interactions(13335)
    ages = [h["age"] for h in history]
    # Most recent epoch (6) has age 0, oldest (1) has age 5
    assert 0 in ages
    assert 5 in ages

def test_no_interactions_returns_empty(store):
    """AS with no history should return empty list."""
    assert store.get_interactions(99999) == []


# ── Prefix History Tests ───────────────────────────────────

def test_record_and_retrieve_prefix(store):
    """A recorded prefix origin should be retrievable."""
    store.record_prefix("1.2.3.0/24", 13335)
    origins = store.get_prefix_origins("1.2.3.0/24")
    assert len(origins) == 1
    assert origins[0]["origin_asn"] == 13335

def test_prefix_count_increments(store):
    """Seeing the same prefix from same AS increments count."""
    store.record_prefix("1.2.3.0/24", 13335)
    store.record_prefix("1.2.3.0/24", 13335)
    store.record_prefix("1.2.3.0/24", 13335)
    origins = store.get_prefix_origins("1.2.3.0/24")
    assert origins[0]["count"] == 3

def test_multiple_origins_for_prefix(store):
    """Same prefix from different ASes = multiple origin records."""
    store.record_prefix("1.2.3.0/24", 13335)
    store.record_prefix("1.2.3.0/24", 99999)
    origins = store.get_prefix_origins("1.2.3.0/24")
    asns = [o["origin_asn"] for o in origins]
    assert 13335 in asns
    assert 99999 in asns

def test_dominant_origin_first(store):
    """Most frequently seen origin should come first."""
    for _ in range(10):
        store.record_prefix("1.2.3.0/24", 13335)
    store.record_prefix("1.2.3.0/24", 99999)
    origins = store.get_prefix_origins("1.2.3.0/24")
    assert origins[0]["origin_asn"] == 13335

def test_unknown_prefix_returns_empty(store):
    """Prefix we've never seen should return empty list."""
    assert store.get_prefix_origins("9.9.9.0/24") == []


# ── Audit Chain Tests ──────────────────────────────────────

def test_chain_valid_after_saves(store):
    """Chain should be valid after normal saves."""
    store.save_trust(make_score(asn=13335, final=0.8))
    store.save_trust(make_score(asn=15169, final=0.9))
    store.save_trust(make_score(asn=99999, final=0.1))
    assert store.verify_chain() is True

def test_chain_length_matches_saves(store):
    """Each save should add one block to the chain."""
    store.save_trust(make_score(asn=13335))
    store.save_trust(make_score(asn=15169))
    store.save_trust(make_score(asn=99999))
    assert store.chain_length() == 3

def test_chain_detects_tampering(store):
    """
    If we directly modify the database bypassing the store,
    verify_chain should catch it.
    """
    store.save_trust(make_score(asn=13335, final=0.8))
    store.save_trust(make_score(asn=15169, final=0.9))

    # Directly tamper with the database
    import sqlite3
    conn = sqlite3.connect(store.db_path)
    conn.execute(
        "UPDATE audit_chain SET final_score = 0.1 WHERE asn = 13335"
    )
    conn.commit()
    conn.close()

    assert store.verify_chain() is False

def test_empty_chain_is_valid(store):
    """An empty chain should be considered valid."""
    assert store.verify_chain() is True


# ── Stats Tests ────────────────────────────────────────────

def test_stats_correct(store):
    """Stats should accurately reflect current state."""
    store.save_trust(make_score(asn=13335, final=0.8, isolated=False))
    store.save_trust(make_score(asn=99999, final=0.2, isolated=True))
    store.record_prefix("1.2.3.0/24", 13335)

    s = store.stats()
    assert s["total_asns"]    == 2
    assert s["isolated_asns"] == 1
    assert s["known_prefixes"] == 1
    assert s["chain_length"]  == 2
    assert s["chain_valid"]   is True