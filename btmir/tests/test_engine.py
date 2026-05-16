# btmir/tests/test_engine.py

import pytest
from btmir.trust.models import BGPUpdate
from btmir.trust.engine import (
    compute_wb,
    compute_wd,
    compute_wr,
    compute_trust,
    check_path_anomaly,
    apply_decay,
    TRUST_THRESHOLD,
    SECURITY_GATE,
)


# ── Helper ─────────────────────────────────────────────────
def make_update(origin_asn=13335, prefix="1.2.3.0/24",
                as_path=None, peer_asn=1299):
    return BGPUpdate(
        timestamp=1715698800.0,
        peer_asn=peer_asn,
        peer_ip="72.52.92.213",
        prefix=prefix,
        as_path=as_path or [1299, 3356, origin_asn],
        origin_asn=origin_asn,
        announced=True,
    )


# ── Time Decay Tests ───────────────────────────────────────
def test_decay_age_zero_unchanged():
    """An interaction from this epoch should not be decayed."""
    assert apply_decay(1.0, 0) == 1.0

def test_decay_reduces_with_age():
    """Older interactions must be worth less."""
    assert apply_decay(1.0, 5) < apply_decay(1.0, 0)
    assert apply_decay(1.0, 10) < apply_decay(1.0, 5)

def test_decay_never_negative():
    """Decay should never produce a negative value."""
    assert apply_decay(1.0, 1000) >= 0.0


# ── WB Tests ───────────────────────────────────────────────
def test_wb_perfect():
    """RPKI valid + clean path = high WB."""
    wb = compute_wb(rpki_valid=True, path_anomaly_score=0.0)
    assert wb == 1.0

def test_wb_no_rpki():
    """No RPKI = lower WB even with clean path."""
    wb = compute_wb(rpki_valid=False, path_anomaly_score=0.0)
    assert wb < 1.0
    assert wb > 0.0

def test_wb_high_anomaly():
    """High path anomaly = low WB."""
    wb = compute_wb(rpki_valid=True, path_anomaly_score=1.0)
    assert wb < compute_wb(rpki_valid=True, path_anomaly_score=0.0)

def test_wb_worst_case():
    """No RPKI + maximum anomaly = very low WB."""
    wb = compute_wb(rpki_valid=False, path_anomaly_score=1.0)
    assert wb < SECURITY_GATE


# ── Path Anomaly Tests ─────────────────────────────────────
def test_clean_path_no_anomaly():
    """A normal short path should have zero anomaly."""
    assert check_path_anomaly([1299, 3356, 13335]) == 0.0

def test_loop_detected():
    """A path where an AS appears twice is a loop."""
    score = check_path_anomaly([1299, 3356, 1299, 13335])
    assert score >= 0.7

def test_long_path_anomaly():
    """A path longer than 10 hops is suspicious."""
    long_path = list(range(1, 15))   # 14 unique ASes
    score = check_path_anomaly(long_path)
    assert score > 0.0

def test_empty_path_max_anomaly():
    """An empty path is maximally suspicious."""
    assert check_path_anomaly([]) == 1.0


# ── WD Tests ───────────────────────────────────────────────
def test_wd_no_history_neutral():
    """Unknown AS with no history gets neutral score."""
    assert compute_wd([]) == 0.5

def test_wd_all_successful():
    """All successful interactions = high WD."""
    history = [{"success": True, "age": 0} for _ in range(10)]
    wd = compute_wd(history)
    assert wd > 0.9

def test_wd_all_failed():
    """All failed interactions = low WD."""
    history = [{"success": False, "age": 0} for _ in range(10)]
    wd = compute_wd(history)
    assert wd < 0.1

def test_wd_recent_matters_more():
    """Recent success should outweigh old failure."""
    history = [
        {"success": False, "age": 20},  # old failure
        {"success": False, "age": 15},
        {"success": True,  "age": 0},   # recent success
        {"success": True,  "age": 1},
    ]
    wd = compute_wd(history)
    assert wd > 0.5

def test_wd_recent_failure_matters_more():
    """Recent failure should outweigh old success."""
    history = [
        {"success": True,  "age": 20},  # old success
        {"success": True,  "age": 15},
        {"success": False, "age": 0},   # recent failure
        {"success": False, "age": 1},
    ]
    wd = compute_wd(history)
    assert wd < 0.5


# ── WR Tests ───────────────────────────────────────────────
def test_wr_no_recommendations_neutral():
    """No peer opinions = neutral score."""
    assert compute_wr([]) == 0.5

def test_wr_trusted_peers_positive():
    """Highly trusted peers saying good things = high WR."""
    recs = [
        {"score": 0.9, "recommender_trust": 0.95},
        {"score": 0.85, "recommender_trust": 0.90},
    ]
    wr = compute_wr(recs)
    assert wr > 0.8

def test_wr_untrusted_peers_low_influence():
    """
    Collusion resistance test.
    Many malicious ASes trying ballot stuffing should not
    be able to reliably override a trusted peer's opinion.
    We run it 20 times and check the average holds.
    """
    results = []
    for _ in range(20):
        recs = [
            # 8 malicious ASes trying to inflate score
            {"score": 1.0, "recommender_trust": 0.05},
            {"score": 1.0, "recommender_trust": 0.05},
            {"score": 1.0, "recommender_trust": 0.05},
            {"score": 1.0, "recommender_trust": 0.05},
            {"score": 1.0, "recommender_trust": 0.05},
            {"score": 1.0, "recommender_trust": 0.05},
            {"score": 1.0, "recommender_trust": 0.05},
            {"score": 1.0, "recommender_trust": 0.05},
            # 2 trusted ASes giving honest low score
            {"score": 0.2, "recommender_trust": 0.90},
            {"score": 0.2, "recommender_trust": 0.90},
        ]
        results.append(compute_wr(recs))

    average = sum(results) / len(results)
    # Over many runs, honest trusted peers should dominate
    assert average < 0.5, f"Collusion resistance failed, average WR={average:.3f}"


# ── Full Trust Computation Tests ───────────────────────────
def test_trusted_as_cloudflare_like():
    """
    A well-known AS with RPKI, clean history, good reputation
    should score well above threshold.
    """
    update = make_update(origin_asn=13335)
    history = [{"success": True, "age": i} for i in range(20)]
    recs    = [
        {"score": 0.9, "recommender_trust": 0.9},
        {"score": 0.85, "recommender_trust": 0.85},
    ]
    result = compute_trust(
        update=update,
        rpki_valid=True,
        interaction_history=history,
        recommendations=recs,
    )
    assert not result.is_isolated
    assert result.final > TRUST_THRESHOLD
    assert result.wb > 0.0
    assert result.wd > 0.0
    assert result.wr > 0.0

def test_malicious_as_isolated():
    """
    A rogue AS with no RPKI, looping path, bad history
    should be isolated.
    """
    update = make_update(
        origin_asn=99999,
        as_path=[1299, 99999, 1299, 99999],  # loop
    )
    history = [{"success": False, "age": i} for i in range(5)]
    recs    = [{"score": 0.1, "recommender_trust": 0.8}]
    result  = compute_trust(
        update=update,
        rpki_valid=False,
        interaction_history=history,
        recommendations=recs,
    )
    assert result.is_isolated
    assert result.final <= TRUST_THRESHOLD

def test_security_gate_triggers():
    """
    No RPKI + severe path anomaly should fail the security
    gate and never reach WD/WR computation.
    """
    update = make_update(
        origin_asn=99999,
        as_path=[1, 2, 1, 2, 1, 2],  # severe loop
    )
    result = compute_trust(
        update=update,
        rpki_valid=False,
        interaction_history=[],
        recommendations=[],
    )
    assert result.is_isolated
    assert result.wd == 0.0
    assert result.wr == 0.0
    assert "security gate" in result.reason.lower()

def test_new_as_neutral_history():
    """
    A brand new AS with no history but valid RPKI and
    clean path should not be immediately isolated —
    it gets the benefit of the doubt on WD.
    """
    update = make_update(origin_asn=64500)
    result = compute_trust(
        update=update,
        rpki_valid=True,
        interaction_history=[],   # no history yet
        recommendations=[],
    )
    # Should not be isolated — neutral WD of 0.5
    assert not result.is_isolated