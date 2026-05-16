# btmir/tests/test_hijack.py

import time
import pytest
from btmir.trust.models  import BGPUpdate
from btmir.trust.store   import TrustStore
from btmir.security.hijack import HijackDetector, HijackAlert


# ── Fixtures ───────────────────────────────────────────────

@pytest.fixture
def store(tmp_path):
    return TrustStore(str(tmp_path / "test.db"))

@pytest.fixture
def alerts():
    return []

@pytest.fixture
def detector(store, alerts):
    return HijackDetector(store, on_alert=lambda a: alerts.append(a))


def make_update(prefix, origin_asn, peer_asn=1299, announced=True):
    return BGPUpdate(
        timestamp  = time.time(),
        peer_asn   = peer_asn,
        peer_ip    = "72.52.92.213",
        prefix     = prefix,
        as_path    = [1299, origin_asn],
        origin_asn = origin_asn,
        announced  = announced,
    )


# ── Origin Change Tests ────────────────────────────────────

def test_no_alert_first_time(detector, alerts):
    """First time seeing a prefix — no history, no alert."""
    upd = make_update("1.2.3.0/24", origin_asn=13335)
    result = detector.inspect(upd)
    assert result is None
    assert len(alerts) == 0

def test_no_alert_same_origin(detector, store, alerts):
    """Same AS announcing same prefix repeatedly — no alert."""
    # Establish history
    for _ in range(10):
        store.record_prefix("1.2.3.0/24", 13335)

    upd = make_update("1.2.3.0/24", origin_asn=13335)
    result = detector.inspect(upd)
    assert result is None
    assert len(alerts) == 0

def test_alert_origin_change(detector, store, alerts):
    """
    Known prefix from AS13335 suddenly from AS99999.
    Should fire an ORIGIN_CHANGE alert.
    """
    # Establish strong history for AS13335
    for _ in range(20):
        store.record_prefix("1.2.3.0/24", 13335)

    # Now a different AS announces the same prefix
    upd = make_update("1.2.3.0/24", origin_asn=99999)
    result = detector.inspect(upd)

    assert result is not None
    assert result.attack_type  == "ORIGIN_CHANGE"
    assert result.legit_origin == 13335
    assert result.seen_origin  == 99999
    assert result.confidence   > 0.5
    assert len(alerts)         == 1

def test_confidence_increases_with_history(detector, store):
    """More history = higher confidence when hijack is detected."""
    # Small history
    for _ in range(3):
        store.record_prefix("1.2.3.0/24", 13335)
    upd = make_update("1.2.3.0/24", origin_asn=99999)
    result_low = detector.inspect(upd)

    # Reset
    store2 = TrustStore(str(store.db_path).replace(".db", "2.db"))
    detector2 = HijackDetector(store2)
    for _ in range(100):
        store2.record_prefix("1.2.3.0/24", 13335)
    upd2 = make_update("1.2.3.0/24", origin_asn=99999)
    result_high = detector2.inspect(upd2)

    if result_low and result_high:
        assert result_high.confidence >= result_low.confidence

def test_no_alert_low_confidence(detector, store, alerts):
    """
    If we've only seen a prefix once before, we're not
    confident enough to fire an alert.
    """
    store.record_prefix("1.2.3.0/24", 13335)   # seen only once
    upd = make_update("1.2.3.0/24", origin_asn=99999)
    result = detector.inspect(upd)
    assert result is None


# ── More Specific Tests ────────────────────────────────────

def test_more_specific_hijack_detected(detector, alerts):
    """
    /24 from AS13335 established, then /25 from AS99999.
    Should detect a MORE_SPECIFIC hijack.
    """
    # Establish the parent prefix
    parent = make_update("1.2.3.0/24", origin_asn=13335)
    detector.inspect(parent)

    # Attacker announces more specific from different AS
    specific = make_update("1.2.3.0/25", origin_asn=99999)
    result = detector.inspect(specific)

    assert result is not None
    assert result.attack_type  == "MORE_SPECIFIC"
    assert result.legit_origin == 13335
    assert result.seen_origin  == 99999

def test_legitimate_deaggregation_no_alert(detector, alerts):
    """
    Same AS announcing both /24 and /25 — legitimate
    traffic engineering, not a hijack.
    """
    parent = make_update("1.2.3.0/24", origin_asn=13335)
    detector.inspect(parent)

    specific = make_update("1.2.3.0/25", origin_asn=13335)
    result = detector.inspect(specific)

    assert result is None
    assert len(alerts) == 0

def test_more_specific_confidence(detector):
    """More specific the prefix, higher the confidence."""
    parent = make_update("1.2.3.0/24", origin_asn=13335)
    detector.inspect(parent)

    slash25 = make_update("1.2.3.0/25", origin_asn=99999)
    slash28 = make_update("1.2.3.0/28", origin_asn=99999)

    # Reset recent for clean test
    detector2 = HijackDetector(detector.store)
    parent2 = make_update("1.2.3.0/24", origin_asn=13335)
    detector2.inspect(parent2)
    result28 = detector2.inspect(slash28)

    detector3 = HijackDetector(detector.store)
    parent3 = make_update("1.2.3.0/24", origin_asn=13335)
    detector3.inspect(parent3)
    result25 = detector3.inspect(slash25)

    if result25 and result28:
        assert result28.confidence >= result25.confidence


# ── Severity Tests ─────────────────────────────────────────

def test_severity_critical(store):
    """High confidence alert should be CRITICAL severity."""
    alert = HijackAlert(
        prefix="1.2.3.0/24", legit_origin=13335,
        seen_origin=99999, peer_asn=1299,
        timestamp=time.time(), confidence=0.95,
        attack_type="ORIGIN_CHANGE",
    )
    assert alert.severity == "CRITICAL"

def test_severity_high(store):
    alert = HijackAlert(
        prefix="1.2.3.0/24", legit_origin=13335,
        seen_origin=99999, peer_asn=1299,
        timestamp=time.time(), confidence=0.70,
        attack_type="ORIGIN_CHANGE",
    )
    assert alert.severity == "HIGH"

def test_severity_medium(store):
    alert = HijackAlert(
        prefix="1.2.3.0/24", legit_origin=13335,
        seen_origin=99999, peer_asn=1299,
        timestamp=time.time(), confidence=0.55,
        attack_type="ORIGIN_CHANGE",
    )
    assert alert.severity == "MEDIUM"


# ── Withdrawal Tests ───────────────────────────────────────

def test_withdrawal_clears_recent(detector, alerts):
    """
    After a withdrawal, the prefix should be cleared from
    recent announcements so it doesn't trigger false positives.
    """
    # Announce then withdraw
    upd = make_update("1.2.3.0/24", origin_asn=13335)
    detector.inspect(upd)
    assert "1.2.3.0/24" in detector._recent

    withdrawal = make_update("1.2.3.0/24", origin_asn=13335,
                              announced=False)
    detector.inspect(withdrawal)
    assert "1.2.3.0/24" not in detector._recent


# ── Stats Tests ────────────────────────────────────────────

def test_stats_track_alerts(detector, store, alerts):
    """Alert count should increment correctly."""
    for _ in range(20):
        store.record_prefix("1.2.3.0/24", 13335)
    detector.inspect(make_update("1.2.3.0/24", origin_asn=99999))

    s = detector.stats()
    assert s["alerts_fired"] == 1