# btmir/tests/test_api.py

import pytest
from fastapi.testclient import TestClient

from btmir.trust.store  import TrustStore
from btmir.trust.models import TrustScore
from btmir.api.server   import app, init, add_alert


@pytest.fixture
def store(tmp_path):
    s = TrustStore(str(tmp_path / "test.db"))
    init(s)
    return s

@pytest.fixture
def client(store):
    return TestClient(app)

def make_score(asn, final, isolated):
    return TrustScore(
        asn=asn, wb=0.8, wd=0.7, wr=0.6,
        final=final, is_isolated=isolated,
        reason="test",
    )


# ── Health ─────────────────────────────────────────────────

def test_root(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── Trust Endpoints ────────────────────────────────────────

def test_list_trust_empty(client):
    r = client.get("/trust")
    assert r.status_code == 200
    assert r.json() == []

def test_list_trust_returns_all(client, store):
    store.save_trust(make_score(13335, 0.85, False))
    store.save_trust(make_score(15169, 0.90, False))
    store.save_trust(make_score(99999, 0.10, True))
    r = client.get("/trust")
    assert r.status_code == 200
    assert len(r.json()) == 3

def test_list_trust_isolated_only(client, store):
    store.save_trust(make_score(13335, 0.85, False))
    store.save_trust(make_score(99999, 0.10, True))
    r = client.get("/trust?isolated_only=true")
    assert r.status_code == 200
    data = r.json()
    assert len(data) == 1
    assert data[0]["asn"] == 99999

def test_get_trust_known_as(client, store):
    store.save_trust(make_score(13335, 0.85, False))
    r = client.get("/trust/13335")
    assert r.status_code == 200
    data = r.json()
    assert data["asn"]     == 13335
    assert data["final"]   == 0.85
    assert data["verdict"] == "TRUSTED"

def test_get_trust_unknown_as(client):
    r = client.get("/trust/99999")
    assert r.status_code == 404

def test_get_trust_isolated_verdict(client, store):
    store.save_trust(make_score(99999, 0.10, True))
    r = client.get("/trust/99999")
    assert r.status_code == 200
    assert r.json()["verdict"] == "ISOLATED"

def test_get_isolated(client, store):
    store.save_trust(make_score(13335, 0.85, False))
    store.save_trust(make_score(99999, 0.10, True))
    store.save_trust(make_score(88888, 0.05, True))
    r = client.get("/isolated")
    assert r.status_code == 200
    isolated = r.json()
    assert 99999 in isolated
    assert 88888 in isolated
    assert 13335 not in isolated


# ── Prefix Endpoints ───────────────────────────────────────

def test_get_prefix_known(client, store):
    store.record_prefix("1.2.3.0/24", 13335)
    r = client.get("/prefix/1.2.3.0/24")
    assert r.status_code == 200
    data = r.json()
    assert data["prefix"] == "1.2.3.0/24"
    assert len(data["origins"]) == 1

def test_get_prefix_unknown(client):
    r = client.get("/prefix/9.9.9.0/24")
    assert r.status_code == 404


# ── Alert Endpoints ────────────────────────────────────────

def test_get_alerts_empty(client):
    r = client.get("/alerts")
    assert r.status_code == 200
    assert r.json() == []

def test_get_alerts_returns_alerts(client):
    add_alert({
        "prefix":       "1.2.3.0/24",
        "legit_origin": 13335,
        "seen_origin":  99999,
        "confidence":   0.95,
        "attack_type":  "ORIGIN_CHANGE",
        "severity":     "CRITICAL",
        "timestamp":    1715698800.0,
    })
    r = client.get("/alerts")
    assert r.status_code == 200
    assert len(r.json()) == 1


# ── Chain Endpoint ─────────────────────────────────────────

def test_chain_valid(client, store):
    store.save_trust(make_score(13335, 0.85, False))
    r = client.get("/chain")
    assert r.status_code == 200
    data = r.json()
    assert data["valid"]  is True
    assert data["status"] == "OK"
    assert data["length"] == 1


# ── Stats Endpoint ─────────────────────────────────────────

def test_stats(client, store):
    store.save_trust(make_score(13335, 0.85, False))
    store.save_trust(make_score(99999, 0.10, True))
    store.record_prefix("1.2.3.0/24", 13335)
    r = client.get("/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total_asns"]    == 2
    assert data["isolated_asns"] == 1
    assert data["chain_valid"]   is True