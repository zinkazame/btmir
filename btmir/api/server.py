# btmir/api/server.py
#
# REST API for BTMIR.
# Exposes trust scores, hijack alerts, and system stats
# over HTTP so the dashboard and external tools can query them.
#
# Run with:
#   uvicorn btmir.api.server:app --host 0.0.0.0 --port 8000

import time
from fastapi.responses import FileResponse
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from btmir.trust.store import TrustStore
from btmir.trust.models import TrustScore, BGPUpdate
from btmir.trust.engine import compute_trust

app = FastAPI(
    title       = "BTMIR — BGP Trust API",
    description = "Real-time trust scores for Autonomous Systems",
    version     = "1.0.0",
)

# Allow the dashboard (running on same machine) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

# Store is injected at startup — see main.py
_store: Optional[TrustStore] = None
_start_time = time.time()
_alerts: List[dict] = []   # in-memory alert log
_eval_epoch = 0  # epoch counter for /evaluate endpoint


def init(store: TrustStore):
    """Called by main.py to inject the store before serving."""
    global _store
    _store = store


def add_alert(alert: dict):
    """Called by hijack detector to log alerts."""
    _alerts.append(alert)
    # Keep only last 1000 alerts
    if len(_alerts) > 1000:
        _alerts.pop(0)


def get_store() -> TrustStore:
    if _store is None:
        raise RuntimeError("Store not initialised")
    return _store


# ── Response Models ────────────────────────────────────────

class TrustResponse(BaseModel):
    asn:         int
    wb:          float
    wd:          float
    wr:          float
    final:       float
    is_isolated: bool
    reason:      str
    verdict:     str   # "TRUSTED" or "ISOLATED"


class EvaluateRequest(BaseModel):
    asn:      int
    prefix:   str
    as_path:  List[int]
    peer_asn: int = 0


class LabAlertRequest(BaseModel):
    prefix:       str
    legit_origin: int
    seen_origin:  int
    confidence:   float
    attack_type:  str = "ORIGIN_CHANGE"


class AlertResponse(BaseModel):
    prefix:       str
    legit_origin: int
    seen_origin:  int
    confidence:   float
    attack_type:  str
    severity:     str
    timestamp:    float


class StatsResponse(BaseModel):
    total_asns:     int
    isolated_asns:  int
    known_prefixes: int
    chain_length:   int
    chain_valid:    bool
    uptime_seconds: float
    alert_count:    int


class ChainResponse(BaseModel):
    valid:        bool
    length:       int
    status:       str


# ── Helper ─────────────────────────────────────────────────

def _to_response(score: TrustScore) -> TrustResponse:
    return TrustResponse(
        asn         = score.asn,
        wb          = score.wb,
        wd          = score.wd,
        wr          = score.wr,
        final       = score.final,
        is_isolated = score.is_isolated,
        reason      = score.reason,
        verdict     = "ISOLATED" if score.is_isolated else "TRUSTED",
    )


# ── Endpoints ──────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "BTMIR BGP Trust API"}

@app.get("/dashboard", include_in_schema=False)
def dashboard():
    """Serve the live dashboard."""
    path = Path(__file__).parent.parent / "dashboard" / "index.html"
    return FileResponse(str(path))

@app.get("/trust", response_model=List[TrustResponse],
         tags=["Trust"])
def list_trust(isolated_only: bool = False):
    """
    List trust scores for all known ASes.
    Pass isolated_only=true to see only blocked ASes.
    """
    store  = get_store()
    scores = store.get_all_trust()
    if isolated_only:
        scores = [s for s in scores if s.is_isolated]
    return [_to_response(s) for s in scores]


@app.get("/trust/{asn}", response_model=TrustResponse,
         tags=["Trust"])
def get_trust(asn: int):
    """Get trust score for a specific AS by ASN."""
    store  = get_store()
    score  = store.get_trust(asn)
    if score is None:
        raise HTTPException(
            status_code = 404,
            detail      = f"AS{asn} not in trust store yet",
        )
    return _to_response(score)


@app.get("/isolated", response_model=List[int],
         tags=["Trust"])
def get_isolated():
    """List ASNs of all currently isolated ASes."""
    return get_store().get_isolated()

@app.post("/evaluate", response_model=TrustResponse, tags=["Trust"])
def evaluate(req: EvaluateRequest):
    """
    Submit a BGP update for trust evaluation.
    Used by ExaBGP handler and lab integration.
    """
    global _eval_epoch
    store = get_store()
    _eval_epoch += 1

    update = BGPUpdate(
        timestamp  = time.time(),
        peer_asn   = req.peer_asn,
        peer_ip    = "",
        prefix     = req.prefix,
        as_path    = req.as_path,
        origin_asn = req.asn,
        announced  = True,
    )

    # Record prefix for hijack history
    store.record_prefix(update.prefix, update.origin_asn)

    # Pull history and recommendations
    history = store.get_interactions(req.asn)
    all_scores = store.get_all_trust()
    recs = [
        {"score": s.final, "recommender_trust": s.final}
        for s in all_scores if s.asn != req.asn
    ]

    # Compute trust directly
    result = compute_trust(
        update              = update,
        rpki_valid          = False,
        interaction_history = history,
        recommendations     = recs,
    )

    # Save and record interaction
    store.save_trust(result)
    store.record_interaction(
        asn      = req.asn,
        peer_asn = req.peer_asn,
        success  = not result.is_isolated,
        epoch    = _eval_epoch,
    )

    return _to_response(result)


@app.post("/lab/alert", tags=["Lab"])
def lab_alert(req: LabAlertRequest):
    """
    Receive a hijack alert from the Kali VM lab.
    Pushes it into the dashboard's alert feed.
    """
    alert = {
        "prefix":       req.prefix,
        "legit_origin": req.legit_origin,
        "seen_origin":  req.seen_origin,
        "confidence":   req.confidence,
        "attack_type":  req.attack_type,
        "severity":     "CRITICAL" if req.confidence >= 0.85
                        else "HIGH" if req.confidence >= 0.60
                        else "MEDIUM",
        "timestamp":    time.time(),
    }
    add_alert(alert)
    return {"status": "ok", "alert_received": True}

@app.get("/paths", tags=["Graph"])
def get_paths():
    """
    Real AS edges extracted from actual BGP update paths.
    Used by the dashboard to draw real routing topology.
    """
    store = get_store()
    edges = store.get_as_edges()
    paths = store.get_recent_paths(limit=50)

    # Build node list from edges
    node_asns = set()
    for e in edges:
        node_asns.add(e['source'])
        node_asns.add(e['target'])

    # Get trust scores for these nodes
    nodes = []
    for asn in node_asns:
        rec = store.get_trust(asn)
        nodes.append({
            'asn':        asn,
            'trust':      rec.final      if rec else 0.5,
            'wb':         rec.wb         if rec else 0.5,
            'wd':         rec.wd         if rec else 0.5,
            'wr':         rec.wr         if rec else 0.5,
            'is_isolated': rec.is_isolated if rec else False,
            'verdict':    rec.verdict    if rec else 'UNKNOWN',
        })

    # Recent paths for display
    recent = []
    for p in paths[:20]:
        hops = [int(x) for x in p['as_path'].split(',') if x]
        recent.append({
            'prefix':  p['prefix'],
            'as_path': hops,
            'origin':  p['origin_asn'],
        })

    return {
        'nodes': nodes,
        'edges': edges,
        'recent_paths': recent,
    }

@app.get("/prefix/{prefix:path}", tags=["Prefix"])
def get_prefix(prefix: str):
    """
    Get historical origin ASes for a prefix.
    Useful for investigating hijack alerts.
    """
    store   = get_store()
    origins = store.get_prefix_origins(prefix)
    if not origins:
        raise HTTPException(
            status_code = 404,
            detail      = f"Prefix {prefix} not in history",
        )
    return {
        "prefix":  prefix,
        "origins": origins,
    }


@app.get("/alerts", response_model=List[AlertResponse],
         tags=["Alerts"])
def get_alerts(limit: int = 50):
    """Get recent hijack alerts."""
    return _alerts[-limit:]


@app.get("/chain", response_model=ChainResponse,
         tags=["Blockchain"])
def verify_chain():
    """
    Verify the integrity of the audit chain.
    If valid=false, the trust history has been tampered with.
    """
    store  = get_store()
    valid  = store.verify_chain()
    length = store.chain_length()
    return ChainResponse(
        valid  = valid,
        length = length,
        status = "OK" if valid else "TAMPERED",
    )


@app.get("/stats", response_model=StatsResponse,
         tags=["System"])
def get_stats():
    """Overall system statistics."""
    store = get_store()
    s     = store.stats()
    return StatsResponse(
        total_asns     = s["total_asns"],
        isolated_asns  = s["isolated_asns"],
        known_prefixes = s["known_prefixes"],
        chain_length   = s["chain_length"],
        chain_valid    = s["chain_valid"],
        uptime_seconds = time.time() - _start_time,
        alert_count    = len(_alerts),
    )