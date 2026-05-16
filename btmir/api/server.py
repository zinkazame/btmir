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

from btmir.trust.store  import TrustStore
from btmir.trust.models import TrustScore

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