# BTMIR — Blockchain-Based Trust Model for BGP Security

> Academic Design Project | Divyanshu Mehra   
> Based on: Yang et al. (2025), CMC Vol. 82(3), pp. 4821–4839

A **real, deployable BGP security system** that evaluates trust for Autonomous Systems using a composite trust model, detects prefix hijacks in real time, and enforces routing decisions via ExaBGP.

---

## What Problem Does This Solve?

The Border Gateway Protocol (BGP) routes the entire internet but assumes implicit trust between peers. This creates three critical vulnerabilities:

| Attack | Description | Real Example |
|--------|-------------|--------------|
| Prefix Hijacking | Rogue AS announces IP blocks it doesn't own | Pakistan Telecom vs YouTube (2008) |
| Route Leaks | AS re-advertises routes it shouldn't | Cloudflare outage (2019) |
| Collusion | Malicious ASes coordinate to manipulate trust | Ongoing threat |

Existing solutions like **RPKI** only validate prefix ownership — they say nothing about whether an AS *behaves* honestly over time. **BTMIR adds a behavioral trust layer** on top of RPKI.

---

## How It Works

Every BGP announcement is evaluated through:

T = α·WB + β·WD + γ·WR

| Component | Weight | Measures |
|-----------|--------|---------|
| WB — Security Evaluation | 30% | RPKI coverage, path anomalies |
| WD — Direct Trust | 40% | Historical interaction success rate with time decay |
| WR — Indirect Recommendation | 30% | Peer opinions, collusion-resistant sampling |

If **T ≤ 0.40** → AS is isolated, routes withdrawn.

---

## Architecture

RIPE RIS Live (real BGP stream)
│
▼
RISCollector          ← WebSocket client
│
▼
TrustEngine           ← T = α·WB + β·WD + γ·WR
├─ RPKIValidator     ← RIPE Stat API
├─ TrustStore        ← SQLite + SHA-256 audit chain
└─ HijackDetector    ← origin change + sub-prefix attacks
│
▼
ExaBGP Handler       ← ANNOUNCE / WITHDRAW decisions
│
▼
FRRouting Router     ← real BGP enforcement
│
▼
REST API + Dashboard ← http://localhost:8000

---

## Results

Running against real RIPE RIS Live data:

| Metric | Value |
|--------|-------|
| BGP updates processed | Live stream |
| Hijack detection | Origin change + sub-prefix |
| False positive rate | Near zero (RPKI-validated ASes) |
| Audit chain integrity | SHA-256 hash-chained, tamper-evident |
| Storage complexity | O(n) vs O(n²) traditional |

---

## Quick Start

### Requirements

```bash
pip install fastapi uvicorn websockets aiohttp click
```

### Run against real BGP data

```bash
# Watch Cloudflare's AS
python -m btmir.main --filter-asn 13335

# Open dashboard
# http://localhost:8000/dashboard

# Query trust scores
curl http://localhost:8000/trust
curl http://localhost:8000/trust/13335
curl http://localhost:8000/alerts
```

### Run tests

```bash
pytest btmir/tests/ -v
# 105 passed
```

---

## Virtual BGP Lab (Kali Linux)

A full virtual BGP topology with real routing software:

```bash
cd lab/
# Follow lab/README.md
./start_lab.sh
```

Topology: AS65001 (FRR) ↔ AS65002 (FRR) ↔ AS65003 (ExaBGP + BTMIR)

---

## Project Structure

btmir/
├── trust/
│   ├── models.py        # BGPUpdate, TrustScore data models
│   ├── engine.py        # WB / WD / WR trust computation
│   └── store.py         # SQLite store + SHA-256 audit chain
├── security/
│   ├── hijack.py        # Real-time hijack detection
│   └── rpki.py          # RPKI validation via RIPE Stat
├── collector/
│   └── ris.py           # RIPE RIS Live WebSocket collector
├── bgp/
│   └── exabgp.py        # ExaBGP route enforcement
├── api/
│   └── server.py        # FastAPI REST API
├── dashboard/
│   └── index.html       # Live D3 network graph dashboard
├── tests/               # 105 tests, 0 failures
└── main.py              # Main daemon
lab/
├── start_lab.sh         # One-command BGP lab startup
├── btmir_exabgp.py      # Trust engine for ExaBGP
└── README.md            # Lab setup guide

---

## API Reference

| Endpoint | Description |
|----------|-------------|
| `GET /trust` | All AS trust scores |
| `GET /trust/{asn}` | Trust score for specific AS |
| `GET /isolated` | Currently isolated ASes |
| `GET /alerts` | Recent hijack alerts |
| `GET /prefix/{prefix}` | Prefix origin history |
| `GET /chain` | Audit chain integrity check |
| `GET /stats` | System statistics |
| `GET /dashboard` | Live web dashboard |

---

## Reference

Yang, Q., Ma, L., Ullah, S., Tu, S., Alasmary, H., & Waqas, M. (2025).  
*Blockchain-Based Trust Model for Inter-Domain Routing.*  
Computers, Materials & Continua, 82(3), 4821–4839.  
DOI: 10.32604/cmc.2025.059497
