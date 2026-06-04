# btmir/trust/engine.py

import math
from typing import List
from btmir.trust.models import BGPUpdate, TrustScore


# ── Weights ────────────────────────────────────────────────
# These three must always add up to 1.0
ALPHA = 0.30   # weight for WB (security evaluation)
BETA  = 0.40   # weight for WD (direct trust)
GAMMA = 0.30   # weight for WR (indirect recommendation)

# An AS scoring below this is isolated — routes rejected
TRUST_THRESHOLD = 0.40

# An AS scoring below this on WB alone fails the security
# gate before we even compute WD and WR
SECURITY_GATE = 0.35

# Controls how fast old interactions lose relevance.
# Higher value = past behavior forgotten faster.
DECAY_RATE = 0.05


# ── Time Decay ─────────────────────────────────────────────
def apply_decay(value: float, age_in_epochs: int) -> float:
    """
    Recent interactions matter more than old ones.
    An interaction from 10 epochs ago is worth less
    than one from yesterday.

    Uses exponential decay: value * e^(-rate * age)
    """
    return value * math.exp(-DECAY_RATE * age_in_epochs)


# ── WB: Security Evaluation ────────────────────────────────
def compute_WB(rpki_valid: bool,
               path_anomaly_score: float,
               is_transit: bool = False) -> float:
    """
    Evaluates the security posture of an AS.

    For origin ASes:
        rpki_valid        : does this AS have a valid ROA?
        path_anomaly_score: 0.0 = clean path, 1.0 = suspicious

    For transit ASes:
        RPKI does not apply — they don't originate prefixes.
        WB is based purely on path anomaly behavior.

    Returns WB in range [0.0, 1.0]
    """
    if is_transit:
        # Transit AS — RPKI irrelevant
        # Give neutral base score, penalize only for anomalies
        anomaly_score = 1.0 - path_anomaly_score
        wb = 0.50 + (0.45 * anomaly_score)
        return round(max(0.0, min(1.0, wb)), 4)

    # Origin AS — full RPKI + anomaly evaluation
    rpki_score    = 1.0 if rpki_valid else 0.0
    anomaly_score = 1.0 - path_anomaly_score
    wb = (0.6 * rpki_score) + (0.4 * anomaly_score)
    return round(max(0.0, min(1.0, wb)), 4)

# ── WD: Direct Trust ───────────────────────────────────────
def compute_wd(interaction_history: List[dict]) -> float:
    """
    Computes trust based on our own history with this AS.

    interaction_history: list of past interactions, each a dict:
        {
            "success": True or False,
            "age":     how many epochs ago this happened
        }

    Returns WD in range [0.0, 1.0]
    If no history exists, returns 0.5 (neutral — we don't
    know this AS yet, neither trust nor distrust)
    """
    if not interaction_history:
        return 0.5

    weighted_successes = 0.0
    weighted_total     = 0.0

    for interaction in interaction_history:
        success = 1.0 if interaction["success"] else 0.0
        age     = interaction["age"]
        weight  = apply_decay(1.0, age)

        weighted_successes += weight * success
        weighted_total     += weight

    if weighted_total == 0:
        return 0.5

    wd = weighted_successes / weighted_total
    return round(wd, 4)


# ── WR: Indirect Recommendation ────────────────────────────
def compute_wr(recommendations: List[dict]) -> float:
    """
    Computes trust based on what other ASes say about this AS.

    Uses trust-weighted sampling to resist collusion attacks.
    Higher trust recommenders are more likely to be sampled,
    so a large group of low-trust malicious ASes cannot
    reliably dominate the result even by volume.

    Returns WR in range [0.0, 1.0]
    """
    import random

    if not recommendations:
        return 0.5

    # Build sampling weights from recommender trust scores
    # A recommender with trust 0.9 is 18x more likely to be
    # sampled than one with trust 0.05
    trusts = [rec["recommender_trust"] for rec in recommendations]
    total  = sum(trusts)
    if total == 0:
        return 0.5

    # Normalize to get sampling probabilities
    probabilities = [t / total for t in trusts]

    # Sample half the pool using trust-weighted probabilities
    sample_size = max(1, len(recommendations) // 2)
    indices = random.choices(
        range(len(recommendations)),
        weights=probabilities,
        k=sample_size,
    )
    sample = [recommendations[i] for i in indices]

    # Now compute weighted average of sampled recommendations
    weighted_scores = 0.0
    weighted_total  = 0.0

    for rec in sample:
        score             = rec["score"]
        recommender_trust = rec["recommender_trust"]
        weighted_scores  += recommender_trust * score
        weighted_total   += recommender_trust

    if weighted_total == 0:
        return 0.5

    wr = weighted_scores / weighted_total
    return round(wr, 4)


# ── Path Anomaly Detection ─────────────────────────────────
def check_path_anomaly(as_path: List[int]) -> float:
    """
    Looks for suspicious patterns in the AS path.
    Returns anomaly score: 0.0 = clean, 1.0 = very suspicious.
    """
    if not as_path:
        return 1.0

    anomaly = 0.0

    # Check for loops — same AS appearing more than once
    if len(as_path) != len(set(as_path)):
        anomaly += 0.7

    # Check for unusually long paths
    if len(as_path) > 10:
        extra_hops = len(as_path) - 10
        anomaly += min(0.3, extra_hops * 0.05)

    return round(min(1.0, anomaly), 4)


# ── Composite Trust ────────────────────────────────────────
def compute_trust(
    update:              BGPUpdate,
    rpki_valid:          bool,
    interaction_history: List[dict],
    recommendations:     List[dict],
    is_transit:          bool = False,
) -> TrustScore:
    """
    The main function of the trust engine.
    """
    # Step 1: check path anomaly
    anomaly_score = check_path_anomaly(update.as_path)

    # Step 2: compute WB — pass is_transit flag
    wb = compute_WB(rpki_valid, anomaly_score, is_transit)

    # Step 3: security gate
    if wb < SECURITY_GATE:
        return TrustScore(
            asn        = update.origin_asn,
            wb         = wb,
            wd         = 0.0,
            wr         = 0.0,
            final      = 0.0,
            is_isolated = True,
            reason     = f"Failed security gate: WB={wb} below {SECURITY_GATE}",
        )

    # Step 4: compute WD and WR
    wd = compute_wd(interaction_history)
    wr = compute_wr(recommendations)

    # Step 5: composite trust score
    final = round(
        (ALPHA * wb) + (BETA * wd) + (GAMMA * wr),
        4
    )

    # Step 6: decision
    is_isolated = final <= TRUST_THRESHOLD
    reason = (
        f"Isolated: T={final} below threshold {TRUST_THRESHOLD}"
        if is_isolated else
        f"Trusted: T={final}"
    )

    return TrustScore(
        asn        = update.origin_asn,
        wb         = wb,
        wd         = wd,
        wr         = wr,
        final      = final,
        is_isolated = is_isolated,
        reason     = reason,
    )