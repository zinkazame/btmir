# btmir/tests/test_rpki.py
#
# Tests for RPKI validator.
# We test caching, cache expiry, and the rpki_valid_fraction
# helper without making real network calls.

import time
import pytest
from btmir.security.rpki import RPKIValidator, RPKIResult


@pytest.fixture
def validator():
    return RPKIValidator(cache_ttl=3600)


def make_result(asn, prefix, valid):
    return RPKIResult(
        asn=asn, prefix=prefix,
        valid=valid, reason="test",
    )


# ── Cache Tests ────────────────────────────────────────────

def test_get_cached_miss(validator):
    """Unknown prefix returns None from cache."""
    result = validator.get_cached(13335, "1.2.3.0/24")
    assert result is None

def test_get_cached_hit(validator):
    """Cached result should be returned."""
    r = make_result(13335, "1.2.3.0/24", True)
    validator._cache[(13335, "1.2.3.0/24")] = (r, time.time())
    result = validator.get_cached(13335, "1.2.3.0/24")
    assert result is not None
    assert result.valid is True

def test_cache_expired(validator):
    """Expired cache entry should return None."""
    r   = make_result(13335, "1.2.3.0/24", True)
    old = time.time() - 7200   # 2 hours ago
    validator._cache[(13335, "1.2.3.0/24")] = (r, old)
    result = validator.get_cached(13335, "1.2.3.0/24")
    assert result is None

def test_clear_expired(validator):
    """clear_expired should remove stale entries."""
    r1  = make_result(13335, "1.2.3.0/24", True)
    r2  = make_result(15169, "8.8.8.0/24", True)
    old = time.time() - 7200
    now = time.time()
    validator._cache[(13335, "1.2.3.0/24")] = (r1, old)
    validator._cache[(15169, "8.8.8.0/24")] = (r2, now)
    validator.clear_expired()
    assert validator.cache_size() == 1
    assert validator.get_cached(15169, "8.8.8.0/24") \
           is not None

def test_cache_size(validator):
    """cache_size should reflect number of entries."""
    assert validator.cache_size() == 0
    r = make_result(13335, "1.2.3.0/24", True)
    validator._cache[(13335, "1.2.3.0/24")] = \
        (r, time.time())
    assert validator.cache_size() == 1


# ── rpki_valid_fraction Tests ──────────────────────────────

def test_fraction_unknown_as(validator):
    """AS with no cached results returns neutral 0.5."""
    assert validator.rpki_valid_fraction(13335) == 0.5

def test_fraction_all_valid(validator):
    """AS with all valid prefixes returns 1.0."""
    now = time.time()
    for i in range(5):
        r = make_result(13335, f"1.2.{i}.0/24", True)
        validator._cache[(13335, f"1.2.{i}.0/24")] = \
            (r, now)
    assert validator.rpki_valid_fraction(13335) == 1.0

def test_fraction_all_invalid(validator):
    """AS with all invalid prefixes returns 0.0."""
    now = time.time()
    for i in range(5):
        r = make_result(99999, f"1.2.{i}.0/24", False)
        validator._cache[(99999, f"1.2.{i}.0/24")] = \
            (r, now)
    assert validator.rpki_valid_fraction(99999) == 0.0

def test_fraction_mixed(validator):
    """AS with mixed validity returns correct fraction."""
    now = time.time()
    # 3 valid, 1 invalid
    for i in range(3):
        r = make_result(13335, f"1.2.{i}.0/24", True)
        validator._cache[(13335, f"1.2.{i}.0/24")] = \
            (r, now)
    r = make_result(13335, "1.2.99.0/24", False)
    validator._cache[(13335, "1.2.99.0/24")] = (r, now)
    fraction = validator.rpki_valid_fraction(13335)
    assert fraction == 0.75

def test_fraction_ignores_other_asns(validator):
    """Fraction should only count prefixes for that AS."""
    now = time.time()
    r1 = make_result(13335, "1.2.3.0/24", True)
    r2 = make_result(99999, "5.6.7.0/24", False)
    validator._cache[(13335, "1.2.3.0/24")] = (r1, now)
    validator._cache[(99999, "5.6.7.0/24")] = (r2, now)
    # AS13335 should be 1.0 regardless of AS99999
    assert validator.rpki_valid_fraction(13335) == 1.0
    assert validator.rpki_valid_fraction(99999) == 0.0


# ── RPKIResult Tests ───────────────────────────────────────

def test_result_valid(validator):
    r = make_result(13335, "1.2.3.0/24", True)
    assert r.valid  is True
    assert r.asn    == 13335
    assert r.prefix == "1.2.3.0/24"

def test_result_invalid(validator):
    r = make_result(99999, "1.2.3.0/24", False)
    assert r.valid is False

def test_result_repr(validator):
    r = make_result(13335, "1.2.3.0/24", True)
    assert "VALID" in repr(r)
    assert "13335" in repr(r)