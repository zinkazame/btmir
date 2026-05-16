# btmir/tests/test_collector.py
# Tests for the RIS message parser.
# We don't test the live WebSocket connection here —
# that requires network access and is tested manually.
# What we test is the parser that converts raw RIS messages
# into BGPUpdate objects — the most logic-heavy part.

from btmir.collector.ris import parse_ris_message


def ris_msg(path, prefixes=None, withdrawals=None,
            peer_asn=1299, peer="72.52.92.213",
            timestamp=1715698800.0):
    """Helper to build a realistic RIS Live message."""
    data = {
        "type":      "UPDATE",
        "timestamp": timestamp,
        "peer_asn":  str(peer_asn),
        "peer":      peer,
        "path":      path,
    }
    if prefixes:
        data["announcements"] = [{"prefixes": prefixes}]
    if withdrawals:
        data["withdrawals"] = withdrawals

    return '{"type":"ris_message","data":' + \
           __import__('json').dumps(data) + '}'


# ── Parser Tests ───────────────────────────────────────────

def test_parse_valid_announcement():
    """A normal BGP announcement should parse correctly."""
    raw = ris_msg(
        path=[1299, 3356, 13335],
        prefixes=["103.21.244.0/22"],
    )
    updates = parse_ris_message(raw)
    assert len(updates) == 1
    u = updates[0]
    assert u.prefix     == "103.21.244.0/22"
    assert u.origin_asn == 13335
    assert u.peer_asn   == 1299
    assert u.announced  is True
    assert u.as_path    == [1299, 3356, 13335]

def test_parse_multiple_prefixes():
    """One BGP UPDATE can carry multiple prefixes."""
    raw = ris_msg(
        path=[1299, 13335],
        prefixes=["1.1.1.0/24", "1.0.0.0/24", "8.8.8.0/24"],
    )
    updates = parse_ris_message(raw)
    assert len(updates) == 3
    prefixes = [u.prefix for u in updates]
    assert "1.1.1.0/24" in prefixes
    assert "1.0.0.0/24" in prefixes
    assert "8.8.8.0/24" in prefixes

def test_parse_withdrawal():
    """A BGP withdrawal should have announced=False."""
    raw = ris_msg(
        path=[1299, 13335],
        withdrawals=["1.2.3.0/24"],
    )
    updates = parse_ris_message(raw)
    assert len(updates) == 1
    assert updates[0].announced  is False
    assert updates[0].prefix     == "1.2.3.0/24"

def test_parse_origin_is_last_in_path():
    """Origin AS should always be the last AS in the path."""
    raw = ris_msg(
        path=[64500, 64501, 64502, 13335],
        prefixes=["1.2.3.0/24"],
    )
    updates = parse_ris_message(raw)
    assert updates[0].origin_asn == 13335

def test_parse_timestamp():
    """Timestamp should be preserved from the message."""
    raw = ris_msg(
        path=[1299, 13335],
        prefixes=["1.2.3.0/24"],
        timestamp=1715698800.0,
    )
    updates = parse_ris_message(raw)
    assert updates[0].timestamp == 1715698800.0

def test_parse_peer_info():
    """Peer ASN and IP should be preserved."""
    raw = ris_msg(
        path=[1299, 13335],
        prefixes=["1.2.3.0/24"],
        peer_asn=1299,
        peer="72.52.92.213",
    )
    updates = parse_ris_message(raw)
    assert updates[0].peer_asn == 1299
    assert updates[0].peer_ip  == "72.52.92.213"

def test_parse_empty_path_returns_nothing():
    """A message with no AS path should be ignored."""
    raw = ris_msg(path=[], prefixes=["1.2.3.0/24"])
    updates = parse_ris_message(raw)
    assert updates == []

def test_parse_wrong_type_returns_nothing():
    """Non-UPDATE messages should be ignored."""
    raw = '{"type":"ris_message","data":{"type":"OPEN"}}'
    updates = parse_ris_message(raw)
    assert updates == []

def test_parse_non_ris_message_returns_nothing():
    """Messages that are not ris_message type are ignored."""
    raw = '{"type":"ris_subscribe_ok","data":{}}'
    updates = parse_ris_message(raw)
    assert updates == []

def test_parse_invalid_json_returns_nothing():
    """Malformed JSON should not crash the system."""
    updates = parse_ris_message("this is not json {{{")
    assert updates == []

def test_parse_as_set_in_path():
    """
    BGP paths sometimes contain AS sets like [64500, [64501, 64502], 13335].
    We should handle these without crashing.
    """
    import json
    data = {
        "type":      "UPDATE",
        "timestamp": 1715698800.0,
        "peer_asn":  "1299",
        "peer":      "72.52.92.213",
        "path":      [64500, [64501, 64502], 13335],
        "announcements": [{"prefixes": ["1.2.3.0/24"]}],
    }
    raw = json.dumps({"type": "ris_message", "data": data})
    updates = parse_ris_message(raw)
    assert len(updates) == 1
    assert updates[0].origin_asn == 13335

def test_parse_both_announcements_and_withdrawals():
    """A message can contain both announcements and withdrawals."""
    import json
    data = {
        "type":         "UPDATE",
        "timestamp":    1715698800.0,
        "peer_asn":     "1299",
        "peer":         "72.52.92.213",
        "path":         [1299, 13335],
        "announcements": [{"prefixes": ["1.2.3.0/24"]}],
        "withdrawals":  ["5.6.7.0/24"],
    }
    raw = json.dumps({"type": "ris_message", "data": data})
    updates = parse_ris_message(raw)
    assert len(updates) == 2
    announced  = [u for u in updates if u.announced]
    withdrawn  = [u for u in updates if not u.announced]
    assert len(announced) == 1
    assert len(withdrawn) == 1