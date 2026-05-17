#!/usr/bin/env python3
import sys, json, math, time, sqlite3, logging

logging.basicConfig(
    filename='/tmp/btmir-lab/btmir.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)
log = logging.getLogger('btmir')

DB_PATH         = '/tmp/btmir-lab/btmir.db'
TRUST_THRESHOLD = 0.40
SECURITY_GATE   = 0.35
ALPHA           = 0.30
BETA            = 0.40
GAMMA           = 0.30
DECAY_RATE      = 0.05


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS trust_scores (
            asn         INTEGER PRIMARY KEY,
            final       REAL NOT NULL DEFAULT 0.5,
            wb          REAL NOT NULL DEFAULT 0.5,
            wd          REAL NOT NULL DEFAULT 0.5,
            wr          REAL NOT NULL DEFAULT 0.5,
            is_isolated INTEGER NOT NULL DEFAULT 0,
            updated_at  REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS interactions (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            asn     INTEGER NOT NULL,
            success INTEGER NOT NULL,
            epoch   INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS prefix_history (
            prefix     TEXT NOT NULL,
            origin_asn INTEGER NOT NULL,
            count      INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (prefix, origin_asn)
        );
        CREATE TABLE IF NOT EXISTS decisions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL NOT NULL,
            prefix      TEXT NOT NULL,
            origin_asn  INTEGER NOT NULL,
            decision    TEXT NOT NULL,
            trust_score REAL NOT NULL,
            reason      TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def get_interactions(asn):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT success, epoch,
               MAX(epoch) OVER () as max_epoch
        FROM interactions WHERE asn=?
        ORDER BY rowid DESC LIMIT 100
    """, (asn,)).fetchall()
    conn.close()
    return [{'success': r[0], 'age': r[2]-r[1]} for r in rows]


def save_interaction(asn, success, epoch):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO interactions (asn,success,epoch) VALUES (?,?,?)",
        (asn, int(success), epoch)
    )
    conn.commit()
    conn.close()


def save_trust(asn, wb, wd, wr, final, isolated):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO trust_scores
            (asn,final,wb,wd,wr,is_isolated,updated_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(asn) DO UPDATE SET
            final=excluded.final,
            wb=excluded.wb, wd=excluded.wd, wr=excluded.wr,
            is_isolated=excluded.is_isolated,
            updated_at=excluded.updated_at
    """, (asn, final, wb, wd, wr, int(isolated), time.time()))
    conn.commit()
    conn.close()


def get_prefix_origins(prefix):
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT origin_asn, count FROM prefix_history
        WHERE prefix=? ORDER BY count DESC
    """, (prefix,)).fetchall()
    conn.close()
    return rows


def record_prefix(prefix, asn):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO prefix_history (prefix,origin_asn,count)
        VALUES (?,?,1)
        ON CONFLICT(prefix,origin_asn) DO UPDATE SET
            count=count+1
    """, (prefix, asn))
    conn.commit()
    conn.close()


def log_decision(prefix, asn, decision, score, reason):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO decisions
            (timestamp,prefix,origin_asn,decision,trust_score,reason)
        VALUES (?,?,?,?,?,?)
    """, (time.time(), prefix, asn, decision, score, reason))
    conn.commit()
    conn.close()


def compute_wb(anomaly_score):
    return max(0.0, min(1.0, 0.4 * (1.0 - anomaly_score) + 0.6 * 0.5))


def compute_wd(interactions):
    if not interactions:
        return 0.5
    ws = sum(
        math.exp(-DECAY_RATE * r['age']) * r['success']
        for r in interactions
    )
    wt = sum(
        math.exp(-DECAY_RATE * r['age'])
        for r in interactions
    )
    return max(0.0, min(1.0, ws/wt)) if wt > 0 else 0.5


def path_anomaly(as_path):
    if not as_path:
        return 1.0
    score = 0.0
    if len(as_path) != len(set(as_path)):
        score += 0.7
    if len(as_path) > 10:
        score += min(0.3, (len(as_path)-10)*0.05)
    return min(1.0, score)


def check_hijack(prefix, origin_asn):
    origins = get_prefix_origins(prefix)
    if not origins:
        return False, 0.0
    dominant_asn, dominant_count = origins[0]
    if dominant_asn == origin_asn:
        return False, 0.0
    total = sum(c for _, c in origins)
    confidence = min(0.95, dominant_count / (total + 1))
    if confidence <= 0.50:
        return False, 0.0
    return True, confidence


epoch = 0

def evaluate(prefix, origin_asn, as_path):
    global epoch
    epoch += 1

    is_hijack, confidence = check_hijack(prefix, origin_asn)
    if is_hijack and confidence > 0.70:
        reason = f"HIJACK confidence={confidence:.0%}"
        log.warning(f"BLOCKED {prefix} AS{origin_asn}: {reason}")
        log_decision(prefix, origin_asn, "WITHDRAW", 0.0, reason)
        return False, 0.0, reason

    anomaly = path_anomaly(as_path)
    wb      = compute_wb(anomaly)

    if wb < SECURITY_GATE:
        reason = f"Security gate WB={wb:.3f}"
        log.warning(f"BLOCKED {prefix} AS{origin_asn}: {reason}")
        log_decision(prefix, origin_asn, "WITHDRAW", 0.0, reason)
        return False, 0.0, reason

    interactions = get_interactions(origin_asn)
    wd    = compute_wd(interactions)
    wr    = 0.5
    final = ALPHA*wb + BETA*wd + GAMMA*wr
    isolated = final <= TRUST_THRESHOLD

    save_trust(origin_asn, wb, wd, wr, final, isolated)
    save_interaction(origin_asn, not isolated, epoch)
    record_prefix(prefix, origin_asn)

    if isolated:
        reason = f"Low trust T={final:.3f}"
        log.warning(f"BLOCKED {prefix} AS{origin_asn}: {reason}")
        log_decision(prefix, origin_asn, "WITHDRAW", final, reason)
        return False, final, reason

    reason = f"Trusted T={final:.3f}"
    log.info(f"ALLOWED {prefix} AS{origin_asn}: {reason}")
    log_decision(prefix, origin_asn, "ANNOUNCE", final, reason)
    return True, final, reason


def send(cmd):
    sys.stdout.write(cmd + '\n')
    sys.stdout.flush()


def parse_update(line):
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return []

    if data.get('type') != 'update':
        return []

    neighbor  = data.get('neighbor', {})
    peer_asn  = int(neighbor.get('asn', {}).get('peer', 0))

    # ExaBGP 4.x puts update inside message.update
    msg    = data.get('message', {})
    update = msg.get('update', {})
    if not update:
        update = data.get('update', {})

    attribute   = update.get('attribute', {})
    as_path_raw = attribute.get('as-path', [])
    as_path = []
    for seg in as_path_raw:
        if isinstance(seg, list):
            as_path.extend(int(x) for x in seg
                           if str(x).isdigit())
        elif str(seg).isdigit():
            as_path.append(int(seg))

    results = []

    # ExaBGP 4.x format: announce.family.nexthop = [{nlri: prefix}]
    for family, nexthops in update.get('announce', {}).items():
        if not isinstance(nexthops, dict):
            continue
        for nh, entries in nexthops.items():
            entry_list = entries if isinstance(entries, list) else [entries]
            for entry in entry_list:
                # Entry is either {"nlri": "1.2.3.0/24"} or a string
                if isinstance(entry, dict):
                    prefix = entry.get('nlri', '')
                else:
                    prefix = str(entry)
                if not prefix:
                    continue
                results.append({
                    'prefix':     prefix,
                    'origin_asn': as_path[-1] if as_path else peer_asn,
                    'as_path':    as_path,
                    'announced':  True,
                    'next_hop':   nh,
                })

    for family, prefixes in update.get('withdraw', {}).items():
        prefix_list = prefixes if isinstance(prefixes, list) else [prefixes]
        for entry in prefix_list:
            if isinstance(entry, dict):
                prefix = entry.get('nlri', '')
            else:
                prefix = str(entry)
            if not prefix:
                continue
            results.append({
                'prefix':     prefix,
                'origin_asn': as_path[-1] if as_path else peer_asn,
                'as_path':    as_path,
                'announced':  False,
                'next_hop':   None,
            })

    return results


def main():
    init_db()
    log.info("BTMIR ExaBGP handler started")
    send('startup')

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        # ExaBGP sends 'error' as first line — ignore non-JSON
        if not line.startswith('{'):
            continue

        for upd in parse_update(line):
            prefix     = upd['prefix']
            origin_asn = upd['origin_asn']
            as_path    = upd['as_path']
            announced  = upd['announced']
            next_hop   = upd.get('next_hop', 'self')

            if not announced:
                send(f'withdraw route {prefix}')
                continue

            accept, score, reason = evaluate(
                prefix, origin_asn, as_path
            )

            if accept:
                send(f'announce route {prefix} '
                     f'next-hop {next_hop}')
            else:
                send(f'withdraw route {prefix}')


if __name__ == '__main__':
    main()