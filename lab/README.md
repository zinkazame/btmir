# BTMIR Virtual BGP Lab

Virtual BGP topology using Linux network namespaces,
FRRouting, and ExaBGP on Kali Linux.

## Topology

AS65001 (FRR) ←──→ AS65002 (FRR)
↑                  ↑
└────── AS65003 ───┘
(ExaBGP + BTMIR)

## One-Command Startup

After every VM reboot:

```bash
cd /root/btmir-lab
./start_lab.sh
```

## Requirements

```bash
apt install frr exabgp
pip3 install aiohttp --break-system-packages
```

## What It Does

1. Creates 3 network namespaces simulating real ASes
2. Starts FRR BGP daemons in AS65001 and AS65002
3. Starts ExaBGP + BTMIR trust engine in AS65003
4. BTMIR evaluates every BGP route announcement
5. Trusted routes → ANNOUNCE, Suspicious → WITHDRAW

## Testing Hijack Detection

```bash
# Establish legitimate prefix history
sqlite3 /tmp/btmir-lab/btmir.db \
  "INSERT OR REPLACE INTO prefix_history \
   (prefix,origin_asn,count) VALUES ('1.2.3.0/24',65001,50);"

# Simulate hijack from rogue AS
printf '{"type":"update","neighbor":{"address":{"local":"10.0.13.2",
"peer":"10.0.13.1"},"asn":{"local":65003,"peer":99999}},"message":
{"update":{"attribute":{"origin":"igp","as-path":[99999]},"announce":
{"ipv4 unicast":{"10.0.13.1":[{"nlri":"1.2.3.0/24"}]}}}}}\n' \
  | python3 /tmp/btmir-lab/btmir_exabgp.py

# Expected: withdraw route 1.2.3.0/24
```

## Monitoring

```bash
# Live trust decisions
tail -f /tmp/btmir-lab/btmir.log

# Decision history
sqlite3 /tmp/btmir-lab/btmir.db \
  "SELECT prefix,origin_asn,decision,reason
   FROM decisions ORDER BY id DESC LIMIT 20;"

# BGP session status
vtysh --vty_socket /tmp/btmir-lab/run/as65001 \
  -c "show bgp ipv4 unicast summary"
```