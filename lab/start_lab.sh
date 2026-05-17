#!/bin/bash
# BTMIR Virtual BGP Lab — One-command startup
# Safe to run multiple times — skips already-configured steps

echo "[+] Starting BTMIR Virtual BGP Lab..."

# ── 1. Namespaces ──────────────────────────────────────────
for ns in as65001 as65002 as65003; do
    ip netns list | grep -q $ns || ip netns add $ns
done

# ── 2. Virtual links ───────────────────────────────────────
ip netns exec as65001 ip link show veth1-2 &>/dev/null || {
    ip link add veth1-2 type veth peer name veth2-1
    ip link set veth1-2 netns as65001
    ip link set veth2-1 netns as65002
}
ip netns exec as65001 ip link show veth1-3 &>/dev/null || {
    ip link add veth1-3 type veth peer name veth3-1
    ip link set veth1-3 netns as65001
    ip link set veth3-1 netns as65003
}
ip netns exec as65002 ip link show veth2-3 &>/dev/null || {
    ip link add veth2-3 type veth peer name veth3-2
    ip link set veth2-3 netns as65002
    ip link set veth3-2 netns as65003
}

# ── 3. IP addresses ────────────────────────────────────────
ip netns exec as65001 ip addr add 10.0.12.1/30 dev veth1-2 2>/dev/null || true
ip netns exec as65001 ip addr add 10.0.13.1/30 dev veth1-3 2>/dev/null || true
ip netns exec as65001 ip addr add 192.168.1.1/32 dev lo    2>/dev/null || true
ip netns exec as65002 ip addr add 10.0.12.2/30 dev veth2-1 2>/dev/null || true
ip netns exec as65002 ip addr add 10.0.23.1/30 dev veth2-3 2>/dev/null || true
ip netns exec as65002 ip addr add 192.168.2.1/32 dev lo    2>/dev/null || true
ip netns exec as65003 ip addr add 10.0.13.2/30 dev veth3-1 2>/dev/null || true
ip netns exec as65003 ip addr add 10.0.23.2/30 dev veth3-2 2>/dev/null || true
ip netns exec as65003 ip addr add 192.168.3.1/32 dev lo    2>/dev/null || true

# ── 4. Bring up interfaces ─────────────────────────────────
ip netns exec as65001 ip link set lo up
ip netns exec as65001 ip link set veth1-2 up
ip netns exec as65001 ip link set veth1-3 up
ip netns exec as65002 ip link set lo up
ip netns exec as65002 ip link set veth2-1 up
ip netns exec as65002 ip link set veth2-3 up
ip netns exec as65003 ip link set lo up
ip netns exec as65003 ip link set veth3-1 up
ip netns exec as65003 ip link set veth3-2 up

echo "[+] Network ready"

# ── 5. FRR configs ─────────────────────────────────────────
mkdir -p /tmp/btmir-lab/run/as65001
mkdir -p /tmp/btmir-lab/run/as65002
chmod 777 /tmp/btmir-lab/ 2>/dev/null || true
chown -R frr:frr /tmp/btmir-lab/run/

cat > /tmp/btmir-lab/frr-as65001.conf << 'FRREOF'
frr version 10.0.1
frr defaults traditional
hostname as65001
log syslog informational
router bgp 65001
 bgp router-id 192.168.1.1
 no bgp ebgp-requires-policy
 neighbor 10.0.12.2 remote-as 65002
 neighbor 10.0.12.2 description AS65002-legitimate
 neighbor 10.0.13.2 remote-as 65003
 neighbor 10.0.13.2 description AS65003-btmir
 address-family ipv4 unicast
  network 192.168.1.0/24
  neighbor 10.0.12.2 activate
  neighbor 10.0.13.2 activate
 exit-address-family
line vty
FRREOF

cat > /tmp/btmir-lab/frr-as65002.conf << 'FRREOF'
frr version 10.0.1
frr defaults traditional
hostname as65002
log syslog informational
router bgp 65002
 bgp router-id 192.168.2.1
 no bgp ebgp-requires-policy
 neighbor 10.0.12.1 remote-as 65001
 neighbor 10.0.12.1 description AS65001-legitimate
 neighbor 10.0.23.2 remote-as 65003
 neighbor 10.0.23.2 description AS65003-btmir
 address-family ipv4 unicast
  network 192.168.2.0/24
  neighbor 10.0.12.1 activate
  neighbor 10.0.23.2 activate
 exit-address-family
line vty
FRREOF

chown frr:frr /tmp/btmir-lab/frr-as65001.conf
chown frr:frr /tmp/btmir-lab/frr-as65002.conf

# ── 6. Start FRR ───────────────────────────────────────────
pkill bgpd 2>/dev/null; sleep 1

ip netns exec as65001 /usr/lib/frr/bgpd \
  --config_file /tmp/btmir-lab/frr-as65001.conf \
  --pid_file /tmp/btmir-lab/run/as65001/bgpd.pid \
  --vty_socket /tmp/btmir-lab/run/as65001 \
  --log file:/tmp/btmir-lab/run/as65001/bgpd.log \
  --no_zebra --daemon

sleep 1

ip netns exec as65002 /usr/lib/frr/bgpd \
  --config_file /tmp/btmir-lab/frr-as65002.conf \
  --pid_file /tmp/btmir-lab/run/as65002/bgpd.pid \
  --vty_socket /tmp/btmir-lab/run/as65002 \
  --log file:/tmp/btmir-lab/run/as65002/bgpd.log \
  --no_zebra --daemon

echo "[+] FRR started"

# ── 7. ExaBGP config ───────────────────────────────────────
cat > /tmp/btmir-lab/exabgp.conf << 'EXAEOF'
process btmir {
    run /usr/bin/python3 /tmp/btmir-lab/btmir_exabgp.py;
    encoder json;
}
neighbor 10.0.13.1 {
    router-id 10.0.13.2;
    local-address 10.0.13.2;
    local-as 65003;
    peer-as 65001;
    family { ipv4 unicast; }
    api {
        processes [ btmir ];
        receive { parsed true; update true; }
    }
}
neighbor 10.0.23.1 {
    router-id 10.0.13.2;
    local-address 10.0.23.2;
    local-as 65003;
    peer-as 65002;
    family { ipv4 unicast; }
    api {
        processes [ btmir ];
        receive { parsed true; update true; }
    }
}
EXAEOF

# ── 8. Named pipes ─────────────────────────────────────────
mkdir -p /run/exabgp
rm -f /run/exabgp/exabgp.in /run/exabgp/exabgp.out
mkfifo /run/exabgp/exabgp.in
mkfifo /run/exabgp/exabgp.out
chmod 666 /run/exabgp/exabgp.in /run/exabgp/exabgp.out

# ── 9. Log files ───────────────────────────────────────────
touch /tmp/btmir-lab/btmir.log
touch /tmp/btmir-lab/exabgp.log
chmod 666 /tmp/btmir-lab/btmir.log /tmp/btmir-lab/exabgp.log

# Copy BTMIR script from permanent location
cp /root/btmir-lab/btmir_exabgp.py /tmp/btmir-lab/btmir_exabgp.py
chmod +x /tmp/btmir-lab/btmir_exabgp.py

# ── 10. Start ExaBGP ───────────────────────────────────────
pkill -f "exabgp" 2>/dev/null; sleep 1

ip netns exec as65003 exabgp \
  /tmp/btmir-lab/exabgp.conf \
  > /tmp/btmir-lab/exabgp.log 2>&1 &

echo "[+] ExaBGP started (PID=$!)"
sleep 6

# ── 11. Status ─────────────────────────────────────────────
echo ""
echo "=== BGP Summary (AS65001) ==="
usermod -a -G frrvty root 2>/dev/null || true
vtysh --vty_socket /tmp/btmir-lab/run/as65001 \
  -c "show bgp ipv4 unicast summary" 2>/dev/null

echo ""
echo "=== BTMIR Log ==="
tail -5 /tmp/btmir-lab/btmir.log

echo ""
echo "[+] Lab ready!"
echo "    Decisions : sqlite3 /tmp/btmir-lab/btmir.db 'SELECT prefix,origin_asn,decision,reason FROM decisions ORDER BY id DESC LIMIT 10;'"
echo "    Monitor   : tail -f /tmp/btmir-lab/btmir.log"
echo "    Hijack sim: sqlite3 /tmp/btmir-lab/btmir.db \"INSERT OR REPLACE INTO prefix_history VALUES ('X.X.X.X/24',LEGIT_ASN,50,0,0);\""
