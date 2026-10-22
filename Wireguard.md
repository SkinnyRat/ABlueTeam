# WireGuard overlay for the cyber range (yi / er / san)

## Topology

| Machine | Role | WG address | Notes |
|---|---|---|---|
| san | Range (7730U, 32GB) | 10.13.0.1/24 | WireGuard server, `wg0`, UDP 51820 |
| yi | Blue team (7840HS ES, 24GB) | 10.13.0.2/24 | Client |
| er | Red team (3600, 32GB, RTX 3050) | 10.13.0.3/24 | Client |

All three sit on the TP-Link Archer AX10 LAN (WAN unplugged during range runs). yi and er only ever talk to san's `wg0`; san routes into whichever scenario is up. Swapping scenarios never touches yi/er config.

Scenario subnets (one active at a time):

| Scenario | Subnet |
|---|---|
| kube-goat | 10.13.10.0/24 |
| GOAD / SCCM | 192.168.56.0/24 (left on its default, VirtualBox host-only; NATed, see below) |
| SAM / serverless stack | 10.13.30.0/24 |
| DVWA / OverTheWire | 10.13.40.0/24 |

## san (server), one-time setup

1. Install Docker Engine (not `apt install docker`, which is an unrelated package):
   ```bash
   curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker $USER   # log out/in after
   ```
2. Install WireGuard and generate keys:
   ```bash
   sudo apt install wireguard
   cd /etc/wireguard
   sudo sh -c 'umask 077; wg genkey | tee san.key | wg pubkey > san.pub'
   ```
3. Enable forwarding persistently:
   ```bash
   echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-wg.conf
   sudo sysctl --system
   ```
4. `/etc/wireguard/wg0.conf` (replace the key with the real contents of `san.key`; a leftover placeholder makes `wg-quick` fail with "Key is not the correct length"):
   ```ini
   [Interface]
   Address = 10.13.0.1/24
   ListenPort = 51820
   PrivateKey = <contents of san.key>
   PostUp   = iptables -I FORWARD -i wg0 -j ACCEPT; iptables -I FORWARD -o wg0 -j ACCEPT
   PostUp   = iptables -I DOCKER-USER -i wg0 -j ACCEPT; iptables -I DOCKER-USER -o wg0 -j ACCEPT
   PostUp   = iptables -t nat -A POSTROUTING -s 10.13.0.0/24 -d 192.168.56.0/24 -j MASQUERADE
   PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT
   PostDown = iptables -D DOCKER-USER -i wg0 -j ACCEPT; iptables -D DOCKER-USER -o wg0 -j ACCEPT
   PostDown = iptables -t nat -D POSTROUTING -s 10.13.0.0/24 -d 192.168.56.0/24 -j MASQUERADE

   [Peer]
   # yi
   PublicKey = <yi.pub contents>
   AllowedIPs = 10.13.0.2/32

   [Peer]
   # er
   PublicKey = <er.pub contents>
   AllowedIPs = 10.13.0.3/32
   ```
   - `DOCKER-USER` is a literal iptables chain name, not a user. Docker creates it at daemon start and runs it before its own forwarding rules; without these rules Docker's FORWARD DROP policy blocks routed traffic into its bridges.
   - The MASQUERADE is GOAD-only. GOAD VMs have a Vagrant NAT adapter holding their default route, so without it replies to 10.13.0.x leave the wrong way. Cost: GOAD targets see san (192.168.56.1) as the source. For other scenarios whose bridge is owned by san, route without NAT so the blue side sees real source IPs.
5. Make WireGuard start after Docker, or a reboot fails on the `DOCKER-USER` line ("No chain/target/match by that name") and `wg-quick` tears the interface down:
   ```bash
   sudo mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
   sudo tee /etc/systemd/system/wg-quick@wg0.service.d/override.conf <<'EOF'
   [Unit]
   After=docker.service
   Wants=docker.service
   EOF
   sudo systemctl daemon-reload
   ```
6. Firewall and start (match the subnet to your AX10 LAN):
   ```bash
   sudo ufw allow from 192.168.0.0/16 to any port 51820 proto udp
   sudo systemctl enable --now wg-quick@wg0
   ```
7. Reserve san's IP in the AX10 DHCP settings (bind to its MAC), or the clients' `Endpoint` silently breaks when the lease changes.

`active (exited)` in `systemctl status` is normal for `wg-quick`.

## yi and er (clients)

Run on each machine so private keys never leave it:

```bash
sudo apt install wireguard
cd /etc/wireguard
sudo sh -c 'umask 077; wg genkey | tee yi.key | wg pubkey > yi.pub'   # er.key / er.pub on er
sudo cat yi.pub    # copy this into san's [Peer] block
```

`/etc/wireguard/wg0.conf` (yi shown; on er use `Address = 10.13.0.3/24`):

```ini
[Interface]
Address = 10.13.0.2/24
PrivateKey = <contents of yi.key>

[Peer]
PublicKey = a1EZbZwwIinTW+cgb2V7iyaa6gYnhtiLyJXc4IPWh1M=
Endpoint = <san_lan_ip>:51820
AllowedIPs = 10.13.0.0/16, 192.168.56.0/24
PersistentKeepalive = 25
```

- `10.13.0.0/16` covers every current and future scenario slice, so this file is written once and never edited when san swaps targets.
- `192.168.56.0/24` is the GOAD exception. Make sure yi/er's own LAN is not 192.168.56.x.
- No `0.0.0.0/0`: only lab traffic uses the tunnel.

After adding both pubkeys to san's `wg0.conf`:
```bash
# san
sudo systemctl restart wg-quick@wg0
# yi / er
sudo systemctl enable --now wg-quick@wg0
sudo wg show                 # expect a recent "latest handshake"
ping -c2 10.13.0.1
```

## Per-scenario rules on san

- Docker scenarios: create the network with a fixed subnet and bridge name so nothing needs guessing:
  `docker network create --subnet 10.13.40.0/24 --opt com.docker.network.bridge.name=rng0 range`
- libvirt: define the network with `<forward mode='route'/>` and `<ip address='10.13.20.1' netmask='255.255.255.0'/>`.
- kube-goat: create the `kind` Docker network with `10.13.10.0/24` before `kind create cluster`; reach services via node IP + NodePort (pod IPs are not routable from outside).
- Targets must use san's bridge IP (`10.13.x.1`) as their default gateway, or replies take the wrong path and it looks like a firewall problem.
- Static slices need no per-run scripts; the rules live in `wg0.conf` and survive reboots.

## What works from yi/er

Direct nmap/ssh/rdp to targets (e.g. 10.13.x.y, or GOAD at 192.168.56.10-12). It is routed L3, so no broadcast/L2 attacks (Responder, ARP scans, mDNS) reach the targets; run those from a box on san's bridge. Use `nmap -Pn` against Windows hosts.

## Verification and troubleshooting

```bash
# san
sudo wg show
sysctl net.ipv4.ip_forward                      # must be 1
sudo iptables -t nat -S POSTROUTING | grep 192.168.56
sudo iptables -S DOCKER-USER | grep wg0
# yi/er
ip route get 192.168.56.10                      # must say dev wg0
sudo wg show                                    # handshake + received bytes > 0
```

| Symptom | Cause |
|---|---|
| `wg-quick` fails with "Key is not the correct length" | Placeholder still in `PrivateKey` |
| `wg-quick` fails after reboot, "No chain/target/match" | `wg-quick` started before Docker; fix the systemd drop-in |
| yi shows sent bytes, 0 received, no handshake | Wrong `Endpoint` IP (what happened here), ufw subnet mismatch, AP/client isolation, or mismatched pubkeys |
| Handshake OK but ports filtered | Check `ip route get` on yi, then tcpdump on `wg0` and the scenario bridge on san to see where packets stop |
| nmap "host up" with `-Pn` | Meaningless; `-Pn` assumes up. Judge by port results |


## Status

san and yi are working. er still needs its keypair, client config, and a `[Peer]` entry on san.
