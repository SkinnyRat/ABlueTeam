# Telemetry Pipeline — Fluent Bit (san → yi) + Suricata/Zeek tuning

How sensor data gets from the range box to the blue box, and how the sensors are
trimmed to stay light on san's RAM. Companion to [IDS_monitoring.md](IDS_monitoring.md)
(the "what to collect" design) — this is the "how to move and tune it" build.

```
san (.1)                                        yi (.2)
┌───────────────────────────┐                   ┌──────────────────────────┐
│ Suricata → eve.json  ─┐    │                   │  Fluent Bit (receiver)    │
│ Zeek     → *.log (JSON)┤    │   forward/msgpack │   forward :24224          │
│                        ├─► Fluent Bit (agent) ──┼──► /data/suricata/eve.ndjson
│                        │   tail + disk-buffer   │   └► /data/zeek/zeek.ndjson │
└───────────────────────────┘    over wg0        │        ▲ AI/EDR layer tails │
                                                  └──────────────────────────┘
```

- **Agent on san** tails the sensor logs, parses each JSON line to a record,
  disk-buffers, and forwards over `wg0`. Config: [conf/fluent-bit/agent-san.conf](conf/fluent-bit/agent-san.conf).
- **Receiver on yi** listens on the wg address and writes clean NDJSON per source.
  Config: [conf/fluent-bit/receiver-yi.conf](conf/fluent-bit/receiver-yi.conf).
- Transport is **plaintext TCP inside WireGuard** — already encrypted/authenticated,
  so no TLS to layer on. The receiver binds to `10.13.0.2` only (never the LAN).

## Why Fluent Bit here

Lightest of the shipper options (C; ~10–40 MB on san even under load). Logs are
already JSON, so no Filebeat-style modules are needed. Normalization/enrichment is
done downstream in the Python AI layer, not in the pipeline — so Fluent Bit's
thinner transform story (vs Vector's VRL) doesn't cost us anything here.

---

## Install & run

**Internet must be reachable** (WAN plugged in) for the package install. Fluent Bit
has a `resolute`/26.04 build. All steps below need `sudo`.

### yi (.2) — receiver (run from the repo root)

```bash
curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
sudo mkdir -p /data/suricata /data/zeek
sudo chown -R "$USER":"$USER" /data        # so the AI layer can read/manage it
sudo cp conf/fluent-bit/receiver-yi.conf /etc/fluent-bit/fluent-bit.conf
sudo systemctl enable --now fluent-bit
# if ufw is active, let the agent reach the receiver over wg0:
sudo ufw allow in on wg0 to 10.13.0.2 port 24224 proto tcp
```

### san (.1) — agent (copy the repo's conf/ there first)

```bash
curl -fsSL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh
sudo mkdir -p /var/log/flb-buffer
sudo cp conf/fluent-bit/agent-san.conf /etc/fluent-bit/fluent-bit.conf
sudo cp conf/fluent-bit/parsers.conf   /etc/fluent-bit/parsers.conf
# adjust the Zeek `path` in the agent conf if your install logs outside /opt/zeek
sudo systemctl enable --now fluent-bit
```

If the install script balks at `resolute`, pin the repo to the previous LTS
(binary-compatible):

```bash
echo "deb https://packages.fluentbit.io/ubuntu/noble noble main" | sudo tee /etc/apt/sources.list.d/fluent-bit.list
curl -fsSL https://packages.fluentbit.io/fluentbit.key | sudo gpg --dearmor -o /usr/share/keyrings/fluentbit.gpg
sudo apt update && sudo apt install -y fluent-bit
```

### Verify end to end

```bash
# yi: records should be landing as clean NDJSON
tail -1 /data/suricata/eve.ndjson | jq .
tail -1 /data/zeek/zeek.ndjson   | jq '.log_path, ._path'
# san: agent healthy, bytes leaving
systemctl status fluent-bit --no-pager
```

(If `/data/*.ndjson` shows a `tag`/timestamp wrapper instead of bare JSON, the
`format plain` line in the receiver conf didn't take — check the Fluent Bit version.)

---

## Suricata tuning — rules & RAM

Full ET Open is ~45k rules; loading all of it is the main Suricata RAM cost
(pattern-matching tables). We allowlist only the lab-relevant groups, which drops
the loaded set to a few thousand rules.

**Rule trim** ([conf/suricata/disable.conf](conf/suricata/disable.conf) +
[conf/suricata/enable.conf](conf/suricata/enable.conf)):

```bash
sudo cp conf/suricata/disable.conf conf/suricata/enable.conf /etc/suricata/
sudo suricata-update                 # reads both; writes a trimmed suricata.rules
sudo suricatasc -c reload-rules 2>/dev/null || sudo systemctl restart suricata
```

- `disable.conf` turns everything off (`re:.`); `enable.conf` switches back on only
  WEB (web_server, web_specific_apps, web_client, sql, attack_response, user_agents,
  scan), AD (netbios, rpc, policy), and exploit. The named AD CVEs (EternalBlue,
  Zerologon, PrintNightmare, PetitPotam, SMBGhost) live in netbios/rpc/exploit.

**Engine/memory knobs** ([conf/suricata/suricata-lab.yaml](conf/suricata/suricata-lab.yaml)
— merge into `/etc/suricata/suricata.yaml`): `detect.profile: low`, one AF_PACKET
worker, lab-sized flow/stream memcaps, and app-layer parsers limited to the
protocols in play. Kerberoasting/AS-REP roasting are **not** signatured here — those
come from Zeek metadata (SPN TGS reqs, RC4 etype 23) per IDS_monitoring.md.

### Kube rules — the short answer

**Don't bother, and there's no RAM tradeoff to make.** ET Open has essentially no
Kubernetes signatures, so there is nothing to enable and nothing to weigh. kube-goat's
network-visible traffic is HTTP(S) to the API server / web apps — already covered by
the WEB groups. Real Kubernetes attack detection is **host/syscall-level**: run
**Falco** (or Tetragon) on the cluster node. Falco emits JSON, so it drops straight
into this same pipeline — add a `tail` input on the kube node's Falco log and a
`match falco → file` sink on yi, exactly like the Zeek/Suricata inputs.

---

## Zeek tuning — streamlining

Zeek has no rule-set RAM knob; footprint = node count × traffic × file analysis.
Levers, all in [conf/zeek/local.zeek](conf/zeek/local.zeek):

- `LogAscii::use_json = T` — uniform NDJSON out.
- `@unload frameworks/files/hash-all-files` — skip file hashing (CPU + RAM).
- Disable `Weird`/`DPD` noise streams.
- **Run single-node.** Cluster mode multiplies RAM for nothing at lab volumes — the
  biggest Zeek lever.

The web + AD protocol logs (conn, dns, http, ssl, smb_*, kerberos, ntlm, dce_rpc,
ldap, rdp) are on by default — nothing to add.

---

## Zeek boot start — survive the wg0 race

**Symptom:** after a reboot `zeekctl status` shows `crashed`, but `zeekctl deploy`
run by hand brings it straight to `running`. That rules out a policy bug (a broken
`local.zeek` would fail `deploy` too) — it's a **startup race**. Zeek sniffs `wg0`,
and on san `wg0` is brought up by `wg-quick@wg0`, which is itself ordered
`After=docker.service` (see [Wireguard.md](Wireguard.md)) and so comes up late. If
Zeek is started before `wg0` exists it can't open the capture interface and dies
instantly. By the time you log in and `deploy`, `wg0` is up, so it works.

Confirm the cause from the crash report:

```bash
sudo /opt/zeek/bin/zeekctl diag        # look for: problem with interface wg0 / No such device
```

**Fix:** start Zeek from a systemd unit ordered after the interface, with a guard
that waits for `wg0` to appear. Unit: [conf/zeek/zeek.service](conf/zeek/zeek.service).

```bash
sudo cp conf/zeek/zeek.service /etc/systemd/system/zeek.service
sudo systemctl daemon-reload
sudo systemctl enable --now zeek.service
```

**Self-heal net:** enable zeekctl's cron so a node that ever crashes is redeployed
within 5 min (append — don't clobber root's existing crontab):

```bash
( sudo crontab -l 2>/dev/null; echo '*/5 * * * * /opt/zeek/bin/zeekctl cron' ) | sudo crontab -
```

**Cleanup:** remove any older racing starter (an `@reboot` cron, an ad-hoc init
script, a prior unit) so it can't fire before `wg0` and re-trigger the crash:

```bash
sudo crontab -l 2>/dev/null | grep -i zeek
grep -rIl zeek /etc/cron* 2>/dev/null
```

---

## Interface placement (both sensors)

Point each sensor at the interface where the traffic actually flows on san:

| Traffic | Path on san | Watch interface | Both directions? |
|---|---|---|---|
| Web (DVWA/Juice, docker) | wg0 → range bridge (rng0) | `wg0` + `rng0` | yes — routed, real IPs |
| kube-goat | wg0 → kind bridge | `wg0` + kind bridge | yes — routed, real IPs |
| GOAD / AD | wg0 → **NAT** → host-only (vboxnet, 192.168.56.1) | the **host-only iface** | wg0 sees only attacker→san; watch vboxnet for replies |

GOAD is the exception: its replies are MASQUERADE'd (see [Wireguard.md](Wireguard.md)),
so on `wg0` you only cleanly see the attacker→target direction. To get both sides of
AD conversations (needed for stream reassembly and roasting detection), watch the
VirtualBox host-only interface. Web and kube are routed without NAT, so `wg0` sees
real source IPs both ways.

---

## RAM budget (trimmed), per machine

| Machine | Component | RAM |
|---|---|---|
| **san** (32 GB, shared with GOAD) | Suricata (trimmed rules, profile low) | ~300–450 MB |
| | Zeek (single node, no file hashing) | ~150–300 MB |
| | Fluent Bit agent | ~10–40 MB |
| | **sensor total** | **~0.5–0.8 GB** |
| **yi** (24 GB, not the tetris) | Fluent Bit receiver | ~50–150 MB |
| | NDJSON landing files | disk, not RAM |
| | AI/EDR layer (model via API) | ~100–300 MB |

Leave **~1 GB** on san for sensors; everything else is on yi.
