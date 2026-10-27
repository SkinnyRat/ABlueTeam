# WAF / Network Telemetry Lab — Design Notes

## Topology

```
attacker ──HTTP──> 10.13.0.1 ──> DVWA :8080
 (curl/dirb)        (observe +    Juice :3000
                     digest here)
                         │
                         └── ship digests ──> blue box (.2 or .3)
```

- `.1` = sole chokepoint / WireGuard gateway. All external red+blue machines reach
  `192.168.56.x` (GOAD) **only** via `10.13.0.1`.
- Pattern = **sensor (.1) → collector (blue box)**.
- Two separable jobs: **(A) generate telemetry on .1**, **(B) ship it to the blue box**.

---

## A — Generating telemetry on .1

Three legitimate families (mix & match):

1. **Inline reverse-proxy WAF — CRS-nginx** (nginx + ModSecurity v3 + OWASP CRS)
   - Textbook *WAF*: sees decrypted/parsed HTTP, CRS gives labelled detections (SQLi/LFI/scanner).
   - Can block or just observe (`SecRuleEngine DetectionOnly` for pure telemetry).
   - HTTP/L7 only.
2. **Passive sniffing / network IDS — Suricata and/or Zeek**
   - No proxy; binds to the interface, protocol-aware.
   - Suricata → `eve.json` (HTTP records + ET Open alerts).
   - Zeek → structured protocol logs (`http.log`, `kerberos.log`, `smb_*`, `dce_rpc`, …).
3. **App-level access logs** — cheap baseline, low signal (no attack labelling).

### Is CRS-nginx "best practice"?
Yes — it's **a** canonical WAF way, but proxying is one architecture, not the only legit one.

| Approach | Tool | Inline? | Attack labels? |
|---|---|---|---|
| Reverse-proxy WAF | nginx + ModSecurity + CRS | Yes | Yes (CRS) |
| Reverse-proxy WAF (Go) | Caddy + Coraza | Yes | Yes (CRS-compatible) |
| HAProxy + WAF | HAProxy + Coraza SPOA | Yes | Yes |
| Passive IDS | Suricata (eve.json) | No | Yes (ET rules) |
| Passive analysis | Zeek | No | Partial (behavioral) |
| SOC agent | Wazuh agent on any log | No | Yes (decoders) |

---

## B — Shipping digests to the blue box

Independent of generation. Most → least SOC-idiomatic:

1. **Wazuh agent → Wazuh manager** — best "SOC lab" story; decodes/correlates for you.
2. **Filebeat / Fluent Bit / Vector → Elasticsearch/OpenSearch** — classic ELK + Kibana.
3. **rsyslog / syslog-ng over TCP(TLS)** — dead simple centralization.
4. **Plain NDJSON over HTTPS** — most hands-on; you control the digest format.

### Define "digest" explicitly
- **Raw structured events** (one JSON record per request/alert) → aggregate on blue box. **Recommended.**
- **Pre-aggregated summaries** (per-60s counts by source/rule/app) → lighter wire, less detail. Overkill for a lab.

---

## Compatibility with later red-team vs GOAD (192.168.56.x)

GOAD is **Active Directory** (SMB, Kerberos, LDAP, DCERPC, NTLM, WinRM) — **not HTTP**.

| Option | Covers GOAD? | Why |
|---|---|---|
| Suricata on .1 wg iface | **Yes** | Protocol-aware IDS + ET rules on AD recon/attacks |
| Zeek on .1 wg iface | **Yes — best AD forensics** | `kerberos.log`, `smb_*`, `dce_rpc`, `ntlm`, `dns`, `ldap` |
| Wazuh (SIEM on blue box) | **Yes — via host agents** | Needs Wazuh agent + Sysmon on GOAD Windows hosts |
| ELK / Filebeat | Transport-neutral | Compatible if fed by Suricata/Zeek + Winlogbeat |
| CRS-nginx WAF | **No** | HTTP-only; blind to SMB/Kerberos/LDAP |

- Placement requirement: a wire sensor sees GOAD traffic **only because .1 is the gateway** — confirmed true here.
- Encrypted AD traffic (Kerberos tickets, SMB3, LDAPS) → metadata survives, payloads don't → pair **network (Zeek/Suricata) + host (Sysmon/Winlogbeat/Wazuh)**.

### Recommended dual-lab architecture
- **.1 = wg gateway** running **Zeek + Suricata** on the wg interface → covers web (10.13.0.x) *and* GOAD (192.168.56.x).
- **Keep CRS-nginx** in front of DVWA/Juice as a web-only L7 add-on (complementary).
- **Wazuh manager on blue box**; **Wazuh agent + Sysmon on each GOAD host**; Filebeat/Wazuh agent on .1 ships Zeek/Suricata/ModSecurity logs.

---

## Visibility: Suricata/Zeek WITHOUT CRS-nginx (web, DVWA/Juice)

Assumes DVWA/Juice are plain **HTTP** (their defaults). `.1` sees 100% of packets; question is what parses.

**Normal traffic — see almost everything**
- Zeek `http.log`: method, host, full URI, referrer, UA, status, MIME, body *sizes*; `files.log`.
- Suricata eve http events: same fields, parsed.

**Attacks — traffic visible, labelling weaker than a WAF**
- Recon fully visible: dirb/gobuster/nikto = flood of 404s + scanner UA; curl probes verbatim.
- URL/query injection (SQLi/XSS/LFI/RFI/cmd) visible in URI fields.
- Suricata labels *some* (ET Open) — thinner/noisier than CRS, more false negatives on obfuscation.
- Zeek labels **nothing** as "attack" by default — records richly, classification is downstream.

**Blind spots without the WAF**
- No CRS attack scoring/tagging (rule IDs, anomaly score, paranoia levels) — biggest loss.
- POST bodies (creds, form/JSON payloads): Suricata only if body-logging on; Zeek not by default.
- If TLS is ever added → visibility collapses to SNI/JA3/cert.

> Net: all web content + noisy attacks visible; you lose the normalized attack verdict.

---

## Visibility: Suricata/Zeek WITHOUT Wazuh (AD, GOAD)

Network view only (no host/Sysmon/event-log side).

**Normal traffic — strong metadata (Zeek)**
- `kerberos.log` (AS/TGS, principals, SPNs, enc types, options, errors), `smb_mapping`/`smb_files`,
  `dce_rpc`, `ntlm`, `dns`, `ldap` (newer Zeek), `rdp`, `conn`.
- Suricata: smb/krb5/dcerpc/dns/tls events.

**Attacks you CAN catch from the wire**
- Enumeration/recon: LDAP (BloodHound/SharpHound, ldapsearch over 389), DNS/SMB enum, SYSVOL/NETLOGON.
- Kerberoasting / AS-REP roasting: from metadata (SPN TGS reqs w/ RC4 etype 23; no-preauth accounts).
- Lateral movement: SMB tree connects (ADMIN$/C$/IPC$), PsExec/svcctl via dce_rpc.
- Relay / Pass-the-Hash: NTLM auth events (metadata).
- Known exploits via Suricata sigs: Zerologon, EternalBlue, PetitPotam, PrintNightmare, DCSync patterns.

**Blind spots without Wazuh (host-telemetry gap)**
- On-host, non-networked activity: LSASS/cred dumping (Mimikatz), local privesc, UAC bypass,
  token manipulation, process injection — invisible on the wire.
- No process / command-line / parent-child / user context — weak attribution.
- Encryption shrinks payloads: Kerberos bodies, SMB3-sealed RPC, LDAPS → metadata only.
- Forged tickets (Golden/Silver, Pass-the-Ticket): look valid on the wire → need host/log side.
- Rich auth outcomes (4624/4625/4768/4769 failure codes) live in Windows event logs.

> Net: wire-only gets recon, roasting, lateral movement, relay, known exploits; blind to on-host
> tradecraft, encrypted internals, and forged tickets — the Sysmon/event-log domain.
