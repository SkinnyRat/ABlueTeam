# Weekly writeup — Scan campaign aggregation & evidence enrichment

**Week ending:** 2026-10-27
**Area:** `ABCD/ablueteam` (AI NDR layer), `scan_recon` detector
**Builds on:** the NDR layer added in `884ec8b` (rules detect, LLM triages)

---

## What we did

Reworked the scan detector so it reports **attack campaigns, not individual probes**, and
feeds the triage LLM structured context instead of a single raw record.

- **Per-source campaign aggregation.** The behavioural fan-out path no longer fires one
  finding per `(src, dst)` pair. It now tracks every probe from a source across *all*
  targets in the window and emits a single campaign finding, classified by shape:
  - `vertical` — many ports on one host (port sweep)
  - `horizontal` — many hosts touched on few ports (service/subnet sweep)
  - `block` — many ports *and* many hosts (broad block scan)
- **Evidence enrichment.** Findings carry a new structured `enrichment.campaign` block —
  target count + list, distinct ports, max ports on one host, total probes, the top
  targets with their port sets, and any corroborating ET SCAN signatures. Raw sensor
  records stay in `evidence` (capped at 3 samples); the derived aggregates live
  separately so `evidence` remains raw.
- **Triage now reads the enrichment.** `_build_user_prompt` includes the enrichment block,
  so every backend reasons over the whole sweep rather than one flow record.
- **Severity reflects breadth.** `block` shape, or a campaign corroborated by an ET SCAN
  signature, rates `high`; everything else `medium`.
- **Supporting plumbing.** New `SlidingWindow.current()` read-only accessor; `Finding`
  gained a generic `enrichment` field; ET SCAN pass-through alerts now also feed the
  campaign tracker for corroboration.

Files touched: `detectors/scan_recon.py`, `detectors/base.py`, `models.py`, `triage.py`,
`ABCD/README.md`.

---

## How good the results were

Validated against a live attack run on the range — `dirb`, `sqli`, `nmap`,
`smbclient -N`, `hydra` — processed through the `llamacpp` backend at `--min-severity
medium`. The run produced **44 findings, all from `scan_recon`**:

| Metric | Value |
|---|---|
| Total findings | 44 |
| Scan campaigns (aggregated) | 6 (1 `block`/high, 1 `horizontal`, 4 `vertical`) |
| ET SCAN pass-throughs (low) | 38 |
| Headline campaign | **62 hosts × 276 ports, 9,920 probes → one `high` finding** |

**The aggregation works.** The nmap block scan that would previously have produced
hundreds of per-pair findings collapsed into a single `high` finding with full
enrichment (top targets, port lists). That is exactly the intended outcome.

**Coverage of the attack chain: 1 of 5 tools.** Only nmap was meaningfully detected —
and it was caught thoroughly. The other four produced no findings, because no detector
covers them yet:

| Tool | Detected | Reason |
|---|---|---|
| nmap | ✅ thoroughly | scan campaigns + ET SCAN alerts |
| dirb | ❌ | no HTTP dir-bruteforce / 404-flood detector |
| sqli | ❌ | no web-attack / SQLi detector |
| smbclient -N | ❌ | no SMB-enum detector; the 445 alerts are nmap's SYN probes, not the session |
| hydra | ❌ | no auth-failure / brute-force / password-spray detector |

These are blind spots by design, not regressions — only `scan_recon` exists today among
the three detectors.

### Issues surfaced by the real data

- **ET corroboration never fired.** `corroborating_et_signatures` was empty on all 6
  campaigns even though the same nmap run produced both the Zeek flow bursts and the
  Suricata ET alerts. The campaign fires off dense Zeek `conn` bursts while the
  behavioural ET alerts land sparsely, minutes apart, so they rarely fall inside the same
  30 s correlation window. The feature passes synthetic tests but does not bridge the two
  real sensor streams as tuned.
- **Triage grounding.** The local model occasionally hallucinated (called the vboxnet
  gateway `192.168.56.1` a "known external attacker"; invented AD service ports that
  weren't in the evidence). Narrative quality is backend-dependent.
- **`192.168.56.1` double vantage.** Two campaigns attributed to the vboxnet gateway are
  almost certainly the same nmap seen from the GOAD-side interface, not a separate actor.
- **Debounce sentinel.** The per-source debounce uses `0.0` as the "never fired"
  sentinel. Correct for real epoch timestamps, but it silently suppresses synthetic
  sub-600 s timestamps (bit us during testing).

---

## Next steps

1. **Widen the ET-corroboration window** — retain ET SCAN signatures per source for the
   campaign lifetime (~600 s) instead of 30 s, so nmap campaigns attach their signatures
   and escalate to `high`.
2. **New detectors for the uncovered attacks** (the four misses above):
   - SMB enumeration — tree connects to `ADMIN$`/`C$`/`IPC$` (covers `smbclient`)
   - Brute-force / password-spray — auth-failure fan-out (covers `hydra`)
   - Web recon / injection — HTTP 404 floods, SQLi patterns (covers `dirb` / `sqli`)
3. **Enable `community_id`** in `suricata.yaml` for a clean dedup key that links
   Suricata ↔ Zeek records for the same flow (also helps #1).
4. **Zeek bidirectional on vboxnet** so AD *replies* are logged (needed for some
   detectors; also clears up the `192.168.56.1` double vantage).
5. **Triage grounding** — tighten the prompt / prefer the API backend for `high`
   findings; consider a post-check that the ports it cites appear in the evidence.
6. **Housekeeping** — make the debounce sentinel an explicit `None` check.
