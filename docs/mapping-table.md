# Blog post -> Detection mapping

| SBC blog post | Attack scenario | Sigma rules | Framework reference | Status | False-positive test |
|---|---|---|---|---|---|
| [SS7 Location Disclosure](https://www.sbytec.com/vulnerabilities/ss7-explainer/) | MAP AnyTimeInterrogation from an untrusted GT | [`ss7-location-disclosure.yml`](../detections/sigma/ss7-location-disclosure.yml) | ATT&CK tactic: Reconnaissance. Technique ID pending verification | Live, CI-tested | 0 FP / 50 benign trusted-partner events |
| [IMSI Catchers](https://www.sbytec.com/vulnerabilities/imsi-catchers/) | Rogue cell seen in cell measurements (post 6, Part 8 indicators IND-01, 03, 04, 05, 06) | [`imsi-catcher-critical-indicator.yml`](../detections/sigma/imsi-catcher-critical-indicator.yml), [`imsi-catcher-weak-indicator-combo.yml`](../detections/sigma/imsi-catcher-weak-indicator-combo.yml) | GSMA MoTIF (FS.57) False Base Station entries. FiGHT ID pending verification | Live, CI-tested | 0 FP / 50 benign events across 7 look-alike variants |
| [SIM Swapping](https://www.sbytec.com/vulnerabilities/sim-swapping/) | SS7 technical path: MAP UpdateLocation and RegisterSS call forwarding from untrusted GTs (post 8, Part 3) | [`sim-swap-update-location-untrusted.yml`](../detections/sigma/sim-swap-update-location-untrusted.yml), [`sim-swap-register-ss-cfu-untrusted.yml`](../detections/sigma/sim-swap-register-ss-cfu-untrusted.yml), [`sim-swap-correlation.yml`](../detections/sigma/sim-swap-correlation.yml) | pending verification | Live, CI-tested | 0 FP / 50 benign events, including roamers who register and forward calls from trusted partners |
| [GTP Security](https://www.sbytec.com/vulnerabilities/gtp-security/) | GTPv2-C session abuse at the GRX/IPX border: Create Session impersonation (3a), Modify Bearer redirect (3b), bearer table exhaustion (3d) | [`gtp-session-op-untrusted-peer.yml`](../detections/sigma/gtp-session-op-untrusted-peer.yml), [`gtp-serving-network-mismatch.yml`](../detections/sigma/gtp-serving-network-mismatch.yml), [`gtp-bearer-exhaustion.yml`](../detections/sigma/gtp-bearer-exhaustion.yml) (+ base rule [`gtp-create-session-observed.yml`](../detections/sigma/gtp-create-session-observed.yml)) | GSMA FS.20 layers 2 and 3 as described in post 9. Technique ID pending verification | Live, CI-tested | 0 FP / 50 benign events, including a busy arrival wave and a retry storm |

## A note on framework IDs

Technique-level IDs are left out on purpose until each one is checked against
the source. An earlier version of this table listed MITRE FiGHT IDs that were
guesses, and they were removed rather than left to look authoritative. The
tags in the Sigma rules point to the SBC post indicator codes
(`sbc.indicator.ind-01` and so on), which are exact. To add a verified ID, open
the technique page on [fight.mitre.org](https://fight.mitre.org/) or in the GSMA
MoTIF document (FS.57), then add the ID to this table and to the rule's `tags`.

## IMSI catcher indicators covered

| Code | Indicator | Rule | Implemented |
|---|---|---|---|
| IND-01 | Fingerprint LAC (0, 1, 0xFFFD, 0xFFFE, 0xFFFF) | critical-indicator | yes |
| IND-03 | A5/0 on a Moroccan carrier cell | critical-indicator | yes |
| IND-04 | No AUTHENTICATION REQUEST | weak-indicator-combo | yes |
| IND-05 | Fewer than two neighbours | weak-indicator-combo | yes |
| IND-06 | Unknown cell with RSSI above -55 dBm | weak-indicator-combo | yes |
| IND-02 | LAC change without movement | needs the previous measurement of the same sensor | not yet |
| IND-07 | TA=0 with inconsistent RSSI | informational | not yet |
| IND-08 | LOCATION UPDATING REJECT cause 12 | needs a different event type | not yet |

## What a telecom SOC can and cannot see of a SIM swap

Post 8 models the technical SIM swap as nine events and marks one of them as
detectable. This pipeline covers the ones that cross the operator's signaling
layer, and the rest stay out of reach by design:

| Step in the post | Visible to the telecom SOC | Covered here |
|---|---|---|
| UPDATE-LOCATION from the attacker | yes, at the HLR or signaling firewall | yes, `sim-swap-update-location-untrusted` |
| CANCEL-LOCATION to the victim's real MSC | yes, but every legitimate roaming change produces one | no, a lone one is normal. Useful as context |
| REGISTER-SS call forwarding | yes, at the HLR | yes, `sim-swap-register-ss-cfu-untrusted` |
| Both on the same IMSI within a minute | yes, by correlating the two | yes, `sim-swap-correlation` |
| OTP request, interception, portal login, transfer | no, these happen at the bank and on the attacker's side | no. The post's defence here is out-of-band notification at the bank |

This is the honest version of "we detect SIM swaps": the signaling layer gives
the telecom a short warning window, and the fraud itself is only visible to the bank.

## What the GTP rules cover and what they do not

| Attack in post 9 | Covered | How |
|---|---|---|
| 3a Create Session impersonation | yes | peer without a roaming agreement, or a claimed serving network that is not the sender's own |
| 3b Modify Bearer redirect | yes, from an unknown peer | `gtp-session-op-untrusted-peer` |
| 3d Bearer table exhaustion | yes | threshold: 10 or more distinct IMSIs from one source in 60 s |
| 3c TEID spoofing in GTP-U | **no** | needs user-plane visibility. A signaling log at the border does not contain T-PDUs, and logging them all is rarely practical. The post's own mitigation (FS.37, per-TEID rate limiting) would reuse the threshold approach |
| Any of the above from a compromised **trusted** partner | only the flood | the post says the same of FS.20: a node that passes the trust checks can build messages that pass them. The flood is the one case where volume gives it away |

Two things the threshold taught while building it, both worth knowing for tuning:

- It counts **distinct IMSIs**, not requests. A subscriber retrying 12 times is one IMSI and stays silent.
- The margin to normal traffic is thin. In an early version, a legitimate partner's arrival wave of 8 subscribers plus a few unrelated sessions from the same IP crossed 10 within a minute. A real deployment sets the threshold per partner from its observed peak, not from a global number.

## How to read the "false-positive test" column

Each shipped rule set is tested against a benign traffic fixture generated by
the same script as the attack fixture, using the opposite `--scenario` flag
(see `generators/`). The test asserts the rules produce **zero** matches on
that set. This runs automatically in CI on every push
(`.github/workflows/ci.yml`, job `detection-tests`), so the number in this
table cannot silently go stale.

For IMSI catchers the benign set is built from the "Normal Cause" column of
the indicator table in post 6: isolated rural cells, new towers, roaming
partners using A5/0, congested cells, and two combinations of two weak
indicators. A rule that fires on any of them is too sensitive.

## Roadmap

All four planned scenarios are now built. Diameter, PFCP/N4 and SEPP/N32 are covered on
the blog but not yet built into the pipeline. They follow the same generator,
Sigma rule, CI-tested false-positive pattern as the two scenarios above.
