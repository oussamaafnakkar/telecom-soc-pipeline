# Blog post -> Detection mapping

| SBC blog post | Attack scenario | Sigma rule | MITRE FiGHT technique | Status | False-positive test |
|---|---|---|---|---|---|
| [SS7 Location Disclosure](https://www.sbytec.com/vulnerabilities/ss7-explainer/) | MAP AnyTimeInterrogation from untrusted GT | [`ss7-location-disclosure.yml`](../detections/sigma/ss7-location-disclosure.yml) | FIGHT T1579 - Location Tracking | Live, CI-tested | 0 FP / 50 benign trusted-partner events |
| [IMSI Catchers](https://www.sbytec.com/vulnerabilities/imsi-catchers/) | Paging/attach anomaly consistent with rogue BTS | *planned* | FIGHT T1592 (rogue base station, closest analogue) | Not started | - |
| [SIM Swapping](https://www.sbytec.com/vulnerabilities/sim-swapping/) | Anomalous SendAuthenticationInfo pattern | *planned* | FIGHT T1451 (SIM/subscriber identity abuse, closest analogue) | Not started | - |
| [GTP Security](https://www.sbytec.com/vulnerabilities/gtp-security/) | GTP-C signaling flood / DoS pattern | *planned* | FIGHT T1499-style DoS analogue | Not started | - |

*FiGHT technique IDs above are the closest published match at time of writing and will be
corrected against the current [MITRE FiGHT matrix](https://fight.mitre.org/) before each
rule ships - flagged here rather than asserted as final.*

## How to read the "false-positive test" column

Each shipped rule is tested against a benign traffic fixture generated from
the same script family as the attack fixture, using the opposite `--scenario`
flag (see `generators/`). The test asserts the rule produces **zero** matches
on that benign set. This is run automatically in CI on every push
(`.github/workflows/ci.yml`, job `detection-tests`), not just once
locally - so the number in this table can't silently go stale.

## Roadmap

Diameter, PFCP/N4, and SEPP/N32 scenarios are covered on the blog but not yet
built into the pipeline. They'll follow the same generator -> Sigma rule ->
CI-tested false-positive pattern as SS7 above.
