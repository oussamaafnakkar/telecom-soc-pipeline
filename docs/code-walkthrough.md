# Code Walkthrough

This doc exists so the person reading the repo (including future you, in an
interview) can explain every file, not just point at a green CI badge.

## `generators/ss7_atsi_generator.py`

The only file that invents data.

- `make_event()` builds one dictionary representing a single **decoded** MAP
  signaling message - the fields a real probe/mediation layer would extract
  from the wire (opcode, source/destination Global Title, target subscriber,
  whether the source GT is a known interconnect partner).
- `generate_attack()` samples from `ROGUE_GTS` and sets `trusted=False`, with
  short gaps between events (0.2-2s) to mimic a burst of automated queries.
- `generate_benign()` samples from `TRUSTED_PARTNER_GTS` and sets
  `trusted=True`, with long gaps (5-60s) to mimic normal roaming-state checks.
- The *only* structural difference between the two is which GT list gets
  sampled and the timing - deliberately, because in the real attack that's
  exactly what distinguishes abuse from legitimate roaming traffic: origin and
  volume, not payload content.
- `--seed` makes output reproducible, which is what lets CI assert an exact
  expected count every run instead of a random one.

## `detections/sigma/ss7-location-disclosure.yml`

The actual detection logic, in the vendor-neutral Sigma format (converts to
Splunk SPL, QRadar AQL, or an Elastic query with the right tooling).

```yaml
detection:
    selection:
        signaling_protocol: 'MAP'
        map_opcode: 71
        src_gt_trusted_partner: false
    condition: selection
```

Reads as: match any event where all three fields in `selection` are true.
`condition: selection` fires whenever that block matches (no boolean logic
needed with a single block). `logsource` tells a converter what kind of data
this targets. `falsepositives` and `level` are not functional - they're
triage guidance an analyst reads before deciding whether to escalate.

## `detections/evaluate_ss7_rule.py`

A plain-Python re-implementation of the exact same `selection` block:

```python
def matches_rule(event: dict) -> bool:
    return (
        event.get("signaling_protocol") == "MAP"
        and event.get("map_opcode") == 71
        and event.get("src_gt_trusted_partner") is False
    )
```

This exists because the pipeline does not yet have an automated Sigma-to-
Elasticsearch converter wired in (a real, acknowledged limitation - see
`architecture.md`). This script is what CI actually runs: with
`--expect alerts` it fails unless every event in the file matched; with
`--expect silent` it fails if anything matched. That distinction is what
turns "a rule was written" into "the rule was proven to work."

## `ingest/logstash/conf.d/ss7.conf`

The production-shaped path, three stages:

- `input`: reads JSONL files from `/data/ss7/`.
- `filter`: re-implements the same detection condition a third time, in
  Logstash's own conditional syntax, and tags matching events with
  `sigma_match_ss7_location_disclosure` before indexing. Logstash has no
  `true`/`false` literals, so `src_gt_trusted_partner: false` in the Sigma rule
  becomes `![src_gt_trusted_partner]` here, meaning "this field is false".
- `output`: ships to Elasticsearch into a daily index (`ss7-signaling-YYYY.MM.DD`).

Yes - the detection logic now exists in three places (Sigma rule, Python
evaluator, Logstash filter). That's a real tradeoff, not an oversight, and
it's worth naming directly rather than glossing over it: it's the cost of not
yet having a converter that generates the Logstash/Elastic query directly
from the Sigma rule. Documented here and in `architecture.md` so it reads as
understood scope, not a gap nobody noticed.

## The IMSI catcher scenario

This scenario follows Part 8 of the SBC post on IMSI catchers. The SS7 scenario
judged a signaling message. This one judges a **cell measurement**: a snapshot
of the serving cell as a radio-monitoring sensor sees it. An IMSI catcher is a
fake cell, so the evidence is in how the cell looks, not in the core network.

### `generators/imsi_catcher_generator.py`

Each event has the fields of the post's `CellMeasurement`: `lac`, `cell_id`,
`rssi_dbm`, `encryption`, `auth_requested`, `neighbor_count`, `ta_value`. One
extra field, `cell_in_inventory`, stands in for the lookup a real pipeline does
against the operator's cell inventory.

Attack variants, each a different kind of rogue cell:

| Variant | What it does | Rule it must trip |
|---|---|---|
| `research_grade` | fingerprint LAC, A5/0, no auth, no neighbours (the sweep from the post) | critical |
| `stealth_combo` | believable LAC and cipher, but no auth, no neighbours, unknown loud cell | weak combo only |
| `downgrade_only` | forces A5/0 on a Moroccan carrier, nothing else unusual | critical |

Benign variants come from the "Normal Cause" column of the indicator table:
normal cells, isolated rural cells, new towers, roaming partners using A5/0,
congested cells, and two combinations of two weak indicators. They are the
false-positive test: real life produces each of these signals now and then.

Every event also has `fixture_label` and `fixture_variant`. These are test
labels so the verifier knows the right answer. The rules never read them.

### The two Sigma rules

- `imsi-catcher-critical-indicator.yml`: **IND-01** (LAC in 0, 1, 0xFFFD, 0xFFFE,
  0xFFFF) **or** **IND-03** (A5/0 on MCC 604, MNC 0, 1 or 2). One is enough.
  `condition: selection_fingerprint_lac or selection_null_cipher` says so.
- `imsi-catcher-weak-indicator-combo.yml`: **IND-04 and IND-05 and IND-06** on the
  same measurement: no authentication, fewer than two neighbours, a cell not in
  the inventory with a signal stronger than -55 dBm. `neighbor_count|lt: 2` and
  `rssi_dbm|gt: -55` are Sigma modifiers for "less than" and "greater than".

The post says the indicators are "individually weak but collectively
significant". The second rule is that sentence as code. Any one of its three
signals has a normal cause, and all three together do not.

One limit to know and to say out loud in an interview: a catcher showing only
two of the three weak indicators is not detected by this rule. The post makes
the same point, that commercial catchers are tuned to stay under thresholds.

### `detections/evaluate_imsi_rules.py`

The same logic in plain Python, with one addition: `EXPECTATIONS` says which
rules each attack variant must trip and which it must not. `stealth_combo` must
not trip the critical rule. If it did, the combination rule would not really be
tested. The output table shows events, alerts and per-rule counts for each variant.

### `ingest/logstash/conf.d/imsi.conf`

Same shape as the SS7 pipeline: read files, tag matches, index into
`imsi-catcher-*`. Two Logstash details worth knowing:

- Every fingerprint LAC is written out with `or`, because relying on a list of
  numbers in a Logstash condition is not safe.
- `![auth_requested]` means "this boolean is false", for the same reason as in
  the SS7 pipeline: Logstash has no `true` or `false` literals.

## `Dockerfile` and `scripts/`

One small image (`python:3.12-slim`, standard library only, non-root user)
carries three jobs, each a script in `scripts/`:

- `make_fixtures.sh` writes the attack and benign JSONL files for every scenario
  into `/data/<scenario>/`, one folder each, which Logstash reads.
- `run_detection_tests.sh` generates fresh events in a temp directory and checks,
  for every scenario, that the rules fire on all attack events and on no benign event.
- `verify_e2e.py` asks Elasticsearch the same questions for each scenario: total
  documents, alert-tagged documents, false positives (tagged but benign) and missed
  detections (untagged but attack). For IMSI catchers it also checks that every
  attack variant carries the rule it is meant to trip. Any wrong answer exits non-zero.

## `docker-compose.yml`

Six services (one Logstash container runs one pipeline per scenario):

- `fixtures` runs once, writes the event files into the `fixtures` volume and exits.
- `elasticsearch` stores events. Its healthcheck gates everything that depends on it.
- `logstash` starts only after Elasticsearch is healthy **and** `fixtures` has
  completed (`service_completed_successfully`), so the files exist before it
  starts reading. It mounts the same `fixtures` volume read-only.
- `kibana` is the UI.
- `tests` and `verify` sit behind the `test` profile, so `docker compose up`
  does not start them. `make test` and `make verify` run them on demand.

Containers talk over the private `soc-net` network by service name
(`http://elasticsearch:9200`). Only Elasticsearch and Kibana publish a port,
both on `127.0.0.1`.

## `Makefile`

A short name for each command, so local use and CI are identical:

| Command | What it does |
|---|---|
| `make test` | detection tests in Docker, no Elasticsearch |
| `make up` | build and start the stack |
| `make verify` | run the end-to-end assertions against the running stack |
| `make e2e` | `reset`, `up`, `verify` in order |
| `make logs`, `make ps` | debugging |
| `make down`, `make reset` | stop, or stop and delete all data |

## CI/CD (`.github/workflows/ci.yml`)

Three jobs run in sequence. Each `needs:` the previous one, so a failure stops
the chain early.

1. **`lint-and-validate`**: `ruff`, a check that every Sigma rule has its
   required fields, shell syntax checks, and `docker compose config`.
2. **`detection-tests`**: `make build` then `make test`. The same command you run locally.
3. **`end-to-end-elk-test`**: `make up` then `make verify`. On failure it prints
   `docker compose ps` and the service logs. `make reset` runs with `if: always()`
   so the runner is cleaned up either way.

Because CI calls the same `make` targets as a developer, a green local run means
a green CI run, and a red CI run can be reproduced on your own machine with the
same command.

To watch a run: push to GitHub, open the **Actions** tab, click the workflow.
