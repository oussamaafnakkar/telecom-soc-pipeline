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

## `Dockerfile` and `scripts/`

One small image (`python:3.12-slim`, standard library only, non-root user)
carries three jobs, each a script in `scripts/`:

- `make_fixtures.sh` writes the attack and benign JSONL files into `/data/ss7`.
- `run_detection_tests.sh` generates fresh events in a temp directory and checks
  that the rule fires on all attack events and on no benign event.
- `verify_e2e.py` asks Elasticsearch four questions: total documents, alert-tagged
  documents, false positives (tagged but trusted) and missed detections
  (untagged but untrusted). Any wrong answer exits non-zero.

## `docker-compose.yml`

Six services:

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
