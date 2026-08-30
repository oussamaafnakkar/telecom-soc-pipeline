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
- `filter`: parses the timestamp, then re-implements the same detection
  condition a third time (Logstash's own conditional syntax) and tags
  matching events with `sigma_match_ss7_location_disclosure` before indexing.
- `output`: ships to Elasticsearch into a daily index (`ss7-signaling-YYYY.MM.DD`).

Yes - the detection logic now exists in three places (Sigma rule, Python
evaluator, Logstash filter). That's a real tradeoff, not an oversight, and
it's worth naming directly rather than glossing over it: it's the cost of not
yet having a converter that generates the Logstash/Elastic query directly
from the Sigma rule. Documented here and in `architecture.md` so it reads as
understood scope, not a gap nobody noticed.

## `docker-compose.yml`

Three services: `elasticsearch` (storage/search), `logstash` (depends on
Elasticsearch being **healthy**, not just started, via
`depends_on: condition: service_healthy`), and `kibana` (the UI, the only
port bound beyond the internal Docker network). `soc-net` is a private bridge
network so containers reach each other by service name
(`http://elasticsearch:9200`) without exposing anything except Kibana's port
to the host.

## CI/CD (`.github/workflows/ci.yml`)

Three jobs run in sequence - each `needs:` the previous one, so a failure
stops the chain early instead of burning runner time on doomed later steps.

1. **`lint-and-validate`** - `ruff` on the Python, a schema check that every
   Sigma rule has its required fields, and `docker compose config` to catch a
   broken compose file before anything tries to deploy it.
2. **`detection-smoke-test`** - generates fresh attack and benign fixtures
   inside the runner (not committed data, regenerated every run) and asserts
   the Python evaluator gets 100% detection and 0% false positives. No Docker
   needed, so it's fast.
3. **`end-to-end-elk-test`** - the real proof: runs `docker compose up -d`
   inside the GitHub Actions runner itself, waits for Elasticsearch to report
   healthy, waits for the fixtures to finish indexing, then queries
   Elasticsearch directly and asserts exactly 10 documents carry the
   `sigma_match_ss7_location_disclosure` tag. This proves the whole chain
   (generator -> Logstash -> Elasticsearch), not just the rule logic in
   isolation. `docker compose down -v` runs with `if: always()` so it tears
   down even on failure, and `docker compose logs` only prints
   `if: failure()`, so passing runs stay quiet and failing runs give you
   exactly the debugging output you need.

To watch a run: push to GitHub, open the **Actions** tab, click the running
workflow, and each job's logs stream live.
