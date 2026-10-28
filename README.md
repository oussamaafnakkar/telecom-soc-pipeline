# Telecom Signaling Detection Pipeline

A detection pipeline that turns the attack scenarios from the [Secure Byte
Chronicles Telecom Security series](https://www.sbytec.com/collections/telecom-security-series/)
into working Sigma detection rules, ingested and alerted on through an ELK
stack, and mapped to [MITRE FiGHT](https://fight.mitre.org/) (the
telecom-specific ATT&CK-style framework).

Companion project to the blog series, built to demonstrate operational SOC
skills - writing detections, running a SIEM, and testing for false positives
- rather than just protocol write-ups.

## Status

| Scenario | Status |
|---|---|
| SS7 location disclosure | **Live** - generator, Sigma rule, Logstash ingest, CI-tested (100% detection, 0 false positives) |
| IMSI catchers | Planned |
| SIM swapping | Planned |
| GTP security | Planned |

See [`docs/mapping-table.md`](docs/mapping-table.md) for the full blog-post-to-rule mapping and FiGHT technique IDs.

## Quickstart

New to this repo or unsure what connects to what? Start with
[`docs/getting-started.md`](docs/getting-started.md) instead - it walks
through every command below one at a time, explains what you should see, and
covers debugging. The commands below are the short version for once you're
comfortable.

```bash
git clone <this-repo>
cd telecom-soc-pipeline

# generate attack + benign traffic fixtures
python3 generators/ss7_atsi_generator.py --scenario attack --count 20 --out tests/fixtures/ss7_attack.jsonl
python3 generators/ss7_atsi_generator.py --scenario benign --count 50 --out tests/fixtures/ss7_benign.jsonl

# fast local check, no ELK required
python3 detections/evaluate_ss7_rule.py tests/fixtures/ss7_attack.jsonl --expect alerts
python3 detections/evaluate_ss7_rule.py tests/fixtures/ss7_benign.jsonl --expect silent

# full stack: ingest into a real SIEM and view in Kibana
docker compose up -d
# Kibana: http://localhost:5601  (events land in the ss7-signaling-* index)
```

## How it works

```
generator -> JSON signaling events -> Logstash (tags Sigma-rule matches) -> Elasticsearch -> Kibana
```

Full breakdown in [`docs/architecture.md`](docs/architecture.md). A
line-by-line explanation of every file, including how the CI/CD jobs work,
is in [`docs/code-walkthrough.md`](docs/code-walkthrough.md).

## Why this exists

Full project rationale and how it fits the Moroccan SOC analyst job market is
in the project brief (kept outside this repo, alongside the job-search
materials).

## Repository layout

```
generators/       Python event generators (attack + benign traffic per scenario)
detections/
  sigma/           Sigma detection rules - the source of truth for detection logic
  evaluate_*.py     Standalone evaluators used for fast local testing and CI smoke tests
ingest/logstash/    Logstash pipeline configs
dashboards/         Importable Kibana dashboard exports
docs/               Architecture notes and the blog-post-to-rule mapping table
tests/fixtures/     Generated JSONL fixtures (gitignored except small committed samples)
.github/workflows/  CI: lint, Sigma validation, compose validation, detection smoke test, full ELK integration test
```

## CI/CD

Every push and pull request runs, in order: Python lint, Sigma rule schema
validation, `docker compose config` validation, a fast detection smoke test
(generator -> rule, no ELK needed), and a full end-to-end integration test
that stands up the real ELK stack, ingests both fixtures, and asserts
Elasticsearch tagged exactly the attack traffic as alerts. See
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Security notes

This is a local development / demo configuration - Elasticsearch runs
without auth for simplicity. Do not expose it beyond localhost as-is. See
[`docs/architecture.md`](docs/architecture.md) for the intended network
boundary and what a hardened deployment would add.
