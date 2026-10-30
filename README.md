# Telecom Signaling Detection Pipeline

A detection pipeline that turns the attack scenarios from the [Secure Byte
Chronicles Telecom Security series](https://www.sbytec.com/collections/telecom-security-series/)
into working Sigma detection rules, ingested and alerted on through an ELK
stack, and mapped to [MITRE FiGHT](https://fight.mitre.org/), the
telecom-specific ATT&CK-style framework.

It is a companion project to the blog series. The goal is operational skill:
writing a detection, running it in a SIEM, and proving it works with tests,
including tests for false positives.

Everything runs in Docker. All traffic is synthetic.

## Status

| Scenario | Status |
|---|---|
| SS7 location disclosure | **Live**: generator, Sigma rule, Logstash ingest, CI-tested |
| IMSI catchers | **Live**: generator, two Sigma rules, Logstash ingest, CI-tested |
| SIM swapping | Planned |
| GTP security | Planned |

See [`docs/mapping-table.md`](docs/mapping-table.md) for the blog-post-to-rule mapping.

## Quickstart

You need Docker (with the compose plugin) and `make`. Nothing else.

```bash
git clone git@github.com:oussamaafnakkar/telecom-soc-pipeline.git
cd telecom-soc-pipeline

make test     # detection tests in Docker, no Elasticsearch needed
make e2e      # start Elasticsearch, Logstash and Kibana, then verify the whole pipeline
make down     # stop the stack when you are done
```

`make e2e` ends with a block of `PASS` lines for each scenario. Kibana is then available at
http://localhost:5601. Run `make help` to see every command.

New to the project? [`docs/getting-started.md`](docs/getting-started.md) walks
through each command one at a time and explains what you should see.

## How it works

```
fixtures container -> JSON events -> Logstash (tags rule matches) -> Elasticsearch -> Kibana
```

1. Python generators write synthetic events for each scenario: SS7 signaling from
   untrusted and trusted Global Titles, and GSM cell measurements from rogue and
   legitimate cells. Every scenario has attack traffic and benign look-alikes.
2. Sigma rules define what counts as an attack.
3. Logstash applies the same logic, one pipeline per scenario, and tags matching events.
4. A verifier asks Elasticsearch whether exactly the attack events were tagged.

Details: [`docs/architecture.md`](docs/architecture.md) and
[`docs/code-walkthrough.md`](docs/code-walkthrough.md).

## Repository layout

```
Dockerfile          tools image (generators, tests, verifier)
docker-compose.yml  the whole stack
Makefile            every command you need
generators/         Python event generators, attack and benign traffic per scenario (ss7, imsi)
detections/
  sigma/            Sigma rules, the source of truth for detection logic
  evaluate_*.py     standalone rule evaluators used by the tests
ingest/logstash/    Logstash pipeline configs
scripts/            container scripts: fixtures, detection tests, end-to-end verifier
docs/               architecture, code walkthrough, getting started, mapping table
.github/workflows/  CI
```

## CI

Every push and pull request runs the same commands you run locally:

1. Lint and validate: ruff, Sigma rule fields, shell syntax, `docker compose config`
2. `make test`: detection tests in Docker
3. `make up` then `make verify`: the full stack, checked end to end

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Security notes

This is a local demo configuration. Elasticsearch runs with security disabled,
so every published port is bound to `127.0.0.1`. Do not expose it beyond
localhost as it is. See [`docs/architecture.md`](docs/architecture.md) for the
network boundary and what a hardened deployment adds.

## Contributing and license

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Released under the [MIT License](LICENSE).
