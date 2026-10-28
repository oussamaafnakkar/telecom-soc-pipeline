# Contributing

Thanks for taking a look. This project turns telecom attack scenarios into
tested detection rules, and contributions that add or improve a scenario are
the most useful ones.

## What you need

Docker with the compose plugin, and `make`. Nothing else. Python is not
required on your machine, everything runs in containers.

```bash
make test     # detection tests, about 20 seconds
make e2e      # full stack: Elasticsearch, Logstash, Kibana, then verify
make reset    # stop everything and delete all data
```

## Workflow

1. Branch from `main`: `git switch -b feature/<scenario-name>`
2. Make small commits using [Conventional Commits](https://www.conventionalcommits.org/):
   `feat:`, `fix:`, `docs:`, `ci:`, `test:`, `chore:`
3. Run `make test` before every push, and `make e2e` before opening a pull request.
4. Open a pull request. CI runs the same two commands and must be green to merge.

## Adding a detection scenario

Each scenario ships four things, and a pull request is incomplete without all four:

1. A generator in `generators/` that can produce both **attack** and **benign** events.
2. A Sigma rule in `detections/sigma/`, with `falsepositives` filled in honestly.
3. Tests: the rule must fire on every attack event and stay silent on every benign event.
4. A row in `docs/mapping-table.md` linking the scenario to the blog post and the MITRE FiGHT technique.

## Safety

All traffic in this repository is synthetic. Do not commit real subscriber
identifiers (IMSI, MSISDN), real operator Global Titles, or captures from live
networks. Example values must be clearly fictional.

## Reporting a security problem

If you find a vulnerability in this project itself, open a private security
advisory on GitHub instead of a public issue.
