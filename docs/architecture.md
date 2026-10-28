# Architecture

```
fixtures container        logstash                 elasticsearch          kibana
  | writes JSONL events     | reads the volume,       | indexes into          | dashboards
  | into a Docker volume    | tags rule matches       | ss7-signaling-*       | 127.0.0.1:5601
  v                         v                         v                      v
 [fixtures volume] ---> ingest/logstash/conf.d/ss7.conf ---> [ES index] ---> [Kibana]
                                                              ^
                                       verify container ------+  (asserts the counts)
```

## Why events, not raw wire bytes

The generator produces the **decoded event representation** of MAP signaling
(opcode, source/destination Global Title, target MSISDN, trusted-partner flag)
rather than raw TCAP/MAP-encoded bytes on the wire. This mirrors what actually
reaches a SIEM in a real deployment: a signaling probe or mediation layer
decodes the SS7 traffic first, and it's the decoded event stream that gets
shipped to Logstash/Kafka. Byte-level TCAP/MAP framing is the concern of the
probe itself, not the detection layer - keeping the generator at the event
level is a closer match to how detections are actually built and tested in
production, and it's what let the Sigma rule + false-positive test happen
without needing a real telecom protocol stack.

## Network / security boundary

- Elasticsearch and Kibana publish ports on `127.0.0.1` only, never `0.0.0.0`.
  Logstash publishes nothing. The tools containers (fixtures, tests, verify) run
  as a non-root user with a read-only filesystem, all Linux capabilities dropped
  and `no-new-privileges` set.
- Kibana is the only service meant to be reached by a person, and only on
  localhost in this dev/demo configuration.
- `xpack.security.enabled=false` on Elasticsearch is a **local-development
  convenience only**. A real deployment (or a public live demo) must enable
  authentication and put Kibana behind a reverse proxy with its own auth -
  see the note in `docker-compose.yml`.
- No secrets are stored in this repo. `.env.example` documents what a real
  deployment would need (e.g. Elastic credentials); actual `.env` files are
  gitignored.

## Detection logic lives in two places, on purpose

The Sigma rule (`detections/sigma/ss7-location-disclosure.yml`) is the source
of truth for the detection logic and the artifact a SOC would actually deploy
(convertible to a Kibana/Elastic query, Splunk SPL, or QRadar AQL). The
Logstash filter and `detections/evaluate_ss7_rule.py` are both faithful
re-implementations of that same `selection` block - one so the tagging
happens at ingest time, one so CI can prove the logic works without needing a
live ELK stack for every commit. If the Sigma rule's selection logic changes,
both re-implementations must be updated to match - this is a known
maintenance cost of not yet running a real Sigma-to-Elastic converter, and is
flagged as a roadmap item.
