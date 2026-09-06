# Getting Started (do this on your machine, in order)

Don't read this end to end first. Run each command as you get to it, look at
what it prints, then move to the next one. This is the order that actually
builds understanding.

## 1. Get the code onto your machine and look at it

```bash
cd ~/projects                      # or wherever you keep repos
unzip telecom-soc-pipeline.zip
cd telecom-soc-pipeline
```

Look at the shape of the project first, no reading yet:

```bash
tree -L 2
```

You already know this output. Now open the smallest file and actually read it:

```bash
cat detections/sigma/ss7-location-disclosure.yml
```

This is 30 lines. This is the entire "what counts as an attack" definition
for the whole project. Everything else exists to produce data for this file
to check, or to run this file's logic against real traffic. Read it twice.
The important part is `detection: selection:` - those three lines are the
actual rule.

## 2. Generate fake attack traffic and read it with your own eyes

```bash
python3 generators/ss7_atsi_generator.py --scenario attack --count 3
```

You'll see 3 lines of JSON print to your terminal. Each line is one fake
signaling event. Look at the `src_gt_trusted_partner` field on each line - it
should say `false`. That's the thing the Sigma rule checks for.

Now run it again with `benign` instead of `attack`:

```bash
python3 generators/ss7_atsi_generator.py --scenario benign --count 3
```

Same shape of data, but now `src_gt_trusted_partner` says `true`. That's the
entire difference between the two files. Nothing else about the data changes
in a way that matters to the rule.

## 3. Save both to files, then check the rule against them yourself

```bash
mkdir -p tests/fixtures
python3 generators/ss7_atsi_generator.py --scenario attack --count 20 --out tests/fixtures/ss7_attack.jsonl
python3 generators/ss7_atsi_generator.py --scenario benign --count 50 --out tests/fixtures/ss7_benign.jsonl
```

Look at the file you just made:

```bash
cat tests/fixtures/ss7_attack.jsonl | head -n 2
wc -l tests/fixtures/ss7_attack.jsonl        # should say 20
```

Now run the detection logic against it:

```bash
python3 detections/evaluate_ss7_rule.py tests/fixtures/ss7_attack.jsonl --expect alerts
```

Read the output top to bottom. Each `ALERT` line is one event that matched
the rule. At the bottom it tells you `20/20 events matched` and `PASS`.

Now run it against the benign file:

```bash
python3 detections/evaluate_ss7_rule.py tests/fixtures/ss7_benign.jsonl --expect silent
```

This time you should see `0/50 events matched` and `PASS`. Nothing printed
as an ALERT because none of the trusted-partner traffic should trigger it.

**Stop here and make sure this part makes sense before moving to Docker.**
Everything so far ran with plain `python3` - no Docker, no Elasticsearch, no
Kibana. This is the fast inner loop: change the rule or the generator, rerun
these two commands, see if it still passes. This is also exactly what the
`detection-smoke-test` CI job does automatically on every push.

## 4. Bring up the real SIEM stack (Elasticsearch + Logstash + Kibana)

```bash
docker compose up -d
```

Watch what starts:

```bash
docker compose ps
```

You should see three containers: `soc-elasticsearch`, `soc-logstash`,
`soc-kibana`. `STATUS` will say `starting` or `health: starting` at first.
Wait a bit and run `docker compose ps` again until Elasticsearch shows
`healthy`.

Check Elasticsearch is actually responding:

```bash
curl http://localhost:9200
```

You should get back a JSON blob describing the cluster. If you get
"connection refused," it's not up yet - wait and retry.

## 5. Check that your fake data actually made it into Elasticsearch

Logstash reads from `tests/fixtures/*.jsonl` (see the `docker-compose.yml`
volume mount) and pushes into Elasticsearch. Check the count:

```bash
curl "http://localhost:9200/ss7-signaling-*/_count"
```

You should see a number matching how many events you generated (20 + 50 = 70,
if you kept both files in `tests/fixtures/`).

Check specifically how many got tagged as alerts:

```bash
curl -s "http://localhost:9200/ss7-signaling-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"query": {"term": {"tags": "sigma_match_ss7_location_disclosure"}}}'
```

Look for `"value"` inside `"total"` in the response - it should be 20, matching
your attack file. This is the same check the CI end-to-end test does, just
run by hand.

## 6. Look at it visually in Kibana

Open in your browser: `http://localhost:5601`

First time in Kibana, you need to point it at your data:
1. Go to **Stack Management -> Index Patterns** (or **Data Views**, depending
   on version).
2. Create one matching `ss7-signaling-*`.
3. Go to **Discover** in the left sidebar and pick that pattern.

You'll see your 70 events as a table. Filter by typing
`tags: "sigma_match_ss7_location_disclosure"` in the search bar - you should
get exactly 20 rows back, all your attack traffic, none of your benign
traffic.

## 7. Debugging - what to do when something doesn't work

```bash
docker compose logs elasticsearch    # is it complaining about memory/disk?
docker compose logs logstash         # did it fail to parse the config or the files?
docker compose logs kibana           # can it reach elasticsearch?
```

Common issues:
- **Elasticsearch never goes healthy**: it often needs more memory than
  Docker Desktop/your daemon allows by default. Check `docker compose logs
  elasticsearch` for an out-of-memory or `vm.max_map_count` error.
- **Logstash shows 0 documents indexed**: check `docker compose logs logstash`
  for a parse error - most likely a malformed line in your `.jsonl` file, or
  the file wasn't in `tests/fixtures/` when the container started (Logstash
  only picks up files present at container start with the current config).
- **Nothing works and you want a clean slate**:
  ```bash
  docker compose down -v      # stops everything AND deletes the Elasticsearch data volume
  docker compose up -d        # start fresh
  ```

## 8. Git - saving and pushing your work

```bash
git status                    # what changed since your last commit
git add .
git commit -m "docs: add getting-started guide"
git push
```

After `git push`, go to your repo on GitHub, click the **Actions** tab, and
watch the three CI jobs run in real time. This is the same sequence you just
ran by hand in steps 3-5, except GitHub does it automatically on every push.

## The one-sentence version of the whole system

A Python script invents fake signaling traffic and labels each event as
trustworthy or not. A Sigma rule says "flag anything untrustworthy." Three
things check that rule against the data: a quick Python script (for fast
local iteration and CI), a Logstash filter (for the real pipeline), and
Kibana (so a human can see the result). Docker Compose is just the thing that
starts Elasticsearch, Logstash, and Kibana together so they can talk to each
other.
