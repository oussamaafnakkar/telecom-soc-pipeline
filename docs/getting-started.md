# Getting Started

Run each command as you reach it and look at what it prints before moving on.
Do not read this whole file first.

## 0. Prerequisites (Arch Linux)

```bash
sudo pacman -S docker docker-compose docker-buildx make
sudo systemctl enable --now docker
sudo usermod -aG docker $USER      # then log out and back in
docker compose version             # should print a version
```

## 1. Look around

```bash
cd telecom-soc-pipeline
tree -a -I .git
cat detections/sigma/ss7-location-disclosure.yml
```

The Sigma file is the whole definition of "what is an attack" in this project.
The lines under `detection: selection:` are the actual rule. Everything else
exists to feed this rule data or to prove it works. Read it twice.

## 2. See the fake traffic with your own eyes

```bash
docker compose run --rm tests python3 generators/ss7_atsi_generator.py --scenario attack --count 3
docker compose run --rm tests python3 generators/ss7_atsi_generator.py --scenario benign --count 3
```

Each line is one signaling event. Compare `src_gt_trusted_partner`: `false` in
the attack run, `true` in the benign run. That one field is what the rule checks.

## 3. Run the detection tests

```bash
make test
```

Read the output top to bottom. The attack file must produce an `ALERT` for every
event, and the benign file must produce none. Both must end in `PASS`. If
either fails, the command exits with an error, and that is exactly what turns CI red.

Nothing here needs Elasticsearch. This is the fast loop: change the rule or the
generator, run `make test`, repeat.

## 4. Start the full stack

```bash
make e2e
```

This stops anything old, starts Elasticsearch, Logstash and Kibana, and then runs
the verifier. The first run downloads about 2 GB of images, so be patient.
It ends with four `PASS` lines:

```
PASS  total documents: got 70, expected 70
PASS  alert-tagged documents: got 20, expected 20
PASS  false positives (tagged but trusted): got 0, expected 0
PASS  missed detections (untagged but untrusted): got 0, expected 0
```

Those four numbers are the proof that the whole pipeline works.

## 5. Look at it in Kibana

Open http://localhost:5601 in a browser.

1. Open the menu, then **Stack Management**, then **Data Views**, then create one named `ss7-signaling-*`.
   Pick `@timestamp` as the time field.
2. Open **Discover** and select that data view.
3. If the table is empty, widen the time range to the last 24 hours.
4. Type `tags : "sigma_match_ss7_location_disclosure"` in the search bar.
   You should see exactly 20 events, all attack traffic.

You can also query Elasticsearch directly:

```bash
curl "http://localhost:9200/ss7-signaling-*/_count?pretty"
```

## 6. Debugging

```bash
make ps                          # is every service up? Exited (0) is correct for `fixtures`
make logs                        # last 100 lines of every service
docker compose logs logstash     # one service
make reset                       # delete everything and start clean
```

| Symptom | Where to look |
|---|---|
| `make verify` times out | `docker compose logs logstash`: a config error or a file it could not read |
| Total documents is more than 70 | You started the stack twice without a reset. Run `make e2e` |
| Elasticsearch never gets healthy | `docker compose logs elasticsearch`: usually not enough memory |
| `permission denied` talking to Docker | You are not in the `docker` group, see step 0 |

## 7. Git

```bash
git status
git add <files>
git commit -m "docs: describe what changed"
git push -u origin <branch>
```

After pushing, open the Actions tab of your repository. CI runs the same
`make test` and `make e2e` you just ran by hand.

## The whole system in one paragraph

A container writes fake signaling events and labels each source as trusted or not.
A Sigma rule says "flag the untrusted ones". Logstash applies that rule while
indexing into Elasticsearch, Kibana lets a human look at the result, and a
verifier checks the counts. Docker Compose starts all of it together, and Make
gives each step a short name.
