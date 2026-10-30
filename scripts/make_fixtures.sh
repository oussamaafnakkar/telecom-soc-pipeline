#!/bin/sh
# Writes one attack file and one benign file of JSON events for every scenario.
# Runs inside the tools container as the `fixtures` service, and the files land
# in a Docker volume that Logstash reads from, one folder per scenario.
set -eu

OUT="${FIXTURE_DIR:-/data}"
ATTACK_COUNT="${ATTACK_COUNT:-20}"
BENIGN_COUNT="${BENIGN_COUNT:-50}"
SEED="${SEED:-42}"

mkdir -p "$OUT/ss7" "$OUT/imsi"

python3 generators/ss7_atsi_generator.py --scenario attack --count "$ATTACK_COUNT" --seed "$SEED" --out "$OUT/ss7/ss7_attack.jsonl"
python3 generators/ss7_atsi_generator.py --scenario benign --count "$BENIGN_COUNT" --seed "$SEED" --out "$OUT/ss7/ss7_benign.jsonl"

python3 generators/imsi_catcher_generator.py --scenario attack --count "$ATTACK_COUNT" --seed "$SEED" --out "$OUT/imsi/imsi_attack.jsonl"
python3 generators/imsi_catcher_generator.py --scenario benign --count "$BENIGN_COUNT" --seed "$SEED" --out "$OUT/imsi/imsi_benign.jsonl"

echo "fixtures written to $OUT: $ATTACK_COUNT attack and $BENIGN_COUNT benign events per scenario (ss7, imsi)"
