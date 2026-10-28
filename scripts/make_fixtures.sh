#!/bin/sh
# Writes one attack file and one benign file of JSON signaling events.
# Runs inside the tools container as the `fixtures` service, and the files land
# in a Docker volume that Logstash reads from.
set -eu

OUT="${FIXTURE_DIR:-/data/ss7}"
ATTACK_COUNT="${ATTACK_COUNT:-20}"
BENIGN_COUNT="${BENIGN_COUNT:-50}"
SEED="${SEED:-42}"

mkdir -p "$OUT"
python3 generators/ss7_atsi_generator.py --scenario attack --count "$ATTACK_COUNT" --seed "$SEED" --out "$OUT/ss7_attack.jsonl"
python3 generators/ss7_atsi_generator.py --scenario benign --count "$BENIGN_COUNT" --seed "$SEED" --out "$OUT/ss7_benign.jsonl"

echo "fixtures written to $OUT: $ATTACK_COUNT attack events, $BENIGN_COUNT benign events"
