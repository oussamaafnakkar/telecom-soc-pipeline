#!/bin/sh
# Fast detection test, no Elasticsearch needed.
# 1. The rule must fire on every attack event (no missed detections).
# 2. The rule must stay silent on every benign event (no false positives).
# Exits non-zero on the first failure, which is what makes CI go red.
set -eu

TMP="$(mktemp -d)"
ATTACK_COUNT="${ATTACK_COUNT:-20}"
BENIGN_COUNT="${BENIGN_COUNT:-50}"
SEED="${SEED:-42}"

python3 generators/ss7_atsi_generator.py --scenario attack --count "$ATTACK_COUNT" --seed "$SEED" --out "$TMP/attack.jsonl"
python3 generators/ss7_atsi_generator.py --scenario benign --count "$BENIGN_COUNT" --seed "$SEED" --out "$TMP/benign.jsonl"

echo "== attack fixture: every event must alert =="
python3 detections/evaluate_ss7_rule.py "$TMP/attack.jsonl" --expect alerts

echo
echo "== benign fixture: no event may alert =="
python3 detections/evaluate_ss7_rule.py "$TMP/benign.jsonl" --expect silent
