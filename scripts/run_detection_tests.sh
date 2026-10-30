#!/bin/sh
# Fast detection tests, no Elasticsearch needed. For every scenario:
# 1. The rules must fire on every attack event (no missed detections).
# 2. The rules must stay silent on every benign event (no false positives).
# Exits non-zero on the first failure, which is what makes CI go red.
set -eu

TMP="$(mktemp -d)"
ATTACK_COUNT="${ATTACK_COUNT:-20}"
BENIGN_COUNT="${BENIGN_COUNT:-50}"
SEED="${SEED:-42}"

echo "######## SS7 location disclosure ########"
python3 generators/ss7_atsi_generator.py --scenario attack --count "$ATTACK_COUNT" --seed "$SEED" --out "$TMP/ss7_attack.jsonl"
python3 generators/ss7_atsi_generator.py --scenario benign --count "$BENIGN_COUNT" --seed "$SEED" --out "$TMP/ss7_benign.jsonl"

echo "== attack fixture: every event must alert =="
python3 detections/evaluate_ss7_rule.py "$TMP/ss7_attack.jsonl" --expect alerts
echo
echo "== benign fixture: no event may alert =="
python3 detections/evaluate_ss7_rule.py "$TMP/ss7_benign.jsonl" --expect silent

echo
echo "######## IMSI catcher indicators ########"
python3 generators/imsi_catcher_generator.py --scenario attack --count "$ATTACK_COUNT" --seed "$SEED" --out "$TMP/imsi_attack.jsonl"
python3 generators/imsi_catcher_generator.py --scenario benign --count "$BENIGN_COUNT" --seed "$SEED" --out "$TMP/imsi_benign.jsonl"

echo "== attack fixture: every event must alert, each variant on its own rule =="
python3 detections/evaluate_imsi_rules.py "$TMP/imsi_attack.jsonl" --expect alerts
echo
echo "== benign fixture: no event may alert =="
python3 detections/evaluate_imsi_rules.py "$TMP/imsi_benign.jsonl" --expect silent
