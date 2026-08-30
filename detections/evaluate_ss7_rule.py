#!/usr/bin/env python3
"""
evaluate_ss7_rule.py

Applies the logic of detections/sigma/ss7-location-disclosure.yml directly to a
stream of JSON signaling events, without needing a live ELK stack.

This exists for two reasons:
  1. Fast local iteration while writing/tuning the rule.
  2. A CI smoke test that proves the rule actually fires on attack traffic and
     stays silent on benign traffic - the false-positive test documented in
     docs/mapping-table.md.

In the deployed pipeline, the equivalent logic lives in Elasticsearch (the Sigma
rule is converted to an ES query / Kibana alert). This script is a faithful,
minimal re-implementation of the same `selection` block, kept in sync manually -
see the header of the Sigma rule for the source of truth.
"""

import argparse
import json
import sys


def matches_rule(event: dict) -> bool:
    """Mirrors detections/sigma/ss7-location-disclosure.yml `selection` + `condition`."""
    return (
        event.get("signaling_protocol") == "MAP"
        and event.get("map_opcode") == 71
        and event.get("src_gt_trusted_partner") is False
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="path to newline-delimited JSON events, or '-' for stdin")
    parser.add_argument("--expect", choices=["alerts", "silent"], required=True,
                         help="'alerts' = every event should match (attack fixture); "
                              "'silent' = no event should match (benign/false-positive fixture)")
    args = parser.parse_args()

    total = 0
    matched = 0

    def process(f):
        nonlocal total, matched
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            event = json.loads(line)
            if matches_rule(event):
                matched += 1
                print(f"ALERT  event_id={event['event_id']} src_gt={event['src_gt']} "
                      f"target_msisdn={event['target_msisdn']}")

    if args.input == "-":
        process(sys.stdin)
    else:
        with open(args.input) as f:
            process(f)

    print(f"\n{matched}/{total} events matched the rule.")

    if args.expect == "alerts":
        if total == 0:
            print("FAIL: no events to evaluate.", file=sys.stderr)
            sys.exit(1)
        if matched != total:
            print(f"FAIL: expected all {total} attack events to alert, only {matched} did.", file=sys.stderr)
            sys.exit(1)
        print("PASS: rule fired on 100% of attack traffic.")
    else:  # silent
        if matched != 0:
            print(f"FAIL: rule fired on {matched} benign event(s) - false positive.", file=sys.stderr)
            sys.exit(1)
        print("PASS: rule stayed silent on 100% of benign traffic (0 false positives).")


if __name__ == "__main__":
    main()
