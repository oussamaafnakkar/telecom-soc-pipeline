"""
evaluate_imsi_rules.py

Applies the logic of the two IMSI catcher Sigma rules directly to a stream of
JSON cell measurements, without needing a live ELK stack:

  detections/sigma/imsi-catcher-critical-indicator.yml     (IND-01 or IND-03)
  detections/sigma/imsi-catcher-weak-indicator-combo.yml   (IND-04 and IND-05 and IND-06)

Same job as evaluate_ss7_rule.py: a fast local check, and the test CI runs.
The Sigma files are the source of truth. This script and the Logstash filter
are re-implementations that must be kept in sync by hand.

Modes:
  --expect alerts   every event must match at least one rule, and each attack
                    variant must match exactly the rules it is meant to match
  --expect silent   no event may match any rule (false-positive test)
"""

import argparse
import json
import sys
from collections import defaultdict

SUSPICIOUS_LACS = {0, 1, 0xFFFD, 0xFFFE, 0xFFFF}
MOROCCAN_MNCS = {0, 1, 2}


def critical_indicator(e):
    """IND-01 (fingerprint LAC) or IND-03 (A5/0 on a Moroccan carrier)."""
    if e.get("lac") in SUSPICIOUS_LACS:
        return True
    return e.get("mcc") == 604 and e.get("mnc") in MOROCCAN_MNCS and e.get("encryption") == "A5/0"


def weak_indicator_combo(e):
    """IND-04 and IND-05 and IND-06 together."""
    neighbors = e.get("neighbor_count")
    rssi = e.get("rssi_dbm")
    return (
        e.get("auth_requested") is False
        and neighbors is not None
        and neighbors < 2
        and e.get("cell_in_inventory") is False
        and rssi is not None
        and rssi > -55
    )


RULES = {
    "critical_indicator": critical_indicator,
    "weak_indicator_combo": weak_indicator_combo,
}

# For each attack variant: the rules that must fire, and the rules that must not.
# stealth_combo must NOT trip the critical rule, otherwise it is not stealthy
# and the combination rule is not really being tested.
EXPECTATIONS = {
    "research_grade": ({"critical_indicator"}, set()),
    "stealth_combo": ({"weak_indicator_combo"}, {"critical_indicator"}),
    "downgrade_only": ({"critical_indicator"}, {"weak_indicator_combo"}),
}


def evaluate(path):
    total = 0
    unmatched = 0
    violations = []
    by_variant = defaultdict(lambda: defaultdict(int))

    with (sys.stdin if path == "-" else open(path)) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            total += 1
            event = json.loads(line)
            variant = event.get("fixture_variant", "unknown")
            matched = {name for name, rule in RULES.items() if rule(event)}

            by_variant[variant]["events"] += 1
            if matched:
                by_variant[variant]["alerts"] += 1
            else:
                unmatched += 1
            for name in matched:
                by_variant[variant][name] += 1

            if variant in EXPECTATIONS:
                required, forbidden = EXPECTATIONS[variant]
                if not required <= matched or matched & forbidden:
                    violations.append((event["event_id"], variant, sorted(matched)))

    return total, unmatched, violations, by_variant


def print_table(by_variant):
    print(f"{'variant':30} {'events':>6} {'alerts':>6}  " + "  ".join(RULES))
    for variant, stats in sorted(by_variant.items()):
        counts = "  ".join(f"{stats[name]:>{len(name)}}" for name in RULES)
        print(f"{variant:30} {stats['events']:>6} {stats['alerts']:>6}  {counts}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="path to newline-delimited JSON events, or '-' for stdin")
    parser.add_argument("--expect", choices=["alerts", "silent"], required=True)
    args = parser.parse_args()

    total, unmatched, violations, by_variant = evaluate(args.input)
    matched_events = total - unmatched

    print_table(by_variant)
    print(f"\n{matched_events}/{total} events matched at least one rule.")

    if total == 0:
        print("FAIL: no events to evaluate.", file=sys.stderr)
        sys.exit(1)

    if args.expect == "alerts":
        for event_id, variant, matched in violations:
            print(f"FAIL: {variant} event {event_id} matched {matched}", file=sys.stderr)
        if unmatched:
            print(f"FAIL: {unmatched} attack event(s) matched no rule (missed detection).", file=sys.stderr)
        if unmatched or violations:
            sys.exit(1)
        print("PASS: every attack variant tripped exactly the rules it should.")
    else:
        if matched_events:
            print(f"FAIL: {matched_events} benign event(s) matched a rule (false positives).", file=sys.stderr)
            sys.exit(1)
        print("PASS: no rule fired on benign traffic (0 false positives).")


if __name__ == "__main__":
    main()
