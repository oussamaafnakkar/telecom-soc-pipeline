"""
evaluate_sim_swap_rules.py

Applies the SIM swap Sigma rules directly to a stream of JSON MAP events,
without needing a live ELK stack:

  detections/sigma/sim-swap-update-location-untrusted.yml    (single event)
  detections/sigma/sim-swap-register-ss-cfu-untrusted.yml    (single event)
  detections/sigma/sim-swap-correlation.yml                   (both, same IMSI, 60 s)

The first two judge one event at a time, like the SS7 rule. The third has to
look across events: it groups the hits by IMSI and checks the time between them.
That is the new idea in this scenario.

Modes:
  --expect alerts   every attack event must match its rule, and the set of
                    correlated IMSIs must equal the set of full_swap IMSIs
  --expect silent   no event may match a rule and nothing may correlate
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime

WINDOW_SECONDS = 60


def update_location_untrusted(e):
    return (
        e.get("signaling_protocol") == "MAP"
        and e.get("map_opcode") == 2
        and e.get("src_gt_trusted_partner") is False
    )


def register_ss_cfu_untrusted(e):
    return (
        e.get("signaling_protocol") == "MAP"
        and e.get("map_opcode") == 10
        and e.get("ss_code") == 33
        and e.get("src_gt_trusted_partner") is False
    )


RULES = {
    "update_location": update_location_untrusted,
    "register_ss_cfu": register_ss_cfu_untrusted,
}

# (variant, map_opcode) -> (rules that must fire, rules that must not fire)
EXPECTATIONS = {
    ("ul_only", 2): ({"update_location"}, {"register_ss_cfu"}),
    ("register_ss_only", 10): ({"register_ss_cfu"}, {"update_location"}),
    ("full_swap", 2): ({"update_location"}, {"register_ss_cfu"}),
    ("full_swap", 10): ({"register_ss_cfu"}, {"update_location"}),
}


def _time(event):
    return datetime.fromisoformat(event["@timestamp"])


def correlate(hits_a, hits_b, window=WINDOW_SECONDS):
    """IMSIs that have a hit in both lists no more than `window` seconds apart.

    Each argument is a list of (imsi, datetime). This is a Sigma `temporal`
    correlation grouped by imsi: both rules must match inside the timespan,
    in either order.
    """
    by_imsi = defaultdict(lambda: ([], []))
    for imsi, t in hits_a:
        by_imsi[imsi][0].append(t)
    for imsi, t in hits_b:
        by_imsi[imsi][1].append(t)
    return {
        imsi
        for imsi, (a_times, b_times) in by_imsi.items()
        if any(abs((a - b).total_seconds()) <= window for a in a_times for b in b_times)
    }


def evaluate(path):
    total = 0
    unmatched = 0
    violations = []
    by_variant = defaultdict(lambda: defaultdict(int))
    hits = {name: [] for name in RULES}
    full_swap_imsis = set()

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
                hits[name].append((event["imsi"], _time(event)))
            if variant == "full_swap":
                full_swap_imsis.add(event["imsi"])

            key = (variant, event.get("map_opcode"))
            if key in EXPECTATIONS:
                required, forbidden = EXPECTATIONS[key]
                if not required <= matched or matched & forbidden:
                    violations.append((event["event_id"], variant, sorted(matched)))

    correlated = correlate(hits["update_location"], hits["register_ss_cfu"])
    return total, unmatched, violations, by_variant, correlated, full_swap_imsis


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

    total, unmatched, violations, by_variant, correlated, full_swap_imsis = evaluate(args.input)
    matched_events = total - unmatched

    print_table(by_variant)
    print(f"\n{matched_events}/{total} events matched at least one rule.")
    print(f"{len(correlated)} IMSI(s) correlated (both rules within {WINDOW_SECONDS}s).")

    if total == 0:
        print("FAIL: no events to evaluate.", file=sys.stderr)
        sys.exit(1)

    failed = False
    if args.expect == "alerts":
        for event_id, variant, matched in violations:
            print(f"FAIL: {variant} event {event_id} matched {matched}", file=sys.stderr)
        if unmatched:
            print(f"FAIL: {unmatched} attack event(s) matched no rule (missed detection).", file=sys.stderr)
        if correlated != full_swap_imsis:
            print(
                f"FAIL: correlated IMSIs {len(correlated)} != full_swap IMSIs {len(full_swap_imsis)}.",
                file=sys.stderr,
            )
        failed = bool(unmatched or violations or correlated != full_swap_imsis)
        if not failed:
            print("PASS: every attack incident tripped exactly the rules it should, and only full swaps correlated.")
    else:
        if matched_events or correlated:
            print(f"FAIL: {matched_events} benign event(s) matched, {len(correlated)} correlated.", file=sys.stderr)
            failed = True
        else:
            print("PASS: no rule fired and nothing correlated on benign traffic (0 false positives).")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
