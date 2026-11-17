"""
evaluate_gtp_rules.py

Applies the GTP Sigma rules directly to a stream of JSON GTPv2-C events,
without needing a live ELK stack:

  detections/sigma/gtp-session-op-untrusted-peer.yml        (single event)
  detections/sigma/gtp-serving-network-mismatch.yml         (single event)
  detections/sigma/gtp-bearer-exhaustion.yml                (threshold over time)

The first two judge one event, like the SS7 rule. The third counts: how many
different IMSIs did one source IP create sessions for in 60 seconds? It is a
Sigma `value_count` correlation, and `exhaustion_sources()` below is the only
implementation of it, shared with scripts/verify_e2e.py.

The flood attack is judged only by the threshold. Its individual messages come
from a trusted partner and look normal, so they are exempt from the per-event
"must alert" check.

Modes:
  --expect alerts   each attack variant trips its rules, and exactly the flood
                    sources are flagged by the threshold
  --expect silent   no event matches and no source is flagged
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime

WINDOW_SECONDS = 60
THRESHOLD = 10
CORRELATION_ONLY_VARIANTS = {"bearer_flood"}


def untrusted_peer(e):
    return (
        e.get("signaling_protocol") == "GTPv2-C"
        and e.get("gtp_message_type") in (32, 34)
        and e.get("src_peer_trusted") is False
    )


def serving_network_mismatch(e):
    return (
        e.get("signaling_protocol") == "GTPv2-C"
        and e.get("gtp_message_type") == 32
        and e.get("serving_network_plmn") != e.get("src_peer_plmn")
    )


def create_session_observed(e):
    """The base rule of the exhaustion correlation."""
    return e.get("signaling_protocol") == "GTPv2-C" and e.get("gtp_message_type") == 32


RULES = {
    "untrusted_peer": untrusted_peer,
    "serving_mismatch": serving_network_mismatch,
}

# variant -> (rules that must fire, rules that must not fire)
EXPECTATIONS = {
    "rogue_create_session": ({"untrusted_peer", "serving_mismatch"}, set()),
    "spoofed_serving_network": ({"serving_mismatch"}, {"untrusted_peer"}),
    "modify_bearer_hijack": ({"untrusted_peer"}, {"serving_mismatch"}),
}


def exhaustion_sources(observations, window=WINDOW_SECONDS, threshold=THRESHOLD):
    """Source IPs that created sessions for `threshold` or more distinct IMSIs in `window` seconds.

    `observations` is a list of (src_ip, imsi, datetime) for every observed
    Create Session Request. A sliding window per source keeps a count of each IMSI
    it holds, so retries of one IMSI add requests but not distinct subscribers.
    """
    by_source = defaultdict(list)
    for src_ip, imsi, t in observations:
        by_source[src_ip].append((t, imsi))

    flagged = set()
    for src_ip, items in by_source.items():
        items.sort()
        in_window = {}
        start = 0
        for t, imsi in items:
            in_window[imsi] = in_window.get(imsi, 0) + 1
            while (t - items[start][0]).total_seconds() > window:
                old = items[start][1]
                in_window[old] -= 1
                if not in_window[old]:
                    del in_window[old]
                start += 1
            if len(in_window) >= threshold:
                flagged.add(src_ip)
                break
    return flagged


def _time(event):
    return datetime.fromisoformat(event["@timestamp"])


def evaluate(path):
    total = 0
    unmatched = 0
    violations = []
    by_variant = defaultdict(lambda: defaultdict(int))
    observations = []
    flood_sources = set()

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
            elif variant not in CORRELATION_ONLY_VARIANTS:
                unmatched += 1
            for name in matched:
                by_variant[variant][name] += 1

            if create_session_observed(event):
                observations.append((event["src_ip"], event["imsi"], _time(event)))
            if variant in CORRELATION_ONLY_VARIANTS:
                flood_sources.add(event["src_ip"])

            if variant in EXPECTATIONS:
                required, forbidden = EXPECTATIONS[variant]
                if not required <= matched or matched & forbidden:
                    violations.append((event["event_id"], variant, sorted(matched)))

    return total, unmatched, violations, by_variant, exhaustion_sources(observations), flood_sources


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

    total, unmatched, violations, by_variant, flagged, flood_sources = evaluate(args.input)
    matched_events = sum(s["alerts"] for s in by_variant.values())

    print_table(by_variant)
    print(f"\n{matched_events}/{total} events matched a per-event rule.")
    print(
        f"{len(flagged)} source IP(s) flagged by the exhaustion threshold "
        f"({THRESHOLD}+ distinct IMSIs in {WINDOW_SECONDS}s)."
    )

    if total == 0:
        print("FAIL: no events to evaluate.", file=sys.stderr)
        sys.exit(1)

    failed = False
    if args.expect == "alerts":
        for event_id, variant, matched in violations:
            print(f"FAIL: {variant} event {event_id} matched {matched}", file=sys.stderr)
        if unmatched:
            print(f"FAIL: {unmatched} attack event(s) matched no rule (missed detection).", file=sys.stderr)
        if flagged != flood_sources:
            print(f"FAIL: flagged sources {sorted(flagged)} != flood sources {sorted(flood_sources)}.", file=sys.stderr)
        failed = bool(unmatched or violations or flagged != flood_sources)
        if not failed:
            print("PASS: every attack tripped its rules, and the threshold flagged exactly the flood source.")
    else:
        if matched_events or flagged:
            print(f"FAIL: {matched_events} benign event(s) matched, {len(flagged)} source(s) flagged.", file=sys.stderr)
            failed = True
        else:
            print("PASS: no rule fired and no source was flagged on benign traffic (0 false positives).")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
