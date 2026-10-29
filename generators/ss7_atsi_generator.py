#!/usr/bin/env python3
"""
ss7_atsi_generator.py

Generates synthetic SS7/MAP signaling events representing the AnyTimeInterrogation
(ATSI) location-disclosure scenario covered in SBC post #2 (SS7 Location Disclosure).

Two modes:
  --scenario attack   -> ATSI requests from GTs outside the operator's trusted
                          interconnect partner list (the classic SS7 location
                          tracking abuse pattern: a rogue/leased GT queries
                          subscriber location via MAP ATSI).
  --scenario benign   -> ATSI requests from trusted roaming/interconnect partner
                          GTs, at normal volume. Used for false-positive testing
                          against the Sigma rule.

Output: newline-delimited JSON (one signaling event per line), written to stdout
or a file, matching the schema Logstash expects (see ingest/logstash/conf.d/ss7.conf).

This does NOT require a live SS7 network, a real TCAP/MAP stack, or Scapy's
(limited) SS7 support - it produces the *decoded event representation* a real
probe/mediation layer would emit, which is what actually lands in a SIEM. Byte-level
TCAP/MAP encoding is covered separately in the SBC blog post's own code samples;
this script's job is to produce realistic *events*, not raw wire bytes.
"""

import argparse
import json
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta

# MAP opcode 71 = anyTimeInterrogation (3GPP TS 29.002)
MAP_ATSI_OPCODE = 71
MAP_ATSI_OPNAME = "anyTimeInterrogation"

# Trusted interconnect partner Global Titles (operator's own allowlist).
# In production this comes from the operator's interconnect/roaming agreement
# registry, not a hardcoded list - treat this as the stand-in for that lookup.
TRUSTED_PARTNER_GTS = [
    "212661000001",  # Moroccan MNO roaming partner (example)
    "212661000002",
    "33660000001",   # French roaming partner (example)
    "34911234567",   # Spanish roaming partner (example)
]

# GTs used to simulate rogue/leased-signaling-point abuse - deliberately
# outside the trusted list, mimicking the real-world pattern of attackers
# leasing SS7 access from a loosely-vetted small operator.
ROGUE_GTS = [
    "882285000001",  # satellite/leased global-title block (example, non-attributable)
    "999000000001",  # unallocated/spoofed-looking GT
    "255780000001",  # example leased-access GT
]

SUBSCRIBER_MSISDNS = [
    "212661234567",
    "212662345678",
    "212663456789",
    "212664567890",
]


def make_event(src_gt: str, dst_gt: str, msisdn: str, trusted: bool, ts: datetime) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "signaling_protocol": "MAP",
        "tcap_package_type": "begin",
        "map_opcode": MAP_ATSI_OPCODE,
        "map_operation": MAP_ATSI_OPNAME,
        "src_gt": src_gt,
        "dst_gt": dst_gt,
        "target_msisdn": msisdn,
        "src_gt_trusted_partner": trusted,
        "requested_info": ["location-information", "subscriber-state"],
        "source": "ss7_atsi_generator.py",
    }


def generate_attack(count: int, start: datetime) -> list:
    """Bursts of ATSI requests from rogue GTs against multiple subscribers -
    the location-tracking abuse pattern the Sigma rule should catch."""
    events = []
    ts = start
    for _ in range(count):
        src_gt = random.choice(ROGUE_GTS)
        msisdn = random.choice(SUBSCRIBER_MSISDNS)
        events.append(make_event(src_gt, "212600000000", msisdn, trusted=False, ts=ts))
        ts += timedelta(seconds=random.uniform(0.2, 2.0))
    return events


def generate_benign(count: int, start: datetime) -> list:
    """Normal-volume ATSI traffic from trusted roaming/interconnect partners -
    legitimate roaming state checks. Used to prove the rule doesn't fire on this."""
    events = []
    ts = start
    for _ in range(count):
        src_gt = random.choice(TRUSTED_PARTNER_GTS)
        msisdn = random.choice(SUBSCRIBER_MSISDNS)
        events.append(make_event(src_gt, "212600000000", msisdn, trusted=True, ts=ts))
        ts += timedelta(seconds=random.uniform(5, 60))  # sparse, normal roaming cadence
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=["attack", "benign"], required=True)
    parser.add_argument("--count", type=int, default=25, help="number of events to generate")
    parser.add_argument("--out", type=str, default=None, help="output file (default: stdout)")
    parser.add_argument("--seed", type=int, default=None, help="random seed for reproducible test fixtures")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    start = datetime.now(UTC)
    if args.scenario == "attack":
        events = generate_attack(args.count, start)
    else:
        events = generate_benign(args.count, start)

    lines = (json.dumps(e) + "\n" for e in events)
    if args.out:
        with open(args.out, "w") as out:
            out.writelines(lines)
    else:
        sys.stdout.writelines(lines)


if __name__ == "__main__":
    main()
