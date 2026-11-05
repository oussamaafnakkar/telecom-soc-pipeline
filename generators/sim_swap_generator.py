#!/usr/bin/env python3
"""
sim_swap_generator.py

Generates synthetic MAP signaling events for the SS7 technical path of the SIM
swap, as described in SBC post #8 (SIM Swapping), Part 3.

The attacker sends two kinds of MAP operations to the target HLR:
  UPDATE-LOCATION (opcode 2)  claims to be the new serving MSC, so SMS (and the
                              bank's OTP) is routed to the attacker.
  REGISTER-SS     (opcode 10) sets unconditional call forwarding (CFU, ss-Code
                              0x21 = 33) to the attacker's number, so calls
                              follow, and the rule outlives the connection.

One *incident* is the set of operations that belong together. Output is
newline-delimited JSON, one decoded MAP operation per line. `--count` is the
number of events. An incident is never split, so a count that is not a multiple
of the cycle is topped up with single-event incidents.

Attack incidents (each uses its own synthetic IMSI):
  ul_only           UPDATE-LOCATION from an untrusted GT. SMS hijack only.
  register_ss_only  REGISTER-SS CFU from an untrusted GT. Call hijack only.
  full_swap         both, a couple of seconds apart, same IMSI and same GT.
                    This is the full SIM swap signature from the post.

Benign incidents (the false-positive test), all from trusted nodes:
  roaming_update_location, roaming_register_ss_cfu, home_update_location,
  legit_cancel_location, traveler_lands_and_forwards (a roamer registers and then
  sets call forwarding seconds later: the same two operations as full_swap, from
  a trusted partner).

Every event carries test labels (`fixture_label`, `fixture_variant`,
`fixture_incident`) so the verifier knows the right answer. The rules never
read them. All identifiers are synthetic.
"""

import argparse
import json
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta

MAP_UPDATE_LOCATION = 2
MAP_CANCEL_LOCATION = 3
MAP_REGISTER_SS = 10
SS_CODE_CFU = 33  # 0x21, Call Forwarding Unconditional

HLR_GT = "212600000000"
HOME_MSC_GTS = ["212600100001", "212600100002"]

# Same stand-ins as the SS7 scenario: the operator's interconnect allowlist,
# and leased or spoofed GTs used for abuse.
TRUSTED_PARTNER_GTS = ["212661000001", "212661000002", "33660000001", "34911234567"]
ROGUE_GTS = ["882285000001", "999000000001", "255780000001"]

ATTACKER_NUMBERS = ["212700000001", "212700000002", "212700000003"]
VOICEMAIL_NUMBER = "212600999001"


def _subscriber(n):
    """A synthetic subscriber. IMSI = MCC 604 + MNC 01 + 10-digit MSIN."""
    return {"imsi": f"60401{1234500000 + n:010d}", "msisdn": f"2126{12345000 + n:08d}"}


def _op(opcode, name):
    return {"signaling_protocol": "MAP", "map_opcode": opcode, "map_operation": name}


def _update_location(sub, src_gt, trusted):
    return {
        **_op(MAP_UPDATE_LOCATION, "updateLocation"),
        **sub,
        "src_gt": src_gt,
        "dst_gt": HLR_GT,
        "src_gt_trusted_partner": trusted,
        "msc_number": src_gt,
        "vlr_number": src_gt,
    }


def _register_ss_cfu(sub, src_gt, trusted, forwarded_to):
    return {
        **_op(MAP_REGISTER_SS, "registerSS"),
        **sub,
        "src_gt": src_gt,
        "dst_gt": HLR_GT,
        "src_gt_trusted_partner": trusted,
        "ss_code": SS_CODE_CFU,
        "ss_name": "CFU",
        "forwarded_to_number": forwarded_to,
    }


def _cancel_location(sub, old_vlr):
    return {
        **_op(MAP_CANCEL_LOCATION, "cancelLocation"),
        **sub,
        "src_gt": HLR_GT,
        "dst_gt": old_vlr,
        "src_gt_trusted_partner": True,
        "cancellation_type": "updateProcedure",
    }


# Each incident returns a list of (delay_seconds_from_incident_start, event_fields).


def ul_only(rng, sub):
    return [(0.0, _update_location(sub, rng.choice(ROGUE_GTS), False))]


def register_ss_only(rng, sub):
    return [(0.0, _register_ss_cfu(sub, rng.choice(ROGUE_GTS), False, rng.choice(ATTACKER_NUMBERS)))]


def full_swap(rng, sub):
    gt = rng.choice(ROGUE_GTS)
    return [
        (0.0, _update_location(sub, gt, False)),
        (round(rng.uniform(1, 3), 2), _register_ss_cfu(sub, gt, False, rng.choice(ATTACKER_NUMBERS))),
    ]


def roaming_update_location(rng, sub):
    return [(0.0, _update_location(sub, rng.choice(TRUSTED_PARTNER_GTS), True))]


def roaming_register_ss_cfu(rng, sub):
    return [(0.0, _register_ss_cfu(sub, rng.choice(TRUSTED_PARTNER_GTS), True, VOICEMAIL_NUMBER))]


def home_update_location(rng, sub):
    return [(0.0, _update_location(sub, rng.choice(HOME_MSC_GTS), True))]


def legit_cancel_location(rng, sub):
    return [(0.0, _cancel_location(sub, rng.choice(TRUSTED_PARTNER_GTS)))]


def traveler_lands_and_forwards(rng, sub):
    gt = rng.choice(TRUSTED_PARTNER_GTS)
    return [
        (0.0, _update_location(sub, gt, True)),
        (round(rng.uniform(5, 20), 2), _register_ss_cfu(sub, gt, True, VOICEMAIL_NUMBER)),
    ]


# (name, builder, number of events the incident produces)
ATTACK_INCIDENTS = [("ul_only", ul_only, 1), ("register_ss_only", register_ss_only, 1), ("full_swap", full_swap, 2)]
BENIGN_INCIDENTS = [
    ("roaming_update_location", roaming_update_location, 1),
    ("roaming_register_ss_cfu", roaming_register_ss_cfu, 1),
    ("home_update_location", home_update_location, 1),
    ("legit_cancel_location", legit_cancel_location, 1),
    ("traveler_lands_and_forwards", traveler_lands_and_forwards, 2),
]


def generate(scenario, count, start, rng):
    incidents = ATTACK_INCIDENTS if scenario == "attack" else BENIGN_INCIDENTS
    events = []
    ts = start
    cycle = 0
    incident_no = 0
    while len(events) < count:
        name, build, size = incidents[cycle % len(incidents)]
        cycle += 1
        if size > count - len(events):
            # Never split an incident: use the first single-event one instead.
            name, build, size = next(i for i in incidents if i[2] == 1)
        for delay, fields in build(rng, _subscriber(incident_no)):
            events.append(
                {
                    "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
                    "@timestamp": (ts + timedelta(seconds=delay)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    **fields,
                    "fixture_label": scenario,
                    "fixture_variant": name,
                    "fixture_incident": incident_no,
                    "source": "sim_swap_generator.py",
                }
            )
        incident_no += 1
        # Attack incidents come in quick succession, normal traffic is sparse.
        ts += timedelta(seconds=rng.uniform(3, 10) if scenario == "attack" else rng.uniform(25, 90))
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=["attack", "benign"], required=True)
    parser.add_argument("--count", type=int, default=24, help="number of events to generate")
    parser.add_argument("--out", type=str, default=None, help="output file (default: stdout)")
    parser.add_argument("--seed", type=int, default=None, help="random seed for reproducible fixtures")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    events = generate(args.scenario, args.count, datetime.now(UTC), rng)

    lines = (json.dumps(e) + "\n" for e in events)
    if args.out:
        with open(args.out, "w") as out:
            out.writelines(lines)
    else:
        sys.stdout.writelines(lines)


if __name__ == "__main__":
    main()
