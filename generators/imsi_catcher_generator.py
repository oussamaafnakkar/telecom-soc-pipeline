#!/usr/bin/env python3
"""
imsi_catcher_generator.py

Generates synthetic GSM cell measurements for the IMSI catcher scenario covered
in SBC post #6 (IMSI Catchers), Part 8: Detection.

One event is one snapshot of a serving cell, as a radio-monitoring sensor would
report it (a drive-test probe or RF-monitoring equipment). The fields match the
`CellMeasurement` dataclass in the post: LAC, cell id, signal strength,
encryption, whether the network authenticated the phone, neighbour count.

Two modes:
  --scenario attack  -> three kinds of rogue-cell behaviour (variants below).
  --scenario benign  -> normal cells plus the "Normal Cause" look-alikes from
                        the post's indicator table. Each benign variant trips
                        at most two weak indicators, which is exactly what the
                        rules must tolerate to avoid false positives.

Every event also carries two TEST LABELS, `fixture_label` and `fixture_variant`.
They exist only so the verifier knows the right answer. The detection rules
never read them.

Output: newline-delimited JSON, one event per line, to stdout or a file.

All identifiers are synthetic examples. Do not replace them with real cell
inventory data.
"""

import argparse
import json
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta

# Operator cell inventory: stand-in for the lookup a real pipeline does against
# the operator's network inventory. (mcc, mnc, lac, cell_id, arfcn).
# 604-01-1201-44231 is the example cell used in post 6.
INVENTORY = [
    (604, 1, 1201, 44231, 975),  # Maroc Telecom (example)
    (604, 1, 1202, 44232, 977),
    (604, 0, 3301, 10477, 62),   # Orange Maroc (example)
    (604, 0, 3302, 10478, 64),
    (604, 2, 5102, 20881, 106),  # Inwi (example)
]

# LAC values that post 6 lists as fingerprints of research-grade catchers (IND-01).
SUSPICIOUS_LACS = [0, 1, 0xFFFD, 0xFFFE, 0xFFFF]

SENSORS = ["sensor-casa-01", "sensor-rabat-01", "sensor-tanger-01"]


def _rssi(rng, low, high):
    return round(rng.uniform(low, high), 1)


def _known_cell(rng):
    mcc, mnc, lac, cell_id, arfcn = rng.choice(INVENTORY)
    return {"mcc": mcc, "mnc": mnc, "lac": lac, "cell_id": cell_id, "arfcn": arfcn}


def _unknown_cell(rng):
    """A cell that is not in the inventory, on a plausible LAC of a real carrier."""
    mcc, mnc, lac, _, arfcn = rng.choice(INVENTORY)
    return {"mcc": mcc, "mnc": mnc, "lac": lac, "cell_id": rng.randint(60000, 65000), "arfcn": arfcn}


# ---------------------------------------------------------------- benign variants


def normal_macro(rng):
    """An ordinary urban macro cell. Trips no indicator."""
    return {
        **_known_cell(rng),
        "rssi_dbm": _rssi(rng, -85, -65),
        "encryption": rng.choice(["A5/1", "A5/3"]),
        "auth_requested": True,
        "neighbor_count": rng.randint(4, 6),
        "ta_value": rng.randint(2, 12),
        "cell_in_inventory": True,
    }


def rural_isolated(rng):
    """Isolated rural cell with a thin neighbour list. Trips IND-05 only."""
    return {**normal_macro(rng), "neighbor_count": rng.randint(0, 1), "rssi_dbm": _rssi(rng, -95, -80)}


def new_tower(rng):
    """A newly built tower not yet in the inventory, strong signal. Trips IND-06 only."""
    return {
        **normal_macro(rng),
        **_unknown_cell(rng),
        "rssi_dbm": _rssi(rng, -54, -45),
        "cell_in_inventory": False,
    }


def roaming_partner_null_cipher(rng):
    """A foreign roaming-partner cell using A5/0. IND-03 only counts on Moroccan carriers."""
    return {
        "mcc": 214,
        "mnc": 1,
        "lac": rng.randint(8000, 8999),
        "cell_id": rng.randint(1000, 9999),
        "arfcn": rng.randint(1, 124),
        "rssi_dbm": _rssi(rng, -85, -70),
        "encryption": "A5/0",
        "auth_requested": True,
        "neighbor_count": rng.randint(3, 5),
        "ta_value": rng.randint(2, 12),
        "cell_in_inventory": False,
    }


def congestion_no_auth(rng):
    """Congested cell that skipped authentication. Trips IND-04 only."""
    return {**normal_macro(rng), "auth_requested": False}


def rural_new_tower(rng):
    """New tower in a rural area: unknown, strong, thin neighbours. Trips IND-05 and IND-06."""
    return {**new_tower(rng), "neighbor_count": rng.randint(0, 1)}


def congested_rural_cell(rng):
    """Known rural cell, congested: no auth and thin neighbours. Trips IND-04 and IND-05."""
    return {**rural_isolated(rng), "auth_requested": False}


BENIGN_VARIANTS = [
    ("normal_macro", normal_macro),
    ("rural_isolated", rural_isolated),
    ("new_tower", new_tower),
    ("roaming_partner_null_cipher", roaming_partner_null_cipher),
    ("congestion_no_auth", congestion_no_auth),
    ("rural_new_tower", rural_new_tower),
    ("congested_rural_cell", congested_rural_cell),
]


# ---------------------------------------------------------------- attack variants


def research_grade(rng):
    """The sweep from post 6: fingerprint LAC, null cipher, no auth, no neighbours."""
    return {
        "mcc": 604,
        "mnc": rng.choice([0, 1, 2]),
        "lac": rng.choice(SUSPICIOUS_LACS),
        "cell_id": rng.randint(1, 100),
        "arfcn": rng.choice([975, 62, 106]),
        "rssi_dbm": _rssi(rng, -54, -45),
        "encryption": "A5/0",
        "auth_requested": False,
        "neighbor_count": 0,
        "ta_value": 0,
        "cell_in_inventory": False,
    }


def stealth_combo(rng):
    """A catcher that avoids the obvious fingerprints: believable LAC, real cipher name.

    It still cannot authenticate, hides its neighbours and broadcasts loudly from
    an unknown cell, so it trips IND-04, IND-05 and IND-06 together.
    """
    return {
        **_unknown_cell(rng),
        "rssi_dbm": _rssi(rng, -54, -46),
        "encryption": rng.choice(["A5/1", "A5/3"]),
        "auth_requested": False,
        "neighbor_count": rng.randint(0, 1),
        "ta_value": rng.randint(0, 2),
        "cell_in_inventory": False,
    }


def downgrade_only(rng):
    """A catcher that only forces the null cipher on a Moroccan carrier (IND-03)."""
    return {
        **_unknown_cell(rng),
        "rssi_dbm": _rssi(rng, -80, -65),
        "encryption": "A5/0",
        "auth_requested": True,
        "neighbor_count": rng.randint(3, 5),
        "ta_value": rng.randint(2, 8),
        "cell_in_inventory": False,
    }


ATTACK_VARIANTS = [
    ("research_grade", research_grade),
    ("stealth_combo", stealth_combo),
    ("downgrade_only", downgrade_only),
]


def generate(scenario, count, start, rng):
    variants = ATTACK_VARIANTS if scenario == "attack" else BENIGN_VARIANTS
    events = []
    ts = start
    for i in range(count):
        name, build = variants[i % len(variants)]
        event = {
            "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "sensor_id": rng.choice(SENSORS),
            **build(rng),
            "fixture_label": scenario,
            "fixture_variant": name,
            "source": "imsi_catcher_generator.py",
        }
        events.append(event)
        # Attack sweeps are quick; normal measurements are sparse.
        ts += timedelta(seconds=rng.uniform(0.2, 2.0) if scenario == "attack" else rng.uniform(5, 60))
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", choices=["attack", "benign"], required=True)
    parser.add_argument("--count", type=int, default=25, help="number of events to generate")
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
