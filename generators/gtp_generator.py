#!/usr/bin/env python3
"""
gtp_generator.py

Generates synthetic GTPv2-C events as a probe on the GRX/IPX border would log
them, for the attacks in SBC post #9 (GTP Security), Part 3:

  3a Create Session Request impersonation
  3b Modify Bearer Request redirecting an existing session
  3d Bearer table exhaustion (a flood of Create Session Requests)

3c (TEID spoofing in GTP-U) is not generated: it needs user-plane visibility
that a border signaling log does not have. See docs/mapping-table.md.

Each event is one decoded GTP-C message. Fields the probe adds from its peer
table (stand-ins for a real roaming-agreement lookup): `src_peer_plmn`, the
network the source IP belongs to, and `src_peer_trusted`, whether that network
has a roaming agreement.

Attack incidents:
  rogue_create_session     CSR from a peer with no roaming agreement, claiming
                           to be a serving network that is not its own.
  spoofed_serving_network  CSR from the compromised partner node, claiming another network.
  modify_bearer_hijack     Modify Bearer from a peer with no roaming agreement.
  bearer_flood             12 CSRs for 12 different IMSIs in seconds, from a
                           trusted partner node (a compromised partner), so no
                           single message looks wrong. Only the volume does.

Benign incidents (the false-positive test), all from trusted peers:
  roaming_create_session, sgw_handover_modify_bearer, delete_session,
  arrival_wave (8 different IMSIs in 30 s, e.g. a flight landing),
  csr_retransmission (one IMSI retrying 12 times, high volume but 1 subscriber).

Attack and benign fixtures use different IMSIs and different peers on purpose,
so a threshold rule counting across both files is not confused by the other.
(The first version let an attack borrow a legitimate partner's IP. In the shared
index it pushed that partner's arrival wave over the threshold. That is also how
a threshold produces false positives in production.)

Every event carries test labels (`fixture_label`, `fixture_variant`,
`fixture_incident`). The rules never read them. All identifiers are synthetic
(RFC 5737 documentation IP ranges).
"""

import argparse
import itertools
import json
import random
import sys
import uuid
from datetime import UTC, datetime, timedelta

GTP_CREATE_SESSION = 32
GTP_MODIFY_BEARER = 34
GTP_DELETE_SESSION = 36

HOME_PLMN = "60401"
PGW_IP = "192.0.2.10"
APN = "internet.iam.ma"
FLOOD_SIZE = 12  # more than the detection threshold of 10 distinct IMSIs

# Roaming partners with an agreement. (ip, plmn)
BENIGN_PEERS = [("198.51.100.10", "21407"), ("198.51.100.20", "20801")]
COMPROMISED_PEER = ("198.51.100.30", "21401")  # a trusted partner node that has been taken over
# Peers with no roaming agreement. The probe cannot map them to a network.
ROGUE_PEERS = [("203.0.113.50", "unknown"), ("203.0.113.51", "unknown"), ("203.0.113.52", "unknown")]

ATTACK_SUBSCRIBER_BASE = 0
BENIGN_SUBSCRIBER_BASE = 5000


def _subscriber(n):
    """A synthetic subscriber. IMSI = MCC 604 + MNC 01 + 10-digit MSIN."""
    return {"imsi": f"60401{1234500000 + n:010d}", "msisdn": f"2126{12345000 + n:08d}"}


def _message(msg_type, name, sub, peer, rng, **extra):
    ip, plmn, trusted = peer
    return {
        "signaling_protocol": "GTPv2-C",
        "gtp_message_type": msg_type,
        "gtp_message_name": name,
        **sub,
        "apn": APN,
        "rat_type": 6,
        "src_ip": ip,
        "src_peer_plmn": plmn,
        "src_peer_trusted": trusted,
        "dst_ip": PGW_IP,
        "sgw_fteid_ip": ip,
        "sgw_fteid_teid": rng.getrandbits(32),
        **extra,
    }


def _trusted(peer):
    return (peer[0], peer[1], True)


def _untrusted(peer):
    return (peer[0], peer[1], False)


def _create_session(sub, peer, claimed_plmn, rng):
    return _message(GTP_CREATE_SESSION, "CreateSessionRequest", sub, peer, rng, serving_network_plmn=claimed_plmn)


def _modify_bearer(sub, peer, rng):
    return _message(GTP_MODIFY_BEARER, "ModifyBearerRequest", sub, peer, rng)


# Each incident returns a list of (delay_seconds_from_incident_start, event_fields).
# `new_sub` hands out the next unused subscriber.


def rogue_create_session(rng, new_sub):
    peer = _untrusted(rng.choice(ROGUE_PEERS))
    # The attacker claims to be the home network itself, as in the post's example.
    return [(0.0, _create_session(new_sub(), peer, HOME_PLMN, rng))]


def spoofed_serving_network(rng, new_sub):
    # The same compromised partner node as the flood, never a legitimate partner's IP.
    peer = _trusted(COMPROMISED_PEER)
    return [(0.0, _create_session(new_sub(), peer, HOME_PLMN, rng))]


def modify_bearer_hijack(rng, new_sub):
    return [(0.0, _modify_bearer(new_sub(), _untrusted(rng.choice(ROGUE_PEERS)), rng))]


def bearer_flood(rng, new_sub):
    peer = _trusted(COMPROMISED_PEER)
    events = []
    delay = 0.0
    for _ in range(FLOOD_SIZE):
        events.append((round(delay, 2), _create_session(new_sub(), peer, peer[1], rng)))
        delay += rng.uniform(0.5, 3.0)
    return events


def roaming_create_session(rng, new_sub):
    peer = _trusted(rng.choice(BENIGN_PEERS))
    return [(0.0, _create_session(new_sub(), peer, peer[1], rng))]


def sgw_handover_modify_bearer(rng, new_sub):
    return [(0.0, _modify_bearer(new_sub(), _trusted(rng.choice(BENIGN_PEERS)), rng))]


def delete_session(rng, new_sub):
    peer = _trusted(rng.choice(BENIGN_PEERS))
    return [(0.0, _message(GTP_DELETE_SESSION, "DeleteSessionRequest", new_sub(), peer, rng))]


def arrival_wave(rng, new_sub):
    peer = _trusted(BENIGN_PEERS[0])
    events = []
    delay = 0.0
    for _ in range(8):
        events.append((round(delay, 2), _create_session(new_sub(), peer, peer[1], rng)))
        delay += rng.uniform(1.0, 5.0)
    return events


def csr_retransmission(rng, new_sub):
    peer = _trusted(BENIGN_PEERS[1])
    sub = new_sub()
    events = []
    delay = 0.0
    for _ in range(12):
        events.append((round(delay, 2), _create_session(sub, peer, peer[1], rng)))
        delay += rng.uniform(0.5, 3.0)
    return events


# (name, builder, number of events the incident produces)
ATTACK_INCIDENTS = [
    ("rogue_create_session", rogue_create_session, 1),
    ("spoofed_serving_network", spoofed_serving_network, 1),
    ("modify_bearer_hijack", modify_bearer_hijack, 1),
    ("bearer_flood", bearer_flood, FLOOD_SIZE),
]
BENIGN_INCIDENTS = [
    ("roaming_create_session", roaming_create_session, 1),
    ("sgw_handover_modify_bearer", sgw_handover_modify_bearer, 1),
    ("delete_session", delete_session, 1),
    ("arrival_wave", arrival_wave, 8),
    ("csr_retransmission", csr_retransmission, 12),
]


def generate(scenario, count, start, rng):
    incidents = ATTACK_INCIDENTS if scenario == "attack" else BENIGN_INCIDENTS
    subscribers = itertools.count(ATTACK_SUBSCRIBER_BASE if scenario == "attack" else BENIGN_SUBSCRIBER_BASE)

    def new_sub():
        return _subscriber(next(subscribers))

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
        for delay, fields in build(rng, new_sub):
            events.append(
                {
                    "event_id": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
                    "@timestamp": (ts + timedelta(seconds=delay)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    **fields,
                    "fixture_label": scenario,
                    "fixture_variant": name,
                    "fixture_incident": incident_no,
                    "source": "gtp_generator.py",
                }
            )
        incident_no += 1
        # Leave a gap after each incident so incidents do not run into each other.
        ts += timedelta(seconds=rng.uniform(70, 120) if size > 1 else rng.uniform(5, 20))
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
