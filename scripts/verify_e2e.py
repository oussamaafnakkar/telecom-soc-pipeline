"""
verify_e2e.py

Checks that the running stack did its job end to end, for every scenario:

    generator -> JSON files -> Logstash -> Elasticsearch

For each scenario it asks Elasticsearch these questions and fails loudly if any
answer is wrong:

  1. Total documents == attack + benign    (nothing lost, nothing duplicated)
  2. Alert-tagged documents == attack      (the rules fired on all attack traffic)
  3. Tagged AND benign == 0                (no false positives)
  4. Untagged AND attack == 0              (no missed detections)
  5. Per attack variant: every event carries a rule that variant should trip
  6. If the scenario has a correlation rule: the number of IMSIs that carry both
     tags within the time window equals the number of full swaps

"Attack" and "benign" come from the ground truth of each scenario: the trusted
flag for SS7, and the `fixture_label` test label for IMSI catchers. The
detection rules never read those labels.

Standard library only. Runs inside the tools container on the compose network,
so Elasticsearch is reached by its service name.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

# The correlation logic lives in one place, next to the rules it implements.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "detections"))
from evaluate_sim_swap_rules import correlate

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
EXPECT_ATTACK = int(os.environ.get("EXPECT_ATTACK", "20"))
EXPECT_BENIGN = int(os.environ.get("EXPECT_BENIGN", "50"))
TIMEOUT_SECONDS = int(os.environ.get("VERIFY_TIMEOUT", "240"))

SS7_TAG = "sigma_match_ss7_location_disclosure"
IMSI_CRITICAL_TAG = "sigma_match_imsi_catcher_critical_indicator"
IMSI_WEAK_TAG = "sigma_match_imsi_catcher_weak_indicator_combo"
SIM_UL_TAG = "sigma_match_sim_swap_update_location_untrusted"
SIM_CFU_TAG = "sigma_match_sim_swap_register_ss_cfu_untrusted"

SCENARIOS = [
    {
        "name": "SS7 location disclosure",
        "index": "ss7-signaling-*",
        "alert_tags": [SS7_TAG],
        "attack": {"term": {"src_gt_trusted_partner": False}},
        "benign": {"term": {"src_gt_trusted_partner": True}},
        "variants": {},
    },
    {
        "name": "SIM swap (SS7 technical path)",
        "index": "sim-swap-*",
        "alert_tags": [SIM_UL_TAG, SIM_CFU_TAG],
        "attack": {"match": {"fixture_label": "attack"}},
        "benign": {"match": {"fixture_label": "benign"}},
        # variant -> tags, any one of which each event of that variant must carry
        "variants": {
            "ul_only": [SIM_UL_TAG],
            "register_ss_only": [SIM_CFU_TAG],
            "full_swap": [SIM_UL_TAG, SIM_CFU_TAG],
        },
        # sim-swap-correlation.yml: both tags on one IMSI within 60 s. Each
        # full swap is two events, so the expected count is half of them.
        "correlation": {"tag_a": SIM_UL_TAG, "tag_b": SIM_CFU_TAG, "variant": "full_swap", "events_per_incident": 2},
    },
    {
        "name": "IMSI catcher indicators",
        "index": "imsi-catcher-*",
        "alert_tags": [IMSI_CRITICAL_TAG, IMSI_WEAK_TAG],
        "attack": {"match": {"fixture_label": "attack"}},
        "benign": {"match": {"fixture_label": "benign"}},
        # variant -> tags, any one of which each event of that variant must carry
        "variants": {
            "research_grade": [IMSI_CRITICAL_TAG],
            "stealth_combo": [IMSI_WEAK_TAG],
            "downgrade_only": [IMSI_CRITICAL_TAG],
        },
    },
]


def es(method, path, body=None):
    """Send one request to Elasticsearch and return the decoded JSON reply."""
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(ES_URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def count(index, query=None):
    body = {"query": query} if query else None
    return es("POST", f"/{index}/_count", body)["count"]


def has_tag(tag):
    return {"match": {"tags": tag}}


def any_tag(tags):
    return {"bool": {"should": [has_tag(t) for t in tags], "minimum_should_match": 1}}


def tagged_hits(index, tag):
    """(imsi, time) for every document carrying `tag`. Fixtures are tiny, so one page is enough."""
    body = {"size": 1000, "_source": ["imsi", "@timestamp"], "query": has_tag(tag)}
    hits = es("POST", f"/{index}/_search", body)["hits"]["hits"]
    return [
        (h["_source"]["imsi"], datetime.fromisoformat(h["_source"]["@timestamp"]))
        for h in hits
    ]


def wait_for_documents(expected_total):
    """Poll until Logstash has indexed everything for every scenario, or time out."""
    deadline = time.time() + TIMEOUT_SECONDS
    status = "no response from Elasticsearch yet"
    while time.time() < deadline:
        try:
            parts = []
            done = True
            for s in SCENARIOS:
                es("POST", f"/{s['index']}/_refresh")
                n = count(s["index"])
                parts.append(f"{s['index']} {n}/{expected_total}")
                done = done and n >= expected_total
            status = ", ".join(parts)
            if done:
                return True
        except (urllib.error.URLError, OSError, KeyError, ValueError) as error:
            status = f"waiting for Elasticsearch ({error})"
        print(f"  {status}", flush=True)
        time.sleep(5)
    print(f"Timed out: {status}", file=sys.stderr)
    return False


def checks_for(scenario):
    """Return a list of (description, actual, expected) for one scenario."""
    index = scenario["index"]
    tagged = any_tag(scenario["alert_tags"])
    checks = [
        ("total documents", count(index), EXPECT_ATTACK + EXPECT_BENIGN),
        ("alert-tagged documents", count(index, tagged), EXPECT_ATTACK),
        (
            "false positives (tagged but benign)",
            count(index, {"bool": {"must": [tagged, scenario["benign"]]}}),
            0,
        ),
        (
            "missed detections (untagged but attack)",
            count(index, {"bool": {"must": [scenario["attack"]], "must_not": [tagged]}}),
            0,
        ),
    ]
    for variant, tags in scenario["variants"].items():
        in_variant = {"match": {"fixture_variant": variant}}
        total = count(index, in_variant)
        with_tag = count(index, {"bool": {"must": [in_variant, any_tag(tags)]}})
        # max(total, 1) makes a variant with zero events fail instead of pass.
        checks.append((f"variant {variant} carries {' or '.join(tags)}", with_tag, max(total, 1)))

    corr = scenario.get("correlation")
    if corr:
        in_variant = {"match": {"fixture_variant": corr["variant"]}}
        expected = count(index, in_variant) // corr["events_per_incident"]
        found = correlate(tagged_hits(index, corr["tag_a"]), tagged_hits(index, corr["tag_b"]))
        checks.append(("correlated IMSIs (both rules within 60s)", len(found), expected))
    return checks


def main():
    expected_total = EXPECT_ATTACK + EXPECT_BENIGN
    print(f"Waiting for {expected_total} documents in each scenario index ...")
    if not wait_for_documents(expected_total):
        sys.exit(1)

    failed = False
    for scenario in SCENARIOS:
        print(f"\n== {scenario['name']} ({scenario['index']}) ==")
        for name, actual, expected in checks_for(scenario):
            status = "PASS" if actual == expected else "FAIL"
            print(f"{status}  {name}: got {actual}, expected {expected}")
            failed = failed or actual != expected

    if failed:
        sys.exit(1)
    print("\nPASS: generator -> Logstash -> Elasticsearch tagged exactly the attack traffic, in every scenario.")


if __name__ == "__main__":
    main()
