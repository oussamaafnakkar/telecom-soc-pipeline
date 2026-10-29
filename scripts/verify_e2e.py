"""
verify_e2e.py

Checks that the running stack did its job end to end:

    generator -> JSON files -> Logstash -> Elasticsearch

It asks Elasticsearch four questions and fails loudly if any answer is wrong:

  1. Total documents == attack + benign   (nothing lost, nothing duplicated)
  2. Alert-tagged documents == attack     (the rule fired on all attack traffic)
  3. Alert-tagged AND trusted == 0        (no false positives)
  4. Untagged AND untrusted == 0          (no missed detections)

Standard library only. Runs inside the tools container on the compose network,
so Elasticsearch is reached by its service name.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
INDEX = "ss7-signaling-*"
TAG = "sigma_match_ss7_location_disclosure"
EXPECT_ATTACK = int(os.environ.get("EXPECT_ATTACK", "20"))
EXPECT_BENIGN = int(os.environ.get("EXPECT_BENIGN", "50"))
TIMEOUT_SECONDS = int(os.environ.get("VERIFY_TIMEOUT", "240"))


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


def count(query=None):
    body = {"query": query} if query else None
    return es("POST", f"/{INDEX}/_count", body)["count"]


def wait_for_documents(expected_total):
    """Poll until Logstash has indexed everything, or give up after the timeout."""
    deadline = time.time() + TIMEOUT_SECONDS
    last = "no response from Elasticsearch yet"
    while time.time() < deadline:
        try:
            es("POST", f"/{INDEX}/_refresh")
            total = count()
            last = f"{total}/{expected_total} documents indexed"
            if total >= expected_total:
                return True
        except (urllib.error.URLError, OSError, KeyError, ValueError) as error:
            last = f"waiting for Elasticsearch ({error})"
        print(f"  {last}", flush=True)
        time.sleep(5)
    print(f"Timed out: {last}", file=sys.stderr)
    return False


def main():
    expected_total = EXPECT_ATTACK + EXPECT_BENIGN
    print(f"Waiting for {expected_total} documents in {INDEX} ...")
    if not wait_for_documents(expected_total):
        sys.exit(1)

    tagged = {"match": {"tags": TAG}}
    checks = [
        ("total documents", count(), expected_total),
        ("alert-tagged documents", count(tagged), EXPECT_ATTACK),
        (
            "false positives (tagged but trusted)",
            count({"bool": {"must": [tagged, {"term": {"src_gt_trusted_partner": True}}]}}),
            0,
        ),
        (
            "missed detections (untagged but untrusted)",
            count({"bool": {"must": [{"term": {"src_gt_trusted_partner": False}}], "must_not": [tagged]}}),
            0,
        ),
    ]

    failed = False
    for name, actual, expected in checks:
        status = "PASS" if actual == expected else "FAIL"
        print(f"{status}  {name}: got {actual}, expected {expected}")
        failed = failed or actual != expected

    if failed:
        sys.exit(1)
    print("\nPASS: generator -> Logstash -> Elasticsearch tagged exactly the attack traffic.")


if __name__ == "__main__":
    main()
