"""Operator-only, bounded ShopStack failure injector.

This tool calls only the authenticated, TTL-bounded API controls.  It cannot
stop containers, remove volumes, exhaust host resources, or alter Docker.
"""
import argparse
import json
import urllib.request

SCENARIOS = {"api_order_error", "api_order_latency_ms", "worker_job_failure"}

parser = argparse.ArgumentParser()
parser.add_argument("scenario", choices=sorted(SCENARIOS))
parser.add_argument("--token", required=True)
parser.add_argument("--duration", type=int, default=60, choices=range(1, 301))
parser.add_argument("--url", default="http://localhost:8000")
args = parser.parse_args()
request = urllib.request.Request(
    f"{args.url}/failure-scenarios/{args.scenario}",
    data=json.dumps({"duration_seconds": args.duration}).encode(),
    headers={"content-type": "application/json", "X-Failure-Injector-Token": args.token},
    method="POST",
)
print(urllib.request.urlopen(request, timeout=5).read().decode())
