import json
import os
import urllib.error
import urllib.request

BASE = os.environ["API_BASE"]
PROXY = os.environ["PROXY_BASE"]
TOKEN = os.environ["PROXY_TOKEN"]
with open(os.environ["CATALOG_FILE"], encoding="utf-8") as stream:
    catalog = json.load(stream)


def call(url, method="GET", data=None, token=None):
    payload = json.dumps(data).encode() if data is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["X-Executor-Token"] = token
    req = urllib.request.Request(url, data=payload, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


status, _ = call(PROXY + "/deployment/restore", "POST", {"version": "v2"})
assert status == 403, f"unauthenticated proxy request returned {status}"
status, _ = call(PROXY + "/deployment/restore", "POST", {"version": "v2", "image": "hostile"}, TOKEN)
assert status == 422, f"untyped proxy request returned {status}"
status, _ = call(BASE + "/__control/switch", "POST", {"version": "v2", "candidate_id": None})
assert status == 401, f"unauthenticated router switch returned {status}"

for version in ("v2", "v2-bad", "v1"):
    status, body = call(PROXY + "/deployment/restore", "POST", {"version": version}, TOKEN)
    assert status == 200, f"restore {version} returned {status}: {body!r}"
    result = json.loads(body)
    assert result["status"] == "candidate_active"
    assert result["incumbent_retained"] is True
    assert result["phase6_4_required"] is True
    assert result["image_digest"] == catalog["versions"][version]["image_digest"]
    assert result["config_revision"] == catalog["versions"][version]["profile"]["config_revision"]
    assert result["resource_limits"] == catalog["versions"][version]["profile"]["resources"]
    status, state = call(BASE + "/__deployment")
    assert status == 200 and json.loads(state)["version"] == version
    status, health = call(BASE + "/health")
    assert status == 200 and json.loads(health)["status"] == "healthy"
    if version == "v2-bad":
        status, _ = call(BASE + "/orders", "POST", {"customer_name": "Disposable", "items": [{"sku": "it"}]})
        assert status == 500, f"v2-bad did not reproduce its distinct failure: {status}"

print("Phase 6.3 disposable candidate-first routing passed for v1, v2 and v2-bad")
