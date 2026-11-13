"""Fixed Docker socket filter and candidate-first API deployment operation."""
import hashlib
import hmac
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOCKET_PATH = "/var/run/docker.sock"
DOCKER_HOST = os.getenv("DOCKER_HOST", "")
CATALOG_FILE = os.getenv("DEPLOYMENT_CATALOG_FILE", "/etc/agentshield/deployment-catalog.json")
PROXY_TOKEN = os.getenv("PROXY_AUTH_TOKEN", "")
ROUTER_SECRET = os.getenv("ROUTER_CONTROL_SECRET", "")
DEPLOYMENT_ENABLED = os.getenv("DEPLOYMENT_ENABLED", "false").lower() == "true"
ROUTER_URL = os.getenv("ROUTER_URL", "http://api:8000").rstrip("/")
RUN_LABEL_KEY = os.getenv("DEPLOYMENT_RUN_LABEL_KEY", "")
RUN_LABEL_VALUE = os.getenv("DEPLOYMENT_RUN_LABEL_VALUE", "")
RUN_RESOURCE_LABEL_KEY = os.getenv("DEPLOYMENT_RESOURCE_LABEL_KEY", "")
RUN_RESOURCE_LABEL_VALUE = os.getenv("DEPLOYMENT_RESOURCE_LABEL_VALUE", "")
NETWORK = os.getenv("DEPLOYMENT_NETWORK", "")
DATABASE_URL = os.getenv("API_DATABASE_URL", "")
REDIS_URL = os.getenv("API_REDIS_URL", "")
LEGACY_CONTAINER = os.getenv("ALLOWED_CONTAINER_NAME", "shopstack-api")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
VERSION_SET = {"v1", "v2", "v2-bad"}
ROUTE = re.compile(rf"^(?:/v[0-9]+(?:\.[0-9]+)?)?/containers/{re.escape(LEGACY_CONTAINER)}/(json|restart)$")


class DeploymentFailure(RuntimeError):
    def __init__(self, code, compensation=None):
        super().__init__(code)
        self.code = code
        self.compensation = compensation


def load_catalog():
    with open(CATALOG_FILE, encoding="utf-8") as stream:
        catalog = json.load(stream)
    if set(catalog.get("versions", {})) != VERSION_SET:
        raise RuntimeError("Deployment catalog must contain exactly v1, v2 and v2-bad")
    for version, entry in catalog["versions"].items():
        digest = entry.get("image_digest", "")
        profile = entry.get("profile", {})
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise RuntimeError(f"Catalog image digest is invalid for {version}")
        if profile.get("config_revision") != catalog.get("config_revision"):
            raise RuntimeError("Catalog profile revision mismatch")
        if set(profile.get("environment", [])) != {"DATABASE_URL", "REDIS_URL", "FAILURE_INJECTOR_TOKEN"}:
            raise RuntimeError("Catalog environment references are invalid")
        resources = profile.get("resources", {})
        if not isinstance(resources.get("memory_bytes"), int) or not 16 * 1024 * 1024 <= resources["memory_bytes"] <= 2 * 1024**3:
            raise RuntimeError("Catalog memory limit is invalid")
        if not isinstance(resources.get("nano_cpus"), int) or not 100_000_000 <= resources["nano_cpus"] <= 8_000_000_000:
            raise RuntimeError("Catalog CPU limit is invalid")
    return catalog


class UnixHTTPConnection(HTTPConnection):
    def connect(self):
        if DOCKER_HOST.startswith("tcp://"):
            host, port = DOCKER_HOST[6:].rsplit(":", 1)
            self.sock = socket.create_connection((host, int(port)), timeout=8)
            return
        if not DOCKER_HOST:
            raise RuntimeError("Explicit isolated Docker endpoint is required")
        if not DOCKER_HOST.startswith("unix://"):
            raise RuntimeError("Unsupported Docker endpoint scheme")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(8)
        self.sock.connect(DOCKER_HOST[7:] or SOCKET_PATH)


def docker(method, path, payload=None):
    connection = UnixHTTPConnection("docker")
    body = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    try:
        connection.request(method, path, body=body, headers={"Content-Type": "application/json"} if body else {})
        response = connection.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise RuntimeError("Docker response exceeds size limit")
        return response.status, raw
    finally:
        connection.close()


def router_switch(version, candidate_id):
    body = json.dumps({"version": version, "candidate_id": candidate_id}, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(ROUTER_SECRET.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(ROUTER_URL + "/__control/switch", data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Router-Signature": signature})
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("Router rejected upstream switch")
        response.read(4096)


def router_state():
    with urllib.request.urlopen(ROUTER_URL + "/__deployment", timeout=5) as response:
        data = json.loads(response.read(8192))
    version, candidate_id = data.get("version"), data.get("candidate_id")
    if version not in VERSION_SET or (candidate_id is not None and not re.fullmatch(r"as-api-candidate-[a-f0-9]{32}", candidate_id)):
        raise RuntimeError("Router returned an invalid active deployment")
    return version, candidate_id


def wait_healthy(url, attempts=12):
    for index in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200 and json.loads(response.read(8192)).get("status") == "healthy":
                    return True
        except (OSError, ValueError, urllib.error.URLError):
            pass
        if index + 1 < attempts:
            time.sleep(1)
    return False


def restore(version):
    catalog = load_catalog()
    if version not in VERSION_SET:
        raise ValueError("Unsupported deployment version")
    if not NAME_RE.fullmatch(NETWORK) or not ROUTER_SECRET or not DATABASE_URL or not REDIS_URL:
        raise RuntimeError("Deployment profile runtime is not configured")
    entry = catalog["versions"][version]
    image = entry["image_digest"]
    if entry["profile"].get("network") != NETWORK:
        raise RuntimeError("Requested deployment network does not match the approved profile")
    status, raw = docker("GET", "/images/" + urllib.parse.quote(image, safe=":") + "/json")
    if status != 200:
        raise RuntimeError("Approved local deployment image is missing")
    image_info = json.loads(raw)
    if image_info.get("Id") != image:
        raise RuntimeError("Approved local image identity changed")
    prior_version, prior_candidate = router_state()
    candidate = "as-api-candidate-" + uuid.uuid4().hex
    profile = entry["profile"]
    resources = profile["resources"]
    env_values = {"DATABASE_URL": DATABASE_URL, "REDIS_URL": REDIS_URL,
                  "FAILURE_INJECTOR_TOKEN": os.getenv("FAILURE_INJECTOR_TOKEN", "")}
    if any(not isinstance(env_values[key], str) for key in profile["environment"]):
        raise RuntimeError("Deployment environment is invalid")
    body = {"Image": image, "Env": [key + "=" + env_values[key] for key in profile["environment"]],
            "Labels": {"agentshield.managed": "phase6.3", "agentshield.version": version},
            "ExposedPorts": {"8000/tcp": {}},
            "HostConfig": {"NetworkMode": NETWORK, "Memory": resources["memory_bytes"],
                           "NanoCpus": resources["nano_cpus"], "ReadonlyRootfs": True,
                           "SecurityOpt": ["no-new-privileges:true"], "RestartPolicy": {"Name": "no"}},
            "NetworkingConfig": {"EndpointsConfig": {NETWORK: {"Aliases": [candidate]}}}}
    if RUN_LABEL_KEY or RUN_LABEL_VALUE:
        if RUN_LABEL_KEY != "agentshield.phase6.3.integration.run" or not re.fullmatch(r"[A-Za-z0-9-]{8,100}", RUN_LABEL_VALUE):
            raise RuntimeError("Disposable deployment label is invalid")
        body["Labels"][RUN_LABEL_KEY] = RUN_LABEL_VALUE
    if RUN_RESOURCE_LABEL_KEY or RUN_RESOURCE_LABEL_VALUE:
        if (RUN_RESOURCE_LABEL_KEY != "agentshield.phase6.3.integration.run"
                or not re.fullmatch(r"[A-Za-z0-9-]{8,100}", RUN_RESOURCE_LABEL_VALUE)):
            raise RuntimeError("Disposable daemon resource label is invalid")
        body["Labels"][RUN_RESOURCE_LABEL_KEY] = RUN_RESOURCE_LABEL_VALUE
    status, raw = docker("POST", "/containers/create?name=" + candidate, body)
    if status != 201:
        raise RuntimeError("Candidate container creation failed")
    try:
        status, _ = docker("POST", "/containers/" + candidate + "/start")
        if status not in (204, 304):
            raise RuntimeError("Candidate container did not start")
        if not wait_healthy("http://" + candidate + ":8000/health"):
            raise RuntimeError("Candidate health check failed")
    except Exception:
        docker("DELETE", "/containers/" + candidate + "?force=true")
        raise

    try:
        router_switch(version, candidate)
        if not wait_healthy(ROUTER_URL + "/health", attempts=4):
            raise RuntimeError("API router health check failed after cutover")
    except Exception:
        compensated = False
        try:
            router_switch(prior_version, prior_candidate)
            compensated = wait_healthy(ROUTER_URL + "/health", attempts=4)
        except Exception:
            compensated = False
        if compensated:
            docker("DELETE", "/containers/" + candidate + "?force=true")
        raise DeploymentFailure("cutover_failed", "succeeded" if compensated else "uncertain")
    return {"status": "candidate_active", "version": version, "image_digest": image,
            "config_revision": profile["config_revision"], "resource_limits": resources,
            "candidate_id": candidate, "incumbent_retained": True, "phase6_4_required": True}


def project_inspect(data):
    state = data.get("State") or {}
    config = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    labels = config.get("Labels") or {}
    health = state.get("Health") or {}
    return {"id": data.get("Id", ""), "image": data.get("Image", ""),
            "config": {"labels": {"org.opencontainers.image.version": labels.get("org.opencontainers.image.version")}},
            "host_config": {"restart_policy": {"name": ((host.get("RestartPolicy") or {}).get("Name"))}},
            "state": {"running": state.get("Running") is True, "status": state.get("Status"), "health": health.get("Status")}}


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentShieldDockerFilter/1.1"
    sys_version = ""

    def _json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        supplied = self.headers.get("X-Executor-Token", "")
        return len(PROXY_TOKEN.encode()) >= 32 and hmac.compare_digest(supplied, PROXY_TOKEN)

    def _forward(self, method):
        path = self.path.split("?", 1)[0]
        match = ROUTE.fullmatch(path)
        if not match or (method == "GET" and match.group(1) != "json") or (method == "POST" and match.group(1) != "restart"):
            self.send_error(403, "Docker route is not allowed"); return
        if method == "POST" and self.path != path:
            self.send_error(400, "Restart query parameters are fixed"); return
        status, body = docker(method, path + ("?t=5" if method == "POST" else ""))
        if method == "GET" and status == 200:
            try:
                body = json.dumps(project_inspect(json.loads(body)), separators=(",", ":")).encode()
            except (ValueError, TypeError, AttributeError):
                self.send_error(502, "Docker inspection response was invalid"); return
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if method == "GET" or status != 204:
            self.wfile.write(body)

    def do_GET(self):
        self._forward("GET")

    def do_POST_legacy(self):
        self._forward("POST")

    def log_message(self, fmt, *args):
        print("docker-filter request", self.command, self.path.split("?", 1)[0])

    def do_POST(self):
        if self.path == "/deployment/restore":
            self._deployment_post()
        else:
            self.do_POST_legacy()

    def _deployment_post(self):
        if self.path != "/deployment/restore":
            self.send_error(403, "Docker route is not allowed"); return
        if not DEPLOYMENT_ENABLED:
            self.send_error(503, "Deployment restoration is disabled"); return
        if not self._authorized():
            self.send_error(403, "Executor authorization is invalid"); return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1024:
                self.send_error(413, "Request exceeds size limit"); return
            request = json.loads(self.rfile.read(length))
            if (not isinstance(request, dict) or set(request) != {"version"}
                    or not isinstance(request["version"], str) or request["version"] not in VERSION_SET):
                self.send_error(422, "A typed deployment version is required"); return
            self._json(200, restore(request["version"]))
        except DeploymentFailure as exc:
            self._json(502, {"error": exc.code, "compensation": exc.compensation})
        except Exception as exc:
            self._json(502, {"error": type(exc).__name__})

    def do_DELETE(self):
        self.send_error(403, "Docker route is not allowed")


if __name__ == "__main__":
    if DEPLOYMENT_ENABLED and (len(PROXY_TOKEN.encode()) < 32 or len(ROUTER_SECRET.encode()) < 32):
        raise RuntimeError("Proxy and router authorization secrets must contain at least 32 bytes")
    ThreadingHTTPServer(("0.0.0.0", 2375), Handler).serve_forever()
