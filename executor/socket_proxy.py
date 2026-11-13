"""Docker Engine socket filter for the one Phase 4 supported action.

Only shopstack-api inspect and restart routes are forwarded. Inspection output
is projected to non-secret fields before it reaches the Executor.
"""
import json
import os
import re
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection

SOCKET_PATH = "/var/run/docker.sock"
ALLOWED_CONTAINER_NAME = os.getenv("ALLOWED_CONTAINER_NAME", "shopstack-api")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", ALLOWED_CONTAINER_NAME):
    raise RuntimeError("ALLOWED_CONTAINER_NAME must be a single safe container name")
ROUTE = re.compile(
    rf"^(?:/v[0-9]+(?:\.[0-9]+)?)?/containers/{re.escape(ALLOWED_CONTAINER_NAME)}/(json|restart)$"
)


class UnixHTTPConnection(HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(8)
        self.sock.connect(SOCKET_PATH)


def project_inspect(data):
    state = data.get("State") or {}
    config = data.get("Config") or {}
    host = data.get("HostConfig") or {}
    labels = config.get("Labels") or {}
    health = state.get("Health") or {}
    return {
        "id": data.get("Id", ""),
        "image": data.get("Image", ""),
        "config": {"labels": {"org.opencontainers.image.version": labels.get("org.opencontainers.image.version")}},
        "host_config": {"restart_policy": {"name": ((host.get("RestartPolicy") or {}).get("Name"))}},
        "state": {"running": state.get("Running") is True, "status": state.get("Status"),
                  "health": health.get("Status")},
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentShieldDockerFilter/1.0"
    sys_version = ""

    def _forward(self, method):
        path = self.path.split("?", 1)[0]
        match = ROUTE.fullmatch(path)
        if not match or (method == "GET" and match.group(1) != "json") or (method == "POST" and match.group(1) != "restart"):
            self.send_error(403, "Docker route is not allowed")
            return
        if method == "POST" and self.path != path:
            self.send_error(400, "Restart query parameters are fixed")
            return
        connection = UnixHTTPConnection("docker")
        try:
            docker_path = path
            if method == "POST":
                docker_path += "?t=5"
            connection.request(method, docker_path)
            response = connection.getresponse()
            body = response.read(2 * 1024 * 1024 + 1)
            if len(body) > 2 * 1024 * 1024:
                self.send_error(502, "Docker response exceeds size limit")
                return
            if method == "GET" and response.status == 200:
                try:
                    body = json.dumps(project_inspect(json.loads(body)), separators=(",", ":")).encode()
                except (ValueError, TypeError, AttributeError):
                    self.send_error(502, "Docker inspection response was invalid")
                    return
            self.send_response(response.status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if method == "GET" or response.status != 204:
                self.wfile.write(body)
        except (OSError, TimeoutError):
            self.send_error(502, "Docker socket is unavailable")
        finally:
            connection.close()

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def log_message(self, fmt, *args):
        # Do not log response bodies, query data, or Docker metadata.
        print("docker-filter request", self.command, self.path.split("?", 1)[0])


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 2375), Handler).serve_forever()
