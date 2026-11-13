import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg
import redis

SERVICE_NAME = "shopstack-worker"
FAILURE_KEY = "shopstack:failure:worker_job_failure"
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack")
METRICS_PORT = int(os.getenv("WORKER_METRICS_PORT", "8004"))
metrics = {"status": "starting", "processed_orders": 0, "failed_orders": 0, "jobs_total": 0, "last_job_at": None}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(SERVICE_NAME)

def log_event(event, **fields):
    print(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "level": "INFO", "service": SERVICE_NAME, "event": event, **fields}), flush=True)

class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in {"/health", "/metrics"}:
            self.send_error(404)
            return
        body = json.dumps({"service": SERVICE_NAME, **metrics}).encode()
        self.send_response(200 if metrics["status"] == "healthy" else 503)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        return

def start_metrics_server():
    server = ThreadingHTTPServer(("0.0.0.0", METRICS_PORT), MetricsHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

def update_order_status(order_id, status):
    with psycopg.connect(DATABASE_URL) as conn:
        result = conn.execute("UPDATE orders SET status=%s WHERE id=%s", (status, order_id))
        if result.rowcount == 0:
            raise ValueError(f"Order not found: {order_id}")

def main():
    start_metrics_server()
    client = redis.Redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=5,
    socket_timeout=10,
    health_check_interval=30,
    )
    client.ping()
    metrics["status"] = "healthy"
    log_event("worker_started", redis="connected")
    while True:
        job = client.blpop("shopstack:jobs", timeout=5)
        if job is None:
            continue
        _, payload = job
        order_id = None
        metrics["jobs_total"] += 1
        metrics["last_job_at"] = datetime.now(timezone.utc).isoformat()
        try:
            order = json.loads(payload)
            order_id = order["order_id"]
            log_event("job_started", job_type="process_order", order_id=order_id)
            update_order_status(order_id, "processing")
            if client.get(FAILURE_KEY):
                raise RuntimeError("Injected worker job failure")
            time.sleep(2)
            update_order_status(order_id, "completed")
            metrics["processed_orders"] += 1
            client.incr("shopstack:processed_orders")
            log_event("job_completed", job_type="process_order", order_id=order_id)
        except Exception:
            logger.exception("Job processing failed")
            metrics["failed_orders"] += 1
            if order_id:
                try:
                    update_order_status(order_id, "failed")
                except Exception:
                    logger.exception("Could not update failed order status")
            client.incr("shopstack:failed_orders")

if __name__ == "__main__":
    main()
