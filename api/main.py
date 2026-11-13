import json
import logging
import os
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import psycopg
import redis
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from dashboard import router as dashboard_router


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack",
)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
FAILURE_INJECTOR_TOKEN = os.getenv("FAILURE_INJECTOR_TOKEN", "")
FAILURE_PREFIX = "shopstack:failure:"


class JSONFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "service": "shopstack-api",
        }

        if isinstance(record.msg, dict):
            payload.update(record.msg)
        else:
            payload["message"] = record.getMessage()

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload)


logger = logging.getLogger("shopstack")
logger.setLevel(logging.INFO)
logger.handlers.clear()

handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
logger.propagate = False


metrics = {
    "requests_total": 0,
    "errors_total": 0,
    "total_latency_ms": 0.0,
}


redis_client = redis.Redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=5,
)


def get_db_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def initialize_database():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id UUID PRIMARY KEY,
                customer_name TEXT NOT NULL,
                items JSONB NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    redis_client.ping()
    logger.info({"event": "dependencies_connected"})
    yield
    redis_client.close()


app = FastAPI(
    title="ShopStack API",
    description="Target application monitored by AgentShield",
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(dashboard_router)


class OrderRequest(BaseModel):
    customer_name: str = Field(min_length=1, max_length=100)
    items: list[dict] = Field(min_length=1)


class FailureScenarioRequest(BaseModel):
    duration_seconds: int = Field(default=60, ge=1, le=300)


def require_injector_token(token: str | None):
    if not FAILURE_INJECTOR_TOKEN:
        raise HTTPException(status_code=404, detail="Failure injector is disabled")
    if token is None or not secrets.compare_digest(token, FAILURE_INJECTOR_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid failure injector token")


def failure_key(scenario: str):
    return f"{FAILURE_PREFIX}{scenario}"


def inject_order_failure_if_enabled():
    if redis_client.get(failure_key("api_order_error")):
        raise HTTPException(status_code=503, detail="Injected API order failure")
    latency = redis_client.get(failure_key("api_order_latency_ms"))
    if latency:
        time.sleep(min(int(latency), 5000) / 1000)


@app.middleware("http")
async def request_metrics(request: Request, call_next):
    start = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        elapsed = (time.perf_counter() - start) * 1000
        metrics["requests_total"] += 1
        metrics["errors_total"] += 1

        logger.exception({
            "event": "request_failed",
            "method": request.method,
            "path": request.url.path,
            "latency_ms": round(elapsed, 2),
        })
        raise

    elapsed = (time.perf_counter() - start) * 1000
    metrics["requests_total"] += 1
    metrics["total_latency_ms"] += elapsed

    if response.status_code >= 500:
        metrics["errors_total"] += 1

    logger.info({
        "event": "http_request",
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "latency_ms": round(elapsed, 2),
    })

    return response


@app.get("/")
async def root():
    return {
        "application": "ShopStack",
        "service": "api",
        "version": "1.0.0",
        "message": "ShopStack API is running",
    }


@app.get("/health")
def health():
    try:
        redis_client.ping()

        with get_db_connection() as conn:
            conn.execute("SELECT 1")

        return {
            "service": "api",
            "status": "healthy",
            "dependencies": {
                "redis": "connected",
                "postgres": "connected",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception:
        logger.exception({"event": "dependency_health_check_failed"})
        raise HTTPException(
            status_code=503,
            detail="A required dependency is unavailable",
        )


@app.post("/orders", status_code=201)
def create_order(order: OrderRequest):
    order_id = uuid.uuid4()

    try:
        inject_order_failure_if_enabled()
        with get_db_connection() as conn:
            conn.execute(
                """
                INSERT INTO orders (id, customer_name, items)
                VALUES (%s, %s, %s)
                """,
                (order_id, order.customer_name, Jsonb(order.items)),
            )

        job = {
            "order_id": str(order_id),
            "job_type": "process_order",
        }

        redis_client.rpush("shopstack:jobs", json.dumps(job))

        logger.info({
            "event": "order_created",
            "order_id": str(order_id),
        })

        return {
            "order_id": str(order_id),
            "status": "pending",
            "message": "Order accepted for processing",
        }

    except Exception:
        logger.exception({
            "event": "order_creation_failed",
            "order_id": str(order_id),
        })
        raise HTTPException(
            status_code=503,
            detail="Unable to accept order",
        )


@app.get("/failure-scenarios")
def list_failure_scenarios(x_failure_injector_token: str | None = Header(default=None)):
    require_injector_token(x_failure_injector_token)
    return {
        "api_order_error": bool(redis_client.get(failure_key("api_order_error"))),
        "api_order_latency_ms": redis_client.get(failure_key("api_order_latency_ms")),
        "worker_job_failure": bool(redis_client.get(failure_key("worker_job_failure"))),
    }


@app.post("/failure-scenarios/{scenario}")
def enable_failure_scenario(
    scenario: str,
    request: FailureScenarioRequest,
    x_failure_injector_token: str | None = Header(default=None),
):
    require_injector_token(x_failure_injector_token)
    if scenario == "api_order_error":
        value = "1"
    elif scenario == "api_order_latency_ms":
        value = "250"
    elif scenario == "worker_job_failure":
        value = "1"
    else:
        raise HTTPException(status_code=404, detail="Unknown failure scenario")
    redis_client.setex(failure_key(scenario), request.duration_seconds, value)
    return {"scenario": scenario, "enabled": True, "duration_seconds": request.duration_seconds}


@app.delete("/failure-scenarios/{scenario}")
def disable_failure_scenario(
    scenario: str,
    x_failure_injector_token: str | None = Header(default=None),
):
    require_injector_token(x_failure_injector_token)
    if scenario not in {"api_order_error", "api_order_latency_ms", "worker_job_failure"}:
        raise HTTPException(status_code=404, detail="Unknown failure scenario")
    redis_client.delete(failure_key(scenario))
    return {"scenario": scenario, "enabled": False}


@app.get("/orders/{order_id}")
def get_order(order_id: uuid.UUID):
    try:
        with get_db_connection() as conn:
            order = conn.execute(
                "SELECT * FROM orders WHERE id = %s",
                (order_id,),
            ).fetchone()

        if order is None:
            raise HTTPException(status_code=404, detail="Order not found")

        return order

    except HTTPException:
        raise
    except Exception:
        logger.exception({"event": "order_lookup_failed"})
        raise HTTPException(status_code=503, detail="Unable to retrieve order")


@app.get("/metrics")
async def get_metrics():
    total = metrics["requests_total"]

    return {
        "service": "api",
        "requests_total": total,
        "errors_total": metrics["errors_total"],
        "error_rate": round(
            metrics["errors_total"] / total, 4
        ) if total else 0,
        "average_latency_ms": round(
            metrics["total_latency_ms"] / total, 2
        ) if total else 0,
    }


@app.get("/test-error")
async def test_error():
    return JSONResponse(
        status_code=500,
        content={"error": "Intentional test error"},
    )
