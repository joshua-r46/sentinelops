import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import psycopg
import redis
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack",
)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")


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
    version="2.0.0",
    lifespan=lifespan,
)


class OrderRequest(BaseModel):
    customer_name: str = Field(min_length=1, max_length=100)
    items: list[dict] = Field(min_length=1)


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
        "version": "2.0.0",
        "message": "ShopStack API v2 is running",
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
