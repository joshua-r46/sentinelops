import os
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager

import psycopg
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://shopstack:shopstack_dev_password@postgres:5432/shopstack",
)


def get_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


@asynccontextmanager
async def lifespan(app: FastAPI):
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS deployment_ledger (
                id UUID PRIMARY KEY,
                service_name VARCHAR(100) NOT NULL,
                version VARCHAR(50) NOT NULL,
                change_type VARCHAR(50) NOT NULL,
                description TEXT,
                status VARCHAR(30) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )
            """
        )
        conn.execute(
            """
            ALTER TABLE deployment_ledger
                ADD COLUMN IF NOT EXISTS previous_version VARCHAR(50),
                ADD COLUMN IF NOT EXISTS requested_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS applied_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS failed_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS rolled_back_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS failure_reason TEXT
            """
        )
        conn.execute(
            "UPDATE deployment_ledger SET requested_at = created_at "
            "WHERE requested_at IS NULL"
        )

    yield


app = FastAPI(
    title="ShopStack Deployer",
    description="Simulated deployment service and change ledger",
    version="1.0.0",
    lifespan=lifespan,
)


class DeploymentRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=100)
    version: str = Field(min_length=1, max_length=50)
    previous_version: str | None = Field(default=None, max_length=50)
    change_type: str = Field(default="deployment", max_length=50)
    description: str = Field(default="", max_length=1000)


class FailureRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


def serialize(row):
    result = dict(row)
    result["deployment_id"] = str(result.pop("id"))
    return result


def fetch_deployment(deployment_id: uuid.UUID):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM deployment_ledger WHERE id = %s",
            (deployment_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Deployment not found")
    return row


def transition(deployment_id, allowed_from, target, fields):
    row = fetch_deployment(deployment_id)
    if row["status"] not in allowed_from:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot transition deployment from {row['status']} to {target}",
        )
    assignments = ["status = %s"]
    params = [target]
    for column, value in fields.items():
        assignments.append(f"{column} = %s")
        params.append(value)
    params.append(deployment_id)
    with get_connection() as conn:
        updated = conn.execute(
            f"UPDATE deployment_ledger SET {', '.join(assignments)} "
            "WHERE id = %s RETURNING *",
            params,
        ).fetchone()
    return serialize(updated)


@app.get("/health")
def health():
    try:
        with get_connection() as conn:
            conn.execute("SELECT 1")

        return {
            "service": "shopstack-deployer",
            "status": "healthy",
        }
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable",
        )


@app.post("/deployments", status_code=201)
def create_deployment(request: DeploymentRequest):
    deployment_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)

    try:
        with get_connection() as conn:
            row = conn.execute(
                """
                INSERT INTO deployment_ledger (
                    id,
                    service_name,
                    version,
                    change_type,
                    description,
                    status,
                    created_at,
                    requested_at,
                    previous_version
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (
                    deployment_id,
                    request.service_name,
                    request.version,
                    request.change_type,
                    request.description,
                    "requested",
                    created_at,
                    created_at,
                    request.previous_version,
                ),
            ).fetchone()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not record deployment",
        ) from exc

    return serialize(row)


@app.get("/deployments")
def list_deployments():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM deployment_ledger
            ORDER BY created_at DESC
            """
        ).fetchall()

    return [
        serialize(row)
        for row in rows
    ]


@app.get("/deployments/{deployment_id}")
def get_deployment(deployment_id: uuid.UUID):
    return serialize(fetch_deployment(deployment_id))


@app.post("/deployments/{deployment_id}/approve")
def approve_deployment(deployment_id: uuid.UUID):
    return transition(deployment_id, {"requested"}, "approved", {"approved_at": datetime.now(timezone.utc)})


@app.post("/deployments/{deployment_id}/apply")
def apply_deployment(deployment_id: uuid.UUID):
    """Records an operator-applied change only; it never changes live services."""
    return transition(deployment_id, {"approved"}, "applied", {"applied_at": datetime.now(timezone.utc)})


@app.post("/deployments/{deployment_id}/verify")
def verify_deployment(deployment_id: uuid.UUID):
    return transition(deployment_id, {"applied"}, "verified", {"verified_at": datetime.now(timezone.utc)})


@app.post("/deployments/{deployment_id}/fail")
def fail_deployment(deployment_id: uuid.UUID, failure: FailureRequest):
    return transition(
        deployment_id,
        {"requested", "approved", "applied"},
        "failed",
        {"failed_at": datetime.now(timezone.utc), "failure_reason": failure.reason},
    )


@app.post("/deployments/{deployment_id}/rollback")
def rollback_deployment(deployment_id: uuid.UUID):
    row = fetch_deployment(deployment_id)
    if not row["previous_version"]:
        raise HTTPException(status_code=422, detail="previous_version is required before a rollback can be recorded")
    return transition(
        deployment_id,
        {"applied", "failed"},
        "rolled_back",
        {"rolled_back_at": datetime.now(timezone.utc)},
    )
