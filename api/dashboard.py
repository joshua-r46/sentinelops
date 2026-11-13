"""Read only dashboard adapter over the existing ShopStack service APIs."""
import asyncio
import os

import httpx
from fastapi import APIRouter

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

TARGETS = {
    "api": ("SHOPSTACK_API_INTERNAL_URL", "http://api:8000", "/health"),
    "agentshield": ("AGENTSHIELD_URL", "http://agentshield:8002", "/health"),
    "deployer": ("DEPLOYER_URL", "http://deployer:8001", "/health"),
    "deployments": ("DEPLOYER_URL", "http://deployer:8001", "/deployments"),
    "worker": ("WORKER_URL", "http://worker:8004", "/metrics"),
    "safety_gate": ("SAFETY_GATE_URL", "http://agentshield-policy:8003", "/health"),
    "executor": ("EXECUTOR_URL", "http://agentshield-executor:8004", "/health"),
    "verifier": ("VERIFIER_URL", "http://agentshield-verifier:8005", "/health"),
    "snapshots": ("SNAPSHOT_URL", "http://agentshield-snapshot-manager:8006", "/health"),
    "recovery": ("RECOVERY_URL", "http://agentshield-recovery-policy:8007", "/health"),
    "incidents": ("AGENTSHIELD_URL", "http://agentshield:8002", "/incidents"),
}


async def _read(client: httpx.AsyncClient, key: str, target: tuple[str, str, str]):
    env_name, default, path = target
    url = os.getenv(env_name, default).rstrip("/") + path
    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
        if key == "api":
            data = {"status": "healthy", **data}
        return key, {"available": True, "http_status": response.status_code, "data": data}
    except (httpx.HTTPError, ValueError):
        return key, {"available": False, "http_status": None, "data": None}


def _object(result: dict, fields: tuple[str, ...]) -> dict:
    data = result.get("data")
    if not result.get("available") or not isinstance(data, dict):
        return {"available": False, "data": None}
    return {"available": True, "http_status": result["http_status"],
            "data": {field: data[field] for field in fields if field in data}}


def _rows(result: dict, fields: tuple[str, ...]) -> dict:
    data = result.get("data")
    if not result.get("available") or not isinstance(data, list):
        return {"available": False, "data": None}
    return {"available": True, "http_status": result["http_status"],
            "data": [{field: row[field] for field in fields if field in row}
                     for row in data if isinstance(row, dict)]}


@router.get("/overview")
async def overview():
    """Report live service data, with per-service unavailable states."""
    async with httpx.AsyncClient(timeout=2.5, trust_env=False) as client:
        results = dict(await asyncio.gather(*(_read(client, key, target)
                                              for key, target in TARGETS.items())))

    object_fields = {
        "api": ("status", "dependencies"),
        "agentshield": ("status", "mode"),
        "deployer": ("status",),
        "worker": ("status", "processed_orders", "failed_orders", "jobs_total", "last_job_at"),
        "safety_gate": ("status", "mode", "executor", "opa_configured"),
        "executor": ("status", "enabled", "supported_action"),
        "verifier": ("status",),
        "snapshots": ("status",),
        "recovery": ("status", "restoration_enabled", "production_execution_default"),
    }
    services = {name: _object(results[name], fields) for name, fields in object_fields.items()}
    incidents = _rows(results["incidents"],
                      ("id", "summary", "service_name", "kind", "state", "status", "first_seen_at", "last_seen_at"))
    deployments = _rows(results["deployments"],
                        ("deployment_id", "service_name", "version", "change_type", "status", "created_at", "previous_version"))
    return {
        "services": services,
        "incidents": incidents,
        "deployments": deployments,
        "capabilities": {
            "incident_read": incidents["available"],
            "deployment_read": deployments["available"],
            "approval_queue_read": False,
            "execution_history_read": False,
            "snapshot_catalog_read": False,
            "phase_6_4_verification": False,
        },
        "phase_status": {"implemented_through": "6.3", "phase_6_4": "pending"},
    }
