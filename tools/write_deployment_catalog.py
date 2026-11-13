import json
import re
import sys
from pathlib import Path

ids_file, revision = Path(sys.argv[1]), sys.argv[2]
ids = ids_file.read_text().splitlines()
if len(ids) != 3 or any(not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) for image_id in ids):
    raise SystemExit("Expected three immutable local Docker image IDs")
versions = {}
for version, image_digest in zip(("v1", "v2", "v2-bad"), ids):
    versions[version] = {
        "image_digest": image_digest,
        "profile": {
            "config_revision": revision,
            "network": "shopstack_default",
            "environment": ["DATABASE_URL", "REDIS_URL", "FAILURE_INJECTOR_TOKEN"],
            "health_check": {"path": "/health", "port": 8000, "status": "healthy"},
            "resources": {"memory_bytes": 536870912, "nano_cpus": 1000000000},
            "mounts": [],
        },
    }
Path("deployment/catalog.json").write_text(json.dumps({"schema_version": 1, "config_revision": revision,
                                                          "versions": versions}, indent=2) + "\n")
