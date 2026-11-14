"""Authenticated facts ingress. Run behind TLS; agent and reader credentials differ."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError

from collector.models import DeviceSnapshot
from collector.store import SnapshotStore


MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_app(directory: Path, registry: dict[str, dict[str, Any]], read_token_hash: str) -> FastAPI:
    if not registry or not read_token_hash:
        raise ValueError("Collector requires registered devices and a reader credential")
    app = FastAPI(title="NetVuln device collector", docs_url=None, redoc_url=None)
    store = SnapshotStore(directory, registry)

    def authenticate(request: Request, expected: str) -> None:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token or not hmac.compare_digest(token_digest(token), expected):
            raise HTTPException(401, "Invalid collector credential")

    @app.get("/health")
    def health() -> dict:
        return {"status": "healthy", "schema_version": 1}

    @app.post("/v1/devices/{device_id}/snapshots")
    async def ingest(device_id: str, request: Request) -> dict:
        expected = registry.get(device_id)
        if expected is None:
            raise HTTPException(401, "Invalid collector credential")
        authenticate(request, expected["token_sha256"])
        raw = bytearray()
        async for block in request.stream():
            raw.extend(block)
            if len(raw) > MAX_SNAPSHOT_BYTES:
                raise HTTPException(413, "Snapshot exceeds size limit")
        try:
            snapshot = DeviceSnapshot.model_validate_json(bytes(raw))
        except ValidationError as exc:
            raise HTTPException(422, "Invalid device snapshot") from exc
        if snapshot.device_id != device_id:
            raise HTTPException(422, "Snapshot device identity differs from credential")
        if (snapshot.collected_at - datetime.now(timezone.utc)).total_seconds() > 120:
            raise HTTPException(422, "Snapshot timestamp is in the future")
        identity = store.save(snapshot)
        return {"accepted": True, "device_id": device_id, "snapshot_id": identity}

    @app.get("/v1/snapshot")
    def snapshot(request: Request) -> dict:
        authenticate(request, read_token_hash)
        return store.freeze()

    return app


def app_factory() -> FastAPI:
    settings = json.loads(Path(os.environ.get("COLLECTOR_CONFIG", "/etc/netvuln/collector.json")).read_text())
    return create_app(Path(settings["storage_dir"]), settings["devices"], settings["read_token_sha256"])
