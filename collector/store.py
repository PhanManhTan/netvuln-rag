"""Immutable snapshots and explicit inventory coverage, independent of RAG."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from collector.models import DeviceSnapshot


class SnapshotStore:
    def __init__(self, directory: Path, registry: dict[str, dict[str, Any]]) -> None:
        self.directory = directory
        self.registry = registry

    def save(self, snapshot: DeviceSnapshot) -> str:
        if snapshot.device_id not in self.registry:
            raise ValueError("Unregistered device")
        value = snapshot.model_dump(mode="json")
        canonical = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        identity = hashlib.sha256(canonical).hexdigest()
        directory = self.directory / snapshot.device_id
        directory.mkdir(parents=True, exist_ok=True)
        destination = directory / f"{identity}.json"
        descriptor, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=directory)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(canonical)
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                if destination.read_bytes() != canonical:
                    raise ValueError("Snapshot integrity collision")
        finally:
            Path(temporary).unlink(missing_ok=True)
        return identity

    def latest(self, device_id: str) -> tuple[str, DeviceSnapshot] | None:
        if device_id not in self.registry:
            raise ValueError("Unregistered device")
        rows = []
        for path in (self.directory / device_id).glob("*.json"):
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != path.stem:
                raise ValueError(f"Stored snapshot integrity failure: {device_id}")
            snapshot = DeviceSnapshot.model_validate_json(raw)
            if snapshot.device_id != device_id:
                raise ValueError("Stored snapshot identity differs from directory")
            rows.append((path.stem, snapshot))
        return max(rows, key=lambda row: (row[1].collected_at, row[0])) if rows else None

    def freeze(self, max_age_seconds: int = 300, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        devices = []
        snapshots = []
        for device_id, expected in sorted(self.registry.items()):
            row = self.latest(device_id)
            problems: list[str] = []
            if row is None:
                devices.append({"device_id": device_id, "status": "missing", "problems": ["No snapshot received"]})
                continue
            identity, snapshot = row
            age = (now - snapshot.collected_at).total_seconds()
            if age < -120:
                problems.append("Snapshot timestamp is in the future")
            elif age > max_age_seconds:
                problems.append("Snapshot is stale")
            if snapshot.management_ip != expected["ip"]:
                problems.append("Management IP differs from registered target")
            if snapshot.collection_status != "collected" or snapshot.errors:
                problems.append("Collection is incomplete")
            matching = [software for software in snapshot.software if software.product_id == expected["product_id"] and software.evidence.get("scope") == "experiment_target"]
            if len(matching) != 1:
                problems.append("Expected one observed experiment component")
            else:
                observed = matching[0]
                if observed.version != expected["version"]:
                    problems.append("Observed version differs from experiment manifest")
                if observed.error or not observed.binary_sha256:
                    problems.append("Target binary evidence is missing or failed")
                if observed.running is not True:
                    problems.append("Experiment service is not running")
            devices.append({"device_id": device_id, "snapshot_id": identity, "age_seconds": age,
                            "status": "ready" if not problems else "incomplete", "problems": problems})
            snapshots.append({"snapshot_id": identity, **snapshot.model_dump(mode="json")})
        ready = sum(row["status"] == "ready" for row in devices)
        return {"schema_version": 1, "captured_at": now.isoformat(), "expected_devices": len(self.registry),
                "ready_devices": ready, "complete": ready == len(self.registry) and bool(self.registry),
                "devices": devices, "snapshots": snapshots}
