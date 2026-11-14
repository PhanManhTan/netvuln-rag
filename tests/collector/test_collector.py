from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient
import pytest

from collector.models import DeviceSnapshot
from collector.server import create_app, token_digest
from collector.store import SnapshotStore


NOW = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)


def facts(identity="NGINX-A", version="1.24.0", now=NOW):
    return {"schema_version": 1, "device_id": identity, "collected_at": now.isoformat(), "boot_id": "test-boot",
            "management_ip": "10.53.20.10", "collection_status": "collected", "os": {"ID": "ubuntu"},
            "software": [{"product_id": "nginx", "component": "nginx", "version": version,
                          "binary": "/opt/netvuln/products/nginx/1.24.0/sbin/nginx", "binary_sha256": "a" * 64,
                          "running": True, "configuration": {}, "evidence": {"scope": "experiment_target"}}]}


def registry():
    return {"NGINX-A": {"product_id": "nginx", "version": "1.24.0", "ip": "10.53.20.10", "token_sha256": token_digest("agent-a")}}


def test_snapshots_are_immutable_idempotent_and_latest_uses_observation_time(tmp_path):
    store = SnapshotStore(tmp_path, registry())
    newest = DeviceSnapshot.model_validate(facts(now=NOW + timedelta(seconds=10)))
    identity = store.save(newest)
    assert store.save(newest) == identity
    store.save(DeviceSnapshot.model_validate(facts()))
    assert store.latest("NGINX-A")[0] == identity
    assert len(list((tmp_path / "NGINX-A").glob("*.json"))) == 2
    assert not list((tmp_path / "NGINX-A").glob(".snapshot-*"))
    assert store.freeze(now=NOW + timedelta(seconds=20))["complete"]


@pytest.mark.parametrize("condition", ["missing", "stale", "future", "version", "stopped", "partial", "ip", "ambiguous"])
def test_coverage_rejects_incomplete_inventory_instead_of_reporting_success(tmp_path, condition):
    store = SnapshotStore(tmp_path, registry())
    payload = facts()
    if condition == "stale":
        payload["collected_at"] = (NOW - timedelta(seconds=301)).isoformat()
    elif condition == "future":
        payload["collected_at"] = (NOW + timedelta(seconds=121)).isoformat()
    elif condition == "version":
        payload["software"][0]["version"] = "1.26.2"
    elif condition == "stopped":
        payload["software"][0]["running"] = False
    elif condition == "partial":
        payload["collection_status"] = "partial"
    elif condition == "ip":
        payload["management_ip"] = "10.53.20.99"
    elif condition == "ambiguous":
        payload["software"].append(payload["software"][0].copy())
    if condition != "missing":
        store.save(DeviceSnapshot.model_validate(payload))
    report = store.freeze(now=NOW)
    assert report["expected_devices"] == 1
    assert report["ready_devices"] == 0
    assert not report["complete"]


def test_tampered_snapshot_is_detected(tmp_path):
    store = SnapshotStore(tmp_path, registry())
    identity = store.save(DeviceSnapshot.model_validate(facts()))
    path = tmp_path / "NGINX-A" / f"{identity}.json"
    path.write_text(path.read_text().replace("1.24.0", "9.99.0"))
    with pytest.raises(ValueError, match="integrity"):
        store.freeze(now=NOW)


def test_ingress_credentials_cannot_read_inventory_or_impersonate_another_device(tmp_path):
    rows = registry()
    rows["NGINX-B"] = {**rows["NGINX-A"], "token_sha256": token_digest("agent-b")}
    client = TestClient(create_app(tmp_path, rows, token_digest("reader")))
    payload = facts(now=datetime.now(timezone.utc))
    endpoint = "/v1/devices/NGINX-A/snapshots"
    assert client.post(endpoint, json=payload).status_code == 401
    assert client.post(endpoint, json=payload, headers={"Authorization": "Bearer agent-b"}).status_code == 401
    assert client.post(endpoint, json=payload, headers={"Authorization": "Bearer reader"}).status_code == 401
    assert client.post(endpoint, json=payload, headers={"Authorization": "Bearer agent-a"}).status_code == 200
    assert client.get("/v1/snapshot", headers={"Authorization": "Bearer agent-a"}).status_code == 401
    response = client.get("/v1/snapshot", headers={"Authorization": "Bearer reader"})
    assert response.status_code == 200
    assert response.json()["expected_devices"] == 2
    assert not response.json()["complete"]
    assert "token_sha256" not in response.text
    payload["device_id"] = "NGINX-B"
    assert client.post(endpoint, json=payload, headers={"Authorization": "Bearer agent-a"}).status_code == 422


def test_snapshot_requires_timestamp_and_rejects_extra_gold_labels():
    payload = facts()
    payload["collected_at"] = "2026-11-14T12:00:00"
    with pytest.raises(ValueError):
        DeviceSnapshot.model_validate(payload)
    payload = facts()
    payload["expected_cves"] = ["CVE-2021-1234"]
    with pytest.raises(ValueError):
        DeviceSnapshot.model_validate(payload)
