import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from eg_api.http import create_app
from eg_api.store import Session


@pytest.fixture
def client():
    return TestClient(create_app())


def session(client):
    return {"x-eg-session": client.post("/v1/sessions").json()["session_id"]}


def hierarchy(client, headers):
    records = [
        ("tenants", {"id": "acme", "name": "Acme"}),
        ("sites", {"id": "hq", "name": "Headquarters", "tenant_id": "acme"}),
        ("devices", {"id": "host-1", "name": "Host One", "site_id": "hq"}),
    ]
    for kind, record in records:
        response = client.post(f"/v1/{kind}", headers=headers, json=record)
        assert response.status_code == 201
        assert response.json() == record
    return records


def test_create_list_show_and_isolation(client):
    headers, other = session(client), session(client)
    for kind, record in hierarchy(client, headers):
        path = f"/v1/{kind}"
        assert client.get(path, headers=headers).json() == {kind: [record]}
        assert client.get(f"{path}/{record['id']}", headers=headers).json() == record
        assert client.get(path, headers=other).json() == {kind: []}
        assert client.get(f"{path}/{record['id']}", headers=other).status_code == 404
        assert client.post(path, headers=headers, json=record).status_code == 409
        assert client.get(path).status_code == 401
        assert client.get(f"{path}/{record['id']}").status_code == 401
        assert client.post(path, json=record).status_code == 401


def test_parent_must_exist_in_same_session(client):
    first, second = session(client), session(client)
    hierarchy(client, first)
    for kind, record in [
        ("sites", {"id": "hq", "name": "HQ", "tenant_id": "acme"}),
        ("devices", {"id": "host", "name": "Host", "site_id": "hq"}),
    ]:
        assert client.post(f"/v1/{kind}", headers=second, json=record).status_code == 404


@pytest.mark.parametrize("change", [
    {"id": "bad/id"}, {"id": "x" * 65}, {"id": True}, {"id": ""},
    {"id": "."}, {"id": ".."}, {"name": "bad\x7fname"},
    {"name": " "}, {"name": "x" * 121}, {"name": 1}, {"name": "bad\nname"},
    {"secret": "do-not-store"}, {"tenant_id": "extra"},
])
def test_invalid_metadata_rejected_without_echo(client, change):
    response = client.post("/v1/tenants", headers=session(client),
                           json={"id": "acme", "name": "Acme", **change})
    assert response.status_code == 400
    assert "do-not-store" not in response.text


def test_required_fields_limits_and_name_trimming(client):
    headers = session(client)
    assert client.post("/v1/tenants", headers=headers, json={"id": "a"}).status_code == 400
    assert client.post("/v1/tenants", headers=headers,
                       json={"id": "a", "name": " A "}).json()["name"] == "A"
    for parent in (None, [], "", "bad/id"):
        assert client.post("/v1/sites", headers=headers,
                           json={"id": "s", "name": "S", "tenant_id": parent}
                           ).status_code == 400
    stored = client.app.state.store.get(headers["x-eg-session"])
    stored.inventory["tenants"].update(
        {f"t{i}": {"id": f"t{i}", "name": "Tenant"} for i in range(1000)}
    )
    assert client.post("/v1/tenants", headers=headers,
                       json={"id": "overflow", "name": "Overflow"}).status_code == 400


def test_metadata_lifetime(client):
    headers = session(client)
    hierarchy(client, headers)
    stored = client.app.state.store.get(headers["x-eg-session"])
    stored.expires = time.time() - 1
    assert client.get("/v1/tenants", headers=headers).status_code == 401
    assert all(not rows for rows in stored.inventory.values())
    assert client.get("/v1/tenants", headers=session(client)).json() == {"tenants": []}
    restarted = TestClient(create_app())
    assert restarted.get("/v1/tenants", headers=headers).status_code == 401


def test_rotation_inventory_and_shred(client):
    headers = session(client)
    old = client.post("/v1/keys", headers=headers).json()
    client.post("/v1/keys", headers=headers)
    rows = client.get("/v1/keys", headers=headers).json()["keys"]
    assert rows[0]["fingerprint"] == old["fingerprint"]
    assert rows[0]["rotation_status"] == "retired"
    assert rows[0]["current"] is False
    assert rows[0]["created_unix"] <= rows[0]["retired_unix"]
    assert rows[1]["rotation_status"] == "current"
    assert rows[1]["retired_unix"] is None
    assert set(rows[0]) == {
        "kid", "fingerprint", "current", "rotation_status", "created_unix", "retired_unix"
    }
    grant = client.post("/v1/reauth", headers=headers,
                        json={"kid": old["kid"], "confirm_fingerprint": old["fingerprint"]})
    assert client.post("/v1/shred", headers=headers,
                       json={"kid": old["kid"], "grant": grant.json()["grant"]}
                       ).status_code == 200
    fresh = client.post("/v1/keys", headers=headers).json()
    rows = client.get("/v1/keys", headers=headers).json()["keys"]
    reused = next(row for row in rows if row["kid"] == fresh["kid"])
    assert reused["retired_unix"] is None


def test_unimplemented_custody_status(client):
    status = client.get("/v1/status").json()
    for field in ("backup_health", "restore_tests", "escrow_approvals"):
        assert status[field] == "not-implemented"
    assert status["openbao"] == "not-connected"
    assert status["restic"] == "not-configured"


def test_key_inventory_snapshot_waits_for_rotation(monkeypatch):
    stored = Session(created=0, expires=100)
    stored.add_key()
    rotating, release, reading = threading.Event(), threading.Event(), threading.Event()

    def pause_rotation():
        rotating.set()
        assert release.wait(3)
        return 10.0

    def read_inventory():
        reading.set()
        return stored.public_keys()

    monkeypatch.setattr("eg_api.store.time.time", pause_rotation)
    with ThreadPoolExecutor(max_workers=2) as pool:
        writer = pool.submit(stored.add_key)
        try:
            assert rotating.wait(3)
            reader = pool.submit(read_inventory)
            assert reading.wait(3)
            assert not reader.done()
        finally:
            release.set()
        writer.result(timeout=3)
        rows = reader.result(timeout=3)
    assert [row["rotation_status"] for row in rows] == ["retired", "current"]
    assert rows[1]["created_unix"] == 10.0
