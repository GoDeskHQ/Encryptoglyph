import base64
import time

import pytest
from fastapi.testclient import TestClient

from main import app

CTX = {
    "tenant": "acme",
    "purpose": "pii",
    "table": "customers",
    "record_id": "42",
    "field": "email",
}


@pytest.fixture
def client() -> TestClient:
    app.state.store.reset()
    app.state.tokens.reset()
    return TestClient(app)


def _session(client: TestClient) -> dict[str, str]:
    return {"x-eg-session": client.post("/v1/sessions").json()["session_id"]}


def _token(client: TestClient, headers: dict[str, str], scopes, **extra) -> dict:
    made = client.post(
        "/v1/tokens", headers=headers, json={"name": "konektor", "scopes": scopes, **extra}
    )
    assert made.status_code == 201, made.text
    return made.json()


def test_token_is_shown_once_and_listed_without_secret(client: TestClient) -> None:
    headers = _session(client)
    made = _token(client, headers, ["seal", "open"], expires_in_days=2)
    assert made["token"].startswith("egt_")
    assert made["scopes"] == ["seal", "open"]
    assert 2 * 86400 - 5 <= made["expires_unix"] - time.time() <= 2 * 86400 + 5
    listed = client.get("/v1/tokens", headers=headers)
    assert listed.status_code == 200
    raw = listed.text
    assert made["token"] not in raw
    assert listed.json()["tokens"][0]["prefix"] == made["token"][:10]
    assert "token_hash" not in raw and "session_id" not in raw


def test_scoped_token_seals_and_opens_with_session_keys(client: TestClient) -> None:
    headers = _session(client)
    plain = _token(client, headers, ["seal", "open", "keys:read"])["token"]
    bearer = {"authorization": f"Bearer {plain}"}
    sealed = client.post(
        "/v1/seal",
        headers=bearer,
        json={**CTX, "plaintext_b64": base64.b64encode(b"ada@example.test").decode()},
    )
    assert sealed.status_code == 200, sealed.text
    opened = client.post(
        "/v1/open", headers=headers, json={**CTX, "blob_b64": sealed.json()["blob_b64"]}
    )
    assert base64.b64decode(opened.json()["plaintext_b64"]) == b"ada@example.test"
    assert client.get("/v1/keys", headers=bearer).status_code == 200


def test_scope_is_enforced(client: TestClient) -> None:
    headers = _session(client)
    plain = _token(client, headers, ["keys:read"])["token"]
    bearer = {"authorization": f"Bearer {plain}"}
    assert client.post("/v1/keys", headers=bearer).status_code == 401
    assert (
        client.post("/v1/seal", headers=bearer, json={**CTX, "plaintext_b64": "eA=="}).status_code
        == 401
    )
    # Tokens cannot mint tokens or shred keys.
    assert (
        client.post(
            "/v1/tokens", headers=bearer, json={"name": "x", "scopes": ["seal"]}
        ).status_code
        == 401
    )
    assert (
        client.post("/v1/shred", headers=bearer, json={"kid": "k1", "grant": "x"}).status_code
        == 401
    )


def test_revoke_and_bad_requests(client: TestClient) -> None:
    headers = _session(client)
    made = _token(client, headers, ["keys:read"])
    bearer = {"authorization": f"Bearer {made['token']}"}
    assert client.get("/v1/keys", headers=bearer).status_code == 200
    other = _session(client)
    assert client.delete(f"/v1/tokens/{made['id']}", headers=other).status_code == 404
    assert client.delete(f"/v1/tokens/{made['id']}", headers=headers).status_code == 200
    assert client.get("/v1/keys", headers=bearer).status_code == 401
    for body in (
        {"name": "x", "scopes": ["root"]},
        {"name": "x", "scopes": []},
        {"name": "", "scopes": ["seal"]},
        {"name": "x", "scopes": ["seal"], "expires_in_days": 365},
        {"name": "x", "scopes": ["seal"], "expires_in_days": 0},
    ):
        assert client.post("/v1/tokens", headers=headers, json=body).status_code == 400, body
    assert client.post("/v1/tokens", json={"name": "x", "scopes": ["seal"]}).status_code == 401
    assert client.get("/v1/keys", headers={"authorization": "Bearer egt_nope"}).status_code == 401


def test_session_outlives_token_creation_window(client: TestClient) -> None:
    headers = _session(client)
    made = _token(client, headers, ["keys:read"], expires_in_days=10)
    session = app.state.store.get(headers["x-eg-session"])
    assert session is not None and session.expires >= made["expires_unix"]
