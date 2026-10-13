import pytest
from fastapi.testclient import TestClient

import app.main as main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    main.init_db()
    with TestClient(main.app) as test_client:
        yield test_client


def create_admin(client):
    response = client.post(
        "/api/setup",
        json={"username": "nova_admin", "password": "a-long-and-secure-test-passphrase"},
    )
    assert response.status_code == 200


def test_health_and_setup_status(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["app"] == "NovaPanel"

    status = client.get("/api/setup/status")
    assert status.status_code == 200
    assert status.json()["setup_required"] is True


def test_setup_login_and_logout(client):
    create_admin(client)
    assert client.get("/api/me").status_code == 200
    assert client.get("/api/host").status_code == 200

    client.post("/api/logout")
    assert client.get("/api/me").status_code == 401

    response = client.post(
        "/api/login",
        json={"username": "nova_admin", "password": "a-long-and-secure-test-passphrase"},
    )
    assert response.status_code == 200
    assert client.get("/api/me").status_code == 200


def test_setup_can_only_be_completed_once(client):
    create_admin(client)
    response = client.post(
        "/api/setup",
        json={"username": "second_admin", "password": "another-long-and-secure-passphrase"},
    )
    assert response.status_code == 409


def test_private_endpoints_require_login(client):
    assert client.get("/api/users").status_code == 401
    assert client.get("/api/connections").status_code == 401
    assert client.get("/api/host").status_code == 401


def test_user_crud(client):
    create_admin(client)
    created = client.post("/api/users", json={"name": "Test User", "quota_gb": 25})
    assert created.status_code == 201
    user = created.json()
    assert user["name"] == "Test User"
    assert user["quota_gb"] == 25
    assert user["uuid"]

    listing = client.get("/api/users")
    assert len(listing.json()) == 1

    updated = client.put("/api/users/" + user["id"], json={"enabled": False, "name": "Renamed"})
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False
    assert updated.json()["name"] == "Renamed"

    deleted = client.delete("/api/users/" + user["id"])
    assert deleted.status_code == 200
    assert client.get("/api/users").json() == []


def test_connection_validation_and_crud(client):
    create_admin(client)
    invalid = client.post(
        "/api/connections",
        json={"name": "Bad host", "address": "https://example.com/path", "port": 443},
    )
    assert invalid.status_code == 422

    created = client.post(
        "/api/connections",
        json={"name": "Main WS", "address": "vpn.example.com", "port": 443, "transport": "ws", "path": "/ray"},
    )
    assert created.status_code == 201
    connection = created.json()
    assert connection["transport"] == "ws"
    assert connection["tls_ready"] is False

    deleted = client.delete("/api/connections/" + connection["id"])
    assert deleted.status_code == 200


def test_host_report_does_not_guess_network_support(client):
    create_admin(client)
    response = client.get("/api/host")
    assert response.status_code == 200
    assert response.json()["capabilities"]["inbound_tcp_udp"]["status"] == "unknown"


def test_api_docs_are_available(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "NovaPanel"
