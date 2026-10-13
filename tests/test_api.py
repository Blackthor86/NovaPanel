import pytest
from fastapi.testclient import TestClient

import app.main as main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setenv("NOVAPANEL_DEPLOYMENT_MODE", "direct")
    main.init_db()
    with TestClient(main.app) as test_client:
        yield test_client


def create_admin(client):
    response = client.post(
        "/api/setup",
        json={"password": "a-long-and-secure-test-passphrase"},
    )
    assert response.status_code == 200


def test_health_and_setup_status(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["app"] == "NovaPanel"
    assert response.json()["version"] == "0.5.0"

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
        json={"password": "a-long-and-secure-test-passphrase"},
    )
    assert response.status_code == 200
    assert client.get("/api/me").status_code == 200


def test_setup_can_only_be_completed_once(client):
    create_admin(client)
    response = client.post(
        "/api/setup",
        json={"password": "another-long-and-secure-passphrase"},
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


def test_platform_websocket_mode_creates_a_managed_profile(client, monkeypatch):
    monkeypatch.setenv("NOVAPANEL_DEPLOYMENT_MODE", "paas_ws")
    create_admin(client)
    status = client.get("/api/deployment")
    assert status.status_code == 200
    assert status.json()["mode"] == "paas_ws"
    assert status.json()["auto_connection"] is True
    connection = client.get("/api/connections").json()[0]
    assert connection["managed_by_platform"] is True
    assert connection["tls_ready"] is True
    assert connection["port"] == 443

    user = client.post("/api/users", json={"name": "Platform User"})
    assert user.status_code == 201
    config = main.build_xray_config()
    inbound = config["inbounds"][0]
    assert inbound["listen"] == "127.0.0.1"
    assert inbound["port"] == main.PLATFORM_WS_PORT
    assert inbound["streamSettings"]["security"] == "none"
    assert inbound["streamSettings"]["wsSettings"]["path"] == connection["path"]

    response = client.post("/api/connections", json={"name": "manual", "address": "vpn.example.com", "port": 443})
    assert response.status_code == 409

    sub = client.post("/api/users/" + user.json()["id"] + "/subscription")
    assert sub.status_code == 200
    public_host = "https://testserver"
    assert sub.json()["url"].startswith(public_host + "/api/subscriptions/")


def test_direct_mode_remains_available(client, monkeypatch):
    monkeypatch.setenv("NOVAPANEL_DEPLOYMENT_MODE", "direct")
    create_admin(client)
    status = client.get("/api/deployment")
    assert status.status_code == 200
    assert status.json()["mode"] == "direct"
    assert status.json()["auto_connection"] is False


def test_api_docs_are_available(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "NovaPanel API"



def test_xray_config_uses_current_transport_settings(client, tmp_path):
    create_admin(client)
    user = client.post("/api/users", json={"name": "Config User"})
    assert user.status_code == 201

    certificate = tmp_path / "fullchain.pem"
    private_key = tmp_path / "privkey.pem"
    certificate.write_text("test certificate", encoding="utf-8")
    private_key.write_text("test private key", encoding="utf-8")

    connection = client.post(
        "/api/connections",
        json={
            "name": "WS profile",
            "address": "vpn.example.com",
            "port": 443,
            "transport": "ws",
            "path": "/ray",
            "host_header": "vpn.example.com",
            "certificate_file": str(certificate),
            "private_key_file": str(private_key),
        },
    )
    assert connection.status_code == 201

    config = main.build_xray_config()
    inbound = config["inbounds"][0]
    assert inbound["streamSettings"]["method"] == "websocket"
    assert inbound["streamSettings"]["wsSettings"]["host"] == "vpn.example.com"
    assert inbound["streamSettings"]["security"] == "tls"
    assert config["stats"] == {}
    assert config["api"]["listen"] == "127.0.0.1:10085"
    assert config["policy"]["levels"]["0"]["statsUserUplink"] is True
    assert config["policy"]["levels"]["0"]["statsUserDownlink"] is True


def test_expired_users_are_disabled(client):
    create_admin(client)
    created = client.post(
        "/api/users",
        json={"name": "Expired User", "expires_at": "2000-01-01T00:00:00+00:00"},
    )
    assert created.status_code == 201
    user_id = created.json()["id"]

    assert user_id in main.disable_expired_users()
    users = client.get("/api/users").json()
    assert users[0]["enabled"] is False


def test_quota_is_enforced_from_recorded_traffic(client):
    create_admin(client)
    created = client.post("/api/users", json={"name": "Limited User", "quota_gb": 1})
    assert created.status_code == 201
    user_id = created.json()["id"]

    with main.db() as conn:
        conn.execute(
            "UPDATE traffic_usage SET up_bytes = ? WHERE user_id = ?",
            (1024 ** 3, user_id),
        )

    assert user_id in main.disable_expired_users()
    assert client.get("/api/users").json()[0]["enabled"] is False


def test_subscription_links_are_revocable_and_return_active_profiles(client, tmp_path):
    import base64
    from urllib.parse import urlparse

    create_admin(client)
    user = client.post("/api/users", json={"name": "Subscription User"})
    assert user.status_code == 201

    certificate = tmp_path / "fullchain.pem"
    private_key = tmp_path / "privkey.pem"
    certificate.write_text("test certificate", encoding="utf-8")
    private_key.write_text("test private key", encoding="utf-8")

    connection = client.post(
        "/api/connections",
        json={
            "name": "Subscription WS",
            "address": "vpn.example.com",
            "port": 443,
            "transport": "ws",
            "path": "/ray",
            "certificate_file": str(certificate),
            "private_key_file": str(private_key),
        },
    )
    assert connection.status_code == 201

    created = client.post("/api/users/" + user.json()["id"] + "/subscription")
    assert created.status_code == 200
    old_path = urlparse(created.json()["url"]).path
    response = client.get(old_path)
    assert response.status_code == 200
    assert "no-store" in response.headers["cache-control"]
    decoded = base64.b64decode(response.text).decode("utf-8")
    assert "vless://" in decoded
    assert "vpn.example.com:443" in decoded

    rotated = client.post("/api/users/" + user.json()["id"] + "/subscription")
    assert rotated.status_code == 200
    assert client.get(old_path).status_code == 404
    assert client.get(urlparse(rotated.json()["url"]).path).status_code == 200


def test_user_traffic_can_be_reset(client):
    create_admin(client)
    created = client.post("/api/users", json={"name": "Reset User", "quota_gb": 10})
    assert created.status_code == 201
    user_id = created.json()["id"]
    with main.db() as conn:
        conn.execute(
            "UPDATE traffic_usage SET up_bytes = ?, down_bytes = ? WHERE user_id = ?",
            (4096, 8192, user_id),
        )

    response = client.post("/api/users/" + user_id + "/reset-traffic")
    assert response.status_code == 200
    user = client.get("/api/users").json()[0]
    assert user["used_bytes"] == 0
    assert user["up_bytes"] == 0
    assert user["down_bytes"] == 0
