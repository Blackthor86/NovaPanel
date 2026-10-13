from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["app"] == "NovaPanel"


def test_host_report_does_not_assume_network_support():
    response = client.get("/api/host")

    assert response.status_code == 200
    body = response.json()
    assert body["capabilities"]["inbound_tcp_udp"]["status"] == "unknown"
    assert body["capabilities"]["separate_processes"]["status"] == "unknown"


def test_api_docs_are_available():
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "NovaPanel API"
