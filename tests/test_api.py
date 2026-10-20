from fastapi.testclient import TestClient
from backend.app.main import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "SENTINEL Cyber Lab"
    assert data["version"] == "0.2.0"
    assert data["status"] == "online"


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_endpoint_detects_failed_ssh_login():
    response = client.post(
        "/analyze",
        json={
            "text": (
                "Failed password for joao "
                "from 192.168.1.10 port 22 ssh2"
            )
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["lines_analyzed"] == 1
    assert data["events_found"] == 1
    assert data["events"][0]["type"] == "SSH_LOGIN_FAILED"
    assert data["events"][0]["username"] == "joao"


def test_analyze_empty_text():
    response = client.post("/analyze", json={"text": ""})

    assert response.status_code == 200
    assert response.json()["events_found"] == 0


def test_analyze_rejects_missing_text():
    response = client.post("/analyze", json={})

    assert response.status_code == 422
