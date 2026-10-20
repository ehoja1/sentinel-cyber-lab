from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_api_returns_brute_force_alert():
    logs = "\n".join(
        f"Failed password for user{i} from 10.0.0.5 port 22 ssh2"
        for i in range(5)
    )

    response = client.post("/analyze", json={"text": logs})

    assert response.status_code == 200
    data = response.json()
    assert len(data["brute_force_alerts"]) == 1
    assert data["brute_force_alerts"][0]["source_ip"] == "10.0.0.5"


def test_api_accepts_custom_threshold():
    logs = "\n".join(
        f"Failed password for user{i} from 10.0.0.8 port 22 ssh2"
        for i in range(3)
    )

    response = client.post(
        "/analyze",
        json={"text": logs, "brute_force_threshold": 3},
    )

    assert response.status_code == 200
    assert len(response.json()["brute_force_alerts"]) == 1


def test_api_rejects_invalid_threshold():
    response = client.post(
        "/analyze",
        json={"text": "", "brute_force_threshold": 0},
    )

    assert response.status_code == 422
