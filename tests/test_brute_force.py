import pytest

from backend.app.analyzer import analyze_logs


def make_failed_log(ip: str, username: str = "admin") -> str:
    return f"Failed password for {username} from {ip} port 22 ssh2"


def test_alert_when_ip_reaches_default_threshold():
    logs = "\n".join(
        make_failed_log("10.0.0.1", f"user{i}")
        for i in range(5)
    )

    result = analyze_logs(logs)

    assert len(result["brute_force_alerts"]) == 1
    alert = result["brute_force_alerts"][0]
    assert alert["type"] == "SSH_BRUTE_FORCE_SUSPECTED"
    assert alert["source_ip"] == "10.0.0.1"
    assert alert["failed_attempts"] == 5
    assert alert["threshold"] == 5
    assert alert["severity"] == "high"


def test_no_alert_below_threshold():
    logs = "\n".join(
        make_failed_log("10.0.0.1", f"user{i}")
        for i in range(4)
    )

    result = analyze_logs(logs)

    assert result["brute_force_alerts"] == []


def test_alerts_are_separate_for_each_ip():
    logs = "\n".join(
        [make_failed_log("10.0.0.1", f"a{i}") for i in range(5)]
        + [make_failed_log("10.0.0.2", f"b{i}") for i in range(4)]
    )

    result = analyze_logs(logs)

    assert len(result["brute_force_alerts"]) == 1
    assert result["brute_force_alerts"][0]["source_ip"] == "10.0.0.1"


def test_custom_threshold():
    logs = "\n".join(
        make_failed_log("10.0.0.1", f"user{i}")
        for i in range(3)
    )

    result = analyze_logs(logs, brute_force_threshold=3)

    assert len(result["brute_force_alerts"]) == 1
    assert result["brute_force_alerts"][0]["threshold"] == 3


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        analyze_logs("", brute_force_threshold=0)
