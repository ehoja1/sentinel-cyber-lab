from backend.app.analyzer import analyze_logs


def test_empty_input():
    result = analyze_logs("")

    assert result["lines_analyzed"] == 0
    assert result["events_found"] == 0
    assert result["events"] == []
    assert result["failed_logins_by_ip"] == []


def test_failed_ssh_login():
    result = analyze_logs(
        "Failed password for joao from 192.168.1.10 port 22 ssh2"
    )

    assert result["events_found"] == 1

    event = result["events"][0]
    assert event["type"] == "SSH_LOGIN_FAILED"
    assert event["username"] == "joao"
    assert event["source_ip"] == "192.168.1.10"
    assert event["severity"] == "high"
    assert event["line"] == 1


def test_successful_ssh_login():
    result = analyze_logs(
        "Accepted password for joao from 192.168.1.20 port 22 ssh2"
    )

    event = result["events"][0]
    assert event["type"] == "SSH_LOGIN_SUCCESS"
    assert event["username"] == "joao"
    assert event["source_ip"] == "192.168.1.20"
    assert event["severity"] == "info"


def test_http_error_status():
    result = analyze_logs(
        '192.168.1.5 - - "GET /admin HTTP/1.1" 404 123'
    )

    event = result["events"][0]
    assert event["type"] == "HTTP_ERROR"
    assert event["status_code"] == 404
    assert event["severity"] == "medium"


def test_failed_logins_are_grouped_by_ip():
    logs = "\n".join([
        "Failed password for joao from 10.0.0.1 port 22 ssh2",
        "Failed password for maria from 10.0.0.2 port 22 ssh2",
        "Failed password for pedro from 10.0.0.1 port 22 ssh2",
    ])

    result = analyze_logs(logs)

    assert result["events_found"] == 3
    assert result["failed_logins_by_ip"] == [
        {"ip": "10.0.0.1", "attempts": 2},
        {"ip": "10.0.0.2", "attempts": 1},
    ]


def test_line_numbers_and_raw_length_limit():
    long_line = "Failed password for joao from 10.0.0.1 " + ("x" * 600)
    logs = "ordinary log line\n" + long_line

    result = analyze_logs(logs)

    assert result["lines_analyzed"] == 2
    assert result["events_found"] == 1
    assert result["events"][0]["line"] == 2
    assert len(result["events"][0]["raw"]) == 500
