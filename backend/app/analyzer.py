
import re
from collections import Counter


PATTERNS = {
    "SSH_LOGIN_FAILED": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)",
        re.IGNORECASE,
    ),
    "SSH_LOGIN_SUCCESS": re.compile(
        r"Accepted password for (\S+) from (\S+)",
        re.IGNORECASE,
    ),
    "HTTP_ERROR": re.compile(
        r'"(?:GET|POST|PUT|DELETE|PATCH) [^"]+" (4\d{2}|5\d{2})\b',
        re.IGNORECASE,
    ),
}


def analyze_logs(text: str) -> dict:
    events = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for event_type, pattern in PATTERNS.items():
            match = pattern.search(line)

            if not match:
                continue

            event = {
                "line": line_number,
                "type": event_type,
                "raw": line[:500],
            }

            if event_type == "SSH_LOGIN_FAILED":
                event["username"] = match.group(1)
                event["source_ip"] = match.group(2)
                event["severity"] = "high"

            elif event_type == "SSH_LOGIN_SUCCESS":
                event["username"] = match.group(1)
                event["source_ip"] = match.group(2)
                event["severity"] = "info"

            else:
                event["status_code"] = int(match.group(1))
                event["severity"] = "medium"

            events.append(event)
            break

    failed_by_ip = Counter(
        event["source_ip"]
        for event in events
        if event["type"] == "SSH_LOGIN_FAILED"
    )

    return {
        "lines_analyzed": len(text.splitlines()),
        "events_found": len(events),
        "events": events,
        "failed_logins_by_ip": [
            {"ip": ip, "attempts": count}
            for ip, count in failed_by_ip.most_common()
        ],
    }
