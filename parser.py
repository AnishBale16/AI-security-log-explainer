import re
from datetime import datetime


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} "
    r"\d{2}:\d{2}:\d{2}) "
    r"(?P<level>[A-Z]+) "
    r"(?P<message>.*)$"
)


def identify_event(message):
    """
    Identify the type of security event from the log message.
    """

    message_lower = message.lower()

    if "failed password" in message_lower:
        return "authentication_failure"

    if "logged in successfully" in message_lower:
        return "authentication_success"

    if "login successful" in message_lower:
        return "authentication_success"

    if "logged out" in message_lower:
        return "logout"

    return "unknown"


def extract_username(message):
    """
    Extract username from messages such as:

    Failed password for root from 192.168.1.50
    User admin logged in successfully from 192.168.1.50
    """

    patterns = [
        r"Failed password for (\S+)",
        r"User (\S+) logged in successfully",
        r"User (\S+) logged out"
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)

        if match:
            return match.group(1)

    return None


def extract_source_ip(message):
    """
    Extract an IPv4 address from the log message.
    """

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    match = re.search(ip_pattern, message)

    if match:
        return match.group(0)

    return None


def parse_line(line):
    """
    Convert one raw log line into a structured dictionary.
    """

    line = line.strip()

    if not line:
        return None

    match = LOG_PATTERN.match(line)

    if not match:
        return {
            "timestamp": None,
            "level": "UNKNOWN",
            "event_type": "unknown",
            "username": None,
            "source_ip": None,
            "message": line
        }

    timestamp_string = match.group("timestamp")
    level = match.group("level")
    message = match.group("message")

    try:
        timestamp = datetime.strptime(
            timestamp_string,
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        timestamp = None

    event_type = identify_event(message)
    username = extract_username(message)
    source_ip = extract_source_ip(message)

    return {
        "timestamp": timestamp,
        "level": level,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "message": message
    }


def parse_file(file_path):
    """
    Read a complete log file and return structured events.
    """

    events = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line_number, line in enumerate(file, start=1):

            event = parse_line(line)

            if event:
                event["line_number"] = line_number
                events.append(event)

    return events
