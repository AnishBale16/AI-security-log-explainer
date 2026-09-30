from collections import defaultdict
from datetime import timedelta


def detect_brute_force(events, threshold=5):
    """
    Detect multiple failed authentication attempts
    from the same IP address.
    """

    failures_by_ip = defaultdict(list)

    for event in events:

        if event["event_type"] == "authentication_failure":

            ip = event["source_ip"]

            if ip:
                failures_by_ip[ip].append(event)

    findings = []

    for ip, failures in failures_by_ip.items():

        if len(failures) >= threshold:

            findings.append({
                "type": "brute_force",
                "source_ip": ip,
                "username": failures[-1]["username"],
                "failed_attempts": len(failures),
                "first_seen": failures[0]["timestamp"],
                "last_seen": failures[-1]["timestamp"],
                "description": (
                    f"{len(failures)} failed authentication "
                    f"attempts detected from {ip}."
                )
            })

    return findings


def detect_success_after_failures(events, threshold=3):
    """
    Detect a successful login following multiple failed attempts
    from the same IP and username.
    """

    findings = []

    events_sorted = sorted(
        events,
        key=lambda event: event["timestamp"]
        if event["timestamp"] else ""
    )

    for index, event in enumerate(events_sorted):

        if event["event_type"] != "authentication_success":
            continue

        ip = event["source_ip"]
        username = event["username"]

        if not ip or not username:
            continue

        previous_failures = []

        for previous in events_sorted[:index]:

            if previous["event_type"] != "authentication_failure":
                continue

            if previous["source_ip"] != ip:
                continue

            if previous["username"] != username:
                continue

            if not previous["timestamp"] or not event["timestamp"]:
                continue

            time_difference = (
                event["timestamp"] - previous["timestamp"]
            )

            if timedelta(0) <= time_difference <= timedelta(minutes=5):

                previous_failures.append(previous)

        if len(previous_failures) >= threshold:

            findings.append({
                "type": "successful_login_after_failures",
                "source_ip": ip,
                "username": username,
                "failed_attempts": len(previous_failures),
                "successful_login": event["timestamp"],
                "description": (
                    f"Successful login for '{username}' occurred "
                    f"after {len(previous_failures)} failed attempts "
                    f"from {ip}."
                )
            })

    return findings


def detect_multiple_usernames(events, threshold=3):
    """
    Detect one IP attempting authentication against
    multiple usernames.
    """

    usernames_by_ip = defaultdict(set)

    for event in events:

        if event["event_type"] not in (
            "authentication_failure",
            "authentication_success"
        ):
            continue

        ip = event["source_ip"]
        username = event["username"]

        if ip and username:
            usernames_by_ip[ip].add(username)

    findings = []

    for ip, usernames in usernames_by_ip.items():

        if len(usernames) >= threshold:

            findings.append({
                "type": "multiple_username_attempts",
                "source_ip": ip,
                "usernames": sorted(usernames),
                "username_count": len(usernames),
                "description": (
                    f"Multiple usernames were targeted from {ip}."
                )
            })

    return findings


def run_detection(events):
    """
    Run all detection rules.
    """

    findings = []

    findings.extend(
        detect_brute_force(events)
    )

    findings.extend(
        detect_success_after_failures(events)
    )

    findings.extend(
        detect_multiple_usernames(events)
    )

    return findings
