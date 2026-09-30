import sys

from parser import parse_file
from detector import run_detection
from risk_engine import analyze_findings


def print_event_summary(events):
    print("\n" + "=" * 60)
    print("PARSED SECURITY EVENTS")
    print("=" * 60)

    print(f"Total events: {len(events)}")

    for event in events:

        timestamp = event["timestamp"]

        if timestamp:
            timestamp = timestamp.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

        print(
            f"{timestamp} | "
            f"{event['event_type']} | "
            f"User: {event['username']} | "
            f"IP: {event['source_ip']}"
        )


def print_findings(findings):

    print("\n" + "=" * 60)
    print("SECURITY FINDINGS")
    print("=" * 60)

    if not findings:
        print("\nNo suspicious activity detected.")
        return

    for number, finding in enumerate(findings, start=1):

        print(f"\nFinding #{number}")
        print("-" * 60)

        print(f"Type: {finding['type']}")
        print(f"Severity: {finding['severity']}")
        print(f"Risk Score: {finding['risk_score']}/10")

        if finding.get("source_ip"):
            print(f"Source IP: {finding['source_ip']}")

        if finding.get("username"):
            print(f"Username: {finding['username']}")

        if finding.get("failed_attempts"):
            print(
                f"Failed Attempts: "
                f"{finding['failed_attempts']}"
            )

        if finding.get("usernames"):
            print(
                f"Usernames: "
                f"{', '.join(finding['usernames'])}"
            )

        print(f"Description: {finding['description']}")


def main():

    if len(sys.argv) != 2:

        print(
            "\nUsage:\n"
            "python main.py <log_file>\n"
        )

        sys.exit(1)

    log_file = sys.argv[1]

    print("\n" + "=" * 60)
    print("        AI SECURITY LOG EXPLAINER")
    print("=" * 60)

    print(f"\nScanning: {log_file}")

    try:

        events = parse_file(log_file)

    except FileNotFoundError:

        print(f"\nError: File not found: {log_file}")
        sys.exit(1)

    except PermissionError:

        print(
            f"\nError: Permission denied: {log_file}"
        )
        sys.exit(1)

    print_event_summary(events)

    raw_findings = run_detection(events)

    findings = analyze_findings(raw_findings)

    print_findings(findings)

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)

    print(f"Events analyzed: {len(events)}")
    print(f"Findings: {len(findings)}")

    high_risk = sum(
        1
        for finding in findings
        if finding["severity"] in ("HIGH", "CRITICAL")
    )

    print(f"High/Critical findings: {high_risk}")


if __name__ == "__main__":
    main()
