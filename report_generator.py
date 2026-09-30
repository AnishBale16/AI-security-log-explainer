import json
from datetime import datetime


def generate_report(events, findings, output_file):

    report = {
        "project": "AI Security Log Explainer",
        "scan_timestamp": datetime.now().isoformat(),
        "summary": {
            "events_analyzed": len(events),
            "findings": len(findings),
            "high": sum(
                1 for f in findings
                if f["severity"] == "HIGH"
            ),
            "critical": sum(
                1 for f in findings
                if f["severity"] == "CRITICAL"
            )
        },
        "findings": findings
    }

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            default=str
        )

    return report
