import json
from typing import List
from analyzer.models import SecurityAlert


def generate_terminal_report(
    alerts: List[SecurityAlert], total_lines: int, malformed_lines: int
) -> None:
    print("\n" + "=" * 65)
    print("           SECURITY LOG ANALYSIS REPORT")
    print("=" * 65)
    print(f"Total Lines Processed : {total_lines}")
    print(f"Malformed Lines Skipped: {malformed_lines}")
    print(f"Suspicious Events Found: {len(alerts)}")
    print("-" * 65)

    if not alerts:
        print("No suspicious activity detected matching current rules.")
        print("=" * 65 + "\n")
        return

    for alert in alerts:
        badge = f"[{alert.severity}]"
        print(f"{badge:<8} {alert.rule_name}")
        print(f"  Source IP : {alert.ip}")
        print(f"  Timestamp : {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S %z')}")
        for key, val in alert.details.items():
            print(f"  {key.replace('_', ' ').capitalize():<10}: {val}")
        print("-" * 65)


def export_json_report(alerts: List[SecurityAlert], output_path: str) -> None:
    data = [alert.to_dict() for alert in alerts]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Structured report exported to: {output_path}")