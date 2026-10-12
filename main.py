import argparse
import sys
from analyzer.parser import stream_logs
from analyzer.detectors import SecurityEngine
from analyzer.reporter import generate_terminal_report, export_json_report


def main():
    parser = argparse.ArgumentParser(
        description="Lightweight Security Log Analyzer & Threat Detector"
    )
    parser.add_argument(
        "-f",
        "--file",
        default="sample_logs/access.log",
        help="Path to access.log file (default: sample_logs/access.log)",
    )
    parser.add_argument(
        "--burst-threshold",
        type=int,
        default=10,
        help="Max requests per 10s window before triggering alert (default: 10)",
    )
    parser.add_argument(
        "--failed-login-threshold",
        type=int,
        default=5,
        help="Max failed auth attempts per 60s window before alert (default: 5)",
    )
    parser.add_argument(
        "--json",
        metavar="OUTPUT_PATH",
        help="Export findings to specified JSON file path",
    )

    args = parser.parse_args()

    engine = SecurityEngine(
        burst_threshold=args.burst_threshold,
        auth_threshold=args.failed_login_threshold,
    )

    total_lines = 0
    malformed_lines = 0
    all_alerts = []

    try:
        for _, entry in stream_logs(args.file):
            total_lines += 1
            if entry is None:
                malformed_lines += 1
                continue

            alerts = engine.process(entry)
            all_alerts.extend(alerts)

    except FileNotFoundError:
        print(f"[-] Error: Could not find log file at '{args.file}'.", file=sys.stderr)
        sys.exit(1)

    generate_terminal_report(all_alerts, total_lines, malformed_lines)

    if args.json:
        export_json_report(all_alerts, args.json)


if __name__ == "__main__":
    main()