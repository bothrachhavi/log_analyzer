# Log Analyzer

A lightweight Python CLI for detecting suspicious activity in Apache/Nginx combined access logs.

## Features

- Parses access logs line by line.
- Detects:
  - Brute-force authentication attempts.
  - Rapid request bursts that may indicate scraping or DDoS activity.
  - Requests for sensitive endpoints such as `/.env`, `/admin`, and `/.git/config`.
- Reports malformed lines without stopping the analysis.
- Prints findings to the terminal and can export them as JSON.

## Requirements

- Python 3.9+
- No external dependencies

## Usage

Run the analyzer against the included sample log:

```bash
python main.py
```

Specify a log file:

```bash
python main.py --file path/to/access.log
```

Export findings to JSON:

```bash
python main.py --file sample_logs/access.log --json report.json
```

Adjust detection thresholds:

```bash
python main.py \
  --burst-threshold 10 \
  --failed-login-threshold 5
```

## Detection Rules

| Rule | Default condition | Severity |
| --- | --- | --- |
| Brute-force authentication | 5 failed authentication attempts from one IP within 60 seconds | High |
| Rapid request burst | 10 requests from one IP within 10 seconds | Medium |
| Sensitive endpoint reconnaissance | Access to a known sensitive path | Low |

## Project Structure

```text
.
├── analyzer/
│   ├── detectors.py  # Detection rules and security engine
│   ├── models.py     # Log and alert data models
│   ├── parser.py     # Combined log format parser
│   └── reporter.py   # Terminal and JSON reporting
├── main.py           # CLI entry point
└── sample_logs/
    └── access.log    # Example input
```

## Input Format

The parser expects the standard Apache/Nginx combined log format, for example:

```text
192.0.2.10 - - [12/Oct/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 1024
```

Malformed non-empty lines are skipped and included in the terminal report count.
