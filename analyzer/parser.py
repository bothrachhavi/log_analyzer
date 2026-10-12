import re
from datetime import datetime
from typing import Generator, Optional, Tuple
from analyzer.models import LogEntry

# Standard NGINX / Apache Combined Log Format regex
LOG_REGEX = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+\S+"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\S+)"
)


def parse_log_line(line: str) -> Optional[LogEntry]:
    match = LOG_REGEX.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    try:
        # Standard format: 12/Oct/2026:10:00:01 +0000
        dt = datetime.strptime(data["timestamp"], "%d/%b/%Y:%H:%M:%S %z")
        bytes_val = int(data["bytes"]) if data["bytes"].isdigit() else 0
        return LogEntry(
            ip=data["ip"],
            timestamp=dt,
            method=data["method"],
            endpoint=data["endpoint"],
            status=int(data["status"]),
            bytes_sent=bytes_val,
        )
    except (ValueError, KeyError):
        return None


def stream_logs(filepath: str) -> Generator[Tuple[int, Optional[LogEntry]], None, None]:
    """Streams file line-by-line; yields (line_number, LogEntry or None)."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            if not line.strip():
                continue
            yield idx, parse_log_line(line)