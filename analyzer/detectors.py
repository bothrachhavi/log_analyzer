from collections import defaultdict, deque
from datetime import timedelta
from typing import List
from analyzer.models import LogEntry, SecurityAlert


class BruteForceDetector:
    """Flags IPs with >= threshold failed logins within window_seconds."""

    def __init__(self, window_seconds: int = 60, threshold: int = 5):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.history = defaultdict(deque)
        self.alerted_ips = set()

    def inspect(self, entry: LogEntry) -> List[SecurityAlert]:
        # Consider 401 anywhere or 403 on auth paths as failed attempts
        is_failed_auth = entry.status == 401 or (
            entry.status == 403 and "login" in entry.endpoint.lower()
        )
        if not is_failed_auth:
            return []

        dq = self.history[entry.ip]
        dq.append(entry.timestamp)

        while dq and (entry.timestamp - dq[0]) > self.window:
            dq.popleft()

        if len(dq) >= self.threshold and entry.ip not in self.alerted_ips:
            self.alerted_ips.add(entry.ip)
            return [
                SecurityAlert(
                    rule_name="Brute-Force Authentication Attempt",
                    ip=entry.ip,
                    severity="HIGH",
                    timestamp=entry.timestamp,
                    details={
                        "failed_attempts": len(dq),
                        "window_sec": int(self.window.total_seconds()),
                        "last_endpoint": entry.endpoint,
                    },
                )
            ]
        return []


class RequestBurstDetector:
    """Flags IPs exceeding threshold total requests within window_seconds."""

    def __init__(self, window_seconds: int = 10, threshold: int = 10):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.history = defaultdict(deque)
        self.alerted_ips = set()

    def inspect(self, entry: LogEntry) -> List[SecurityAlert]:
        dq = self.history[entry.ip]
        dq.append(entry.timestamp)

        while dq and (entry.timestamp - dq[0]) > self.window:
            dq.popleft()

        if len(dq) >= self.threshold and entry.ip not in self.alerted_ips:
            self.alerted_ips.add(entry.ip)
            return [
                SecurityAlert(
                    rule_name="Rapid Request Burst (DDoS/Scraping)",
                    ip=entry.ip,
                    severity="MEDIUM",
                    timestamp=entry.timestamp,
                    details={
                        "request_count": len(dq),
                        "window_sec": int(self.window.total_seconds()),
                    },
                )
            ]
        return []


class SensitiveEndpointDetector:
    """Flags requests attempting to access known sensitive files/paths."""

    SENSITIVE_PATHS = {
        "/.env",
        "/wp-login.php",
        "/admin",
        "/phpmyadmin",
        "/.git/config",
        "/config.json",
    }

    def __init__(self):
        self.flagged_events = set()

    def inspect(self, entry: LogEntry) -> List[SecurityAlert]:
        if any(entry.endpoint.startswith(path) for path in self.SENSITIVE_PATHS):
            event_key = (entry.ip, entry.endpoint)
            if event_key not in self.flagged_events:
                self.flagged_events.add(event_key)
                return [
                    SecurityAlert(
                        rule_name="Sensitive Endpoint Reconnaissance",
                        ip=entry.ip,
                        severity="LOW",
                        timestamp=entry.timestamp,
                        details={
                            "targeted_endpoint": entry.endpoint,
                            "http_status": entry.status,
                        },
                    )
                ]
        return []


class SecurityEngine:
    """Coordinates all detection modules over the stream."""

    def __init__(self, burst_threshold: int = 10, auth_threshold: int = 5):
        self.detectors = [
            BruteForceDetector(window_seconds=60, threshold=auth_threshold),
            RequestBurstDetector(window_seconds=10, threshold=burst_threshold),
            SensitiveEndpointDetector(),
        ]

    def process(self, entry: LogEntry) -> List[SecurityAlert]:
        alerts = []
        for detector in self.detectors:
            alerts.extend(detector.inspect(entry))
        return alerts