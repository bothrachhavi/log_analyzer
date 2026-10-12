from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict


@dataclass(frozen=True)
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    endpoint: str
    status: int
    bytes_sent: int


@dataclass(frozen=True)
class SecurityAlert:
    rule_name: str
    ip: str
    severity: str
    timestamp: datetime
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule_name,
            "ip": self.ip,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }