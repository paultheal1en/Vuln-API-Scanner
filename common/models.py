"""
Common data models for vulnerability scanners
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class ScanTarget:
    """Target configuration for scanning"""
    ip_address: str
    ports: List[int]
    protocol: str = "tcp"

    def __post_init__(self):
        if not self.ip_address:
            raise ValueError("IP address is required")
        if not self.ports:
            raise ValueError("At least one port is required")


@dataclass
class Vulnerability:
    """Individual vulnerability finding"""
    id: str
    name: str
    severity: SeverityLevel
    description: str
    solution: str = ""
    reference: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    affected_url: str = ""
    affected_parameter: str = ""
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'severity': self.severity.value,
            'description': self.description,
            'solution': self.solution,
            'reference': self.reference,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'affected_url': self.affected_url,
            'affected_parameter': self.affected_parameter,
            'evidence': self.evidence
        }


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    scanner_name: str
    target: ScanTarget
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scan_options: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    error_message: str = ""

    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds"""
        if self.end_time and self.start_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def severity_summary(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        summary = {level.value: 0 for level in SeverityLevel}
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] += 1
        return summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            'scan_id': self.scan_id,
            'scanner_name': self.scanner_name,
            'target': {
                'ip_address': self.target.ip_address,
                'ports': self.target.ports,
                'protocol': self.target.protocol
            },
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': self.duration,
            'vulnerability_count': self.vulnerability_count,
            'severity_summary': self.severity_summary,
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities],
            'scan_options': self.scan_options,
            'error_message': self.error_message
        }


@dataclass
class APIResponse:
    """Standardized API response"""
    success: bool
    data: Any = None
    message: str = ""
    error_code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        response = {
            'success': self.success,
            'message': self.message
        }

        if self.success:
            response['data'] = self.data
        else:
            response['error_code'] = self.error_code

        return response


@dataclass
class ScanRequest:
    """Scan request model"""
    target_ip: str
    ports: List[int]
    scan_options: Dict[str, Any] = field(default_factory=dict)

    def to_scan_target(self) -> ScanTarget:
        return ScanTarget(
            ip_address=self.target_ip,
            ports=self.ports
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanRequest':
        return cls(
            target_ip=data.get('target_ip', ''),
            ports=data.get('ports', []),
            scan_options=data.get('scan_options', {})
        )