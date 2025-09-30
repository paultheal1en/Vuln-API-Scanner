"""
Abstract base class for vulnerability scanners
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import uuid
from datetime import datetime
import logging

from .models import ScanTarget, ScanResult, ScanStatus, Vulnerability


class BaseScanner(ABC):
    """Abstract base class for all vulnerability scanners"""

    def __init__(self, name: str):
        self.name = name
        self.logger = logging.getLogger(f"scanner.{name.lower()}")
        self.active_scans: Dict[str, ScanResult] = {}

    @abstractmethod
    def scan(self, target: ScanTarget, options: Dict[str, Any] = None) -> str:
        """
        Start a vulnerability scan

        Args:
            target: Target configuration (IP + ports)
            options: Scanner-specific options

        Returns:
            scan_id: Unique identifier for the scan
        """
        pass

    @abstractmethod
    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Get current status of a scan"""
        pass

    @abstractmethod
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get complete scan result"""
        pass

    @abstractmethod
    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan"""
        pass

    def generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        return str(uuid.uuid4())

    def create_scan_result(self, scan_id: str, target: ScanTarget, options: Dict[str, Any] = None) -> ScanResult:
        """Create new scan result object"""
        return ScanResult(
            scan_id=scan_id,
            scanner_name=self.name,
            target=target,
            status=ScanStatus.PENDING,
            start_time=datetime.now(),
            scan_options=options or {}
        )

    def update_scan_status(self, scan_id: str, status: ScanStatus) -> None:
        """Update scan status"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id].status = status
            if status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.STOPPED]:
                self.active_scans[scan_id].end_time = datetime.now()

    def add_vulnerability(self, scan_id: str, vulnerability: Vulnerability) -> None:
        """Add vulnerability to scan result"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id].vulnerabilities.append(vulnerability)

    def set_error(self, scan_id: str, error_message: str) -> None:
        """Set error message for scan"""
        if scan_id in self.active_scans:
            self.active_scans[scan_id].error_message = error_message
            self.active_scans[scan_id].status = ScanStatus.FAILED

    def validate_target(self, target: ScanTarget) -> bool:
        """Validate scan target"""
        try:
            # Basic IP validation
            import ipaddress
            ipaddress.ip_address(target.ip_address)

            # Port validation
            for port in target.ports:
                if not isinstance(port, int) or port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {port}")

            return True
        except Exception as e:
            self.logger.error(f"Target validation failed: {e}")
            return False

    def list_scans(self) -> List[Dict[str, Any]]:
        """List all scans with basic info"""
        return [
            {
                'scan_id': scan_id,
                'scanner': result.scanner_name,
                'target_ip': result.target.ip_address,
                'status': result.status.value,
                'start_time': result.start_time.isoformat(),
                'vulnerability_count': result.vulnerability_count
            }
            for scan_id, result in self.active_scans.items()
        ]

    def cleanup_old_scans(self, max_age_hours: int = 24) -> int:
        """Remove old scan results"""
        cutoff_time = datetime.now().timestamp() - (max_age_hours * 3600)
        old_scans = [
            scan_id for scan_id, result in self.active_scans.items()
            if result.start_time.timestamp() < cutoff_time
        ]

        for scan_id in old_scans:
            del self.active_scans[scan_id]

        return len(old_scans)

    def get_scanner_info(self) -> Dict[str, Any]:
        """Get scanner information"""
        return {
            'name': self.name,
            'active_scans': len(self.active_scans),
            'supported_formats': self.get_supported_formats()
        }

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported output formats"""
        pass