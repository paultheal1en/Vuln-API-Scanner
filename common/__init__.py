"""
Common utilities and base classes for vulnerability scanners
"""

from .models import (
    ScanTarget,
    ScanResult,
    Vulnerability,
    ScanStatus,
    SeverityLevel,
    APIResponse,
    ScanRequest
)

from .base_scanner import BaseScanner

from .base_formatter import (
    BaseFormatter,
    JSONFormatter,
    XMLFormatter,
    CSVFormatter,
    TXTFormatter,
    HTMLFormatter
)

from .utils import (
    setup_logging,
    validate_ip_address,
    validate_port,
    parse_port_list,
    sanitize_filename,
    get_severity_score,
    format_duration,
    convert_to_urls,
    get_common_ports,
    RateLimiter
)

__all__ = [
    # Models
    'ScanTarget',
    'ScanResult',
    'Vulnerability',
    'ScanStatus',
    'SeverityLevel',
    'APIResponse',
    'ScanRequest',

    # Base classes
    'BaseScanner',
    'BaseFormatter',

    # Formatters
    'JSONFormatter',
    'XMLFormatter',
    'CSVFormatter',
    'TXTFormatter',
    'HTMLFormatter',

    # Utilities
    'setup_logging',
    'validate_ip_address',
    'validate_port',
    'parse_port_list',
    'sanitize_filename',
    'get_severity_score',
    'format_duration',
    'convert_to_urls',
    'get_common_ports',
    'RateLimiter'
]