"""
Common utilities for vulnerability scanners
"""
import ipaddress
import re
import logging
import os
from typing import List, Dict, Any, Optional
from datetime import datetime


def setup_logging(name: str, level: str = "INFO") -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, level.upper()))
    return logger


def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range (CIDR notation)"""
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Validate port number"""
    return isinstance(port, int) and 1 <= port <= 65535


def validate_port_range(port_range: str) -> bool:
    """Validate port range (e.g., '80-443')"""
    try:
        if '-' in port_range:
            start, end = port_range.split('-', 1)
            start_port = int(start.strip())
            end_port = int(end.strip())
            return validate_port(start_port) and validate_port(end_port) and start_port <= end_port
        else:
            return validate_port(int(port_range))
    except ValueError:
        return False


def parse_port_list(ports_input: str) -> List[int]:
    """Parse comma-separated port list or ranges"""
    ports = []

    for part in ports_input.split(','):
        part = part.strip()

        if '-' in part:
            # Port range
            try:
                start, end = part.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())

                if validate_port(start_port) and validate_port(end_port) and start_port <= end_port:
                    ports.extend(range(start_port, end_port + 1))
            except ValueError:
                continue
        else:
            # Single port
            try:
                port = int(part)
                if validate_port(port):
                    ports.append(port)
            except ValueError:
                continue

    return sorted(list(set(ports)))  # Remove duplicates and sort


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations"""
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]

    return sanitized or "scan_result"


def get_severity_score(severity: str) -> int:
    """Convert severity level to numeric score for sorting"""
    severity_map = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'informational': 1,
        'info': 1
    }
    return severity_map.get(severity.lower(), 0)


def format_duration(seconds: float) -> str:
    """Format duration in human-readable format"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} hours"


def generate_unique_filename(base_name: str, extension: str, directory: str = "/tmp") -> str:
    """Generate unique filename to avoid conflicts"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"{base_name}_{timestamp}.{extension}"
    return os.path.join(directory, sanitize_filename(filename))


def safe_get_nested_value(data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
    """Safely get nested dictionary value"""
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default

    return current


def merge_scan_options(default_options: Dict[str, Any], user_options: Dict[str, Any]) -> Dict[str, Any]:
    """Merge user options with default options"""
    merged = default_options.copy()

    for key, value in user_options.items():
        if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
            merged[key] = merge_scan_options(merged[key], value)
        else:
            merged[key] = value

    return merged


def convert_to_urls(ip_address: str, ports: List[int], protocols: List[str] = None) -> List[str]:
    """Convert IP and ports to list of URLs"""
    if protocols is None:
        protocols = ['http', 'https']

    urls = []

    for port in ports:
        for protocol in protocols:
            # Skip common protocol/port mismatches
            if protocol == 'https' and port == 80:
                continue
            if protocol == 'http' and port == 443:
                continue

            # Use default ports without explicit port number
            if (protocol == 'http' and port == 80) or (protocol == 'https' and port == 443):
                urls.append(f"{protocol}://{ip_address}")
            else:
                urls.append(f"{protocol}://{ip_address}:{port}")

    return urls


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return None


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private/internal"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_common_ports() -> Dict[str, List[int]]:
    """Get common ports for different services"""
    return {
        'web': [80, 443, 8080, 8443, 8000, 8001, 8008, 3000, 9000],
        'ftp': [21, 22],
        'ssh': [22],
        'telnet': [23],
        'smtp': [25, 587, 465],
        'dns': [53],
        'http': [80, 8080, 8000, 8001, 8008, 3000, 9000],
        'https': [443, 8443],
        'pop3': [110, 995],
        'imap': [143, 993],
        'snmp': [161, 162],
        'ldap': [389, 636],
        'smb': [445, 139],
        'rdp': [3389],
        'vnc': [5900, 5901, 5902],
        'mysql': [3306],
        'postgresql': [5432],
        'mongodb': [27017],
        'redis': [6379],
        'all_common': [21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 993, 995, 3389, 5432, 5900, 3306, 6379, 8080, 8443]
    }


def filter_ports_by_service(ports: List[int], service: str) -> List[int]:
    """Filter ports by service type"""
    common_ports = get_common_ports()
    service_ports = common_ports.get(service.lower(), [])

    return [port for port in ports if port in service_ports]


class RateLimiter:
    """Simple rate limiter for API calls"""

    def __init__(self, max_calls: int, time_window: float):
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []

    def allow_request(self) -> bool:
        """Check if request is allowed based on rate limit"""
        now = datetime.now().timestamp()

        # Remove old calls outside time window
        self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]

        # Check if we can make another call
        if len(self.calls) < self.max_calls:
            self.calls.append(now)
            return True

        return False

    def time_until_next_call(self) -> float:
        """Get time in seconds until next call is allowed"""
        if len(self.calls) < self.max_calls:
            return 0.0

        oldest_call = min(self.calls)
        return self.time_window - (datetime.now().timestamp() - oldest_call)