"""
Pytest configuration and fixtures
"""
import pytest
import tempfile
import os
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import ScanTarget, ScanResult, Vulnerability, ScanStatus, SeverityLevel


@pytest.fixture
def sample_target():
    """Sample scan target fixture"""
    return ScanTarget("192.168.1.100", [80, 443])


@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability fixture"""
    return Vulnerability(
        id="12345",
        name="Test Vulnerability",
        severity=SeverityLevel.HIGH,
        description="This is a test vulnerability description",
        solution="Update the software to the latest version",
        reference="https://example.com/security-advisory",
        cve_id="CVE-2023-12345",
        cvss_score=7.5,
        affected_url="http://192.168.1.100/vulnerable-page",
        affected_parameter="id",
        evidence="GET /vulnerable-page?id=1 HTTP/1.1"
    )


@pytest.fixture
def sample_scan_result(sample_target, sample_vulnerability):
    """Sample scan result fixture"""
    return ScanResult(
        scan_id="test-scan-12345",
        scanner_name="Test Scanner",
        target=sample_target,
        status=ScanStatus.COMPLETED,
        start_time=datetime(2023, 1, 1, 12, 0, 0),
        end_time=datetime(2023, 1, 1, 12, 5, 30),
        vulnerabilities=[sample_vulnerability],
        scan_options={"timeout": 300, "ssl": True}
    )


@pytest.fixture
def temp_directory():
    """Temporary directory fixture"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def sample_nikto_xml():
    """Sample Nikto XML output"""
    return '''<?xml version="1.0"?>
<niktoscan>
    <scandetails targetip="192.168.1.100" targethostname="example.com" targetport="80" targetbanner="Apache/2.4.41">
        <item id="123" osvdb="456" method="GET">
            <uri>/admin/</uri>
            <namelink>Admin Directory</namelink>
            <description>Admin directory found. This may allow unauthorized access.</description>
        </item>
        <item id="124" osvdb="457" method="GET">
            <uri>/backup.sql</uri>
            <namelink>Database Backup</namelink>
            <description>Database backup file found. This may contain sensitive information.</description>
        </item>
    </scandetails>
</niktoscan>'''


@pytest.fixture
def sample_zap_alerts():
    """Sample ZAP alerts data"""
    return [
        {
            "id": "1",
            "name": "Cross Site Scripting (Reflected)",
            "risk": "High",
            "confidence": "Medium",
            "url": "http://example.com/search",
            "param": "q",
            "description": "Cross-site Scripting (XSS) is possible",
            "solution": "Validate all input and encode output",
            "reference": "https://owasp.org/www-project-top-ten/",
            "cweid": "79",
            "wascid": "8",
            "evidence": "<script>alert('XSS')</script>"
        },
        {
            "id": "2",
            "name": "SQL Injection",
            "risk": "High",
            "confidence": "High",
            "url": "http://example.com/product",
            "param": "id",
            "description": "SQL Injection may be possible",
            "solution": "Use parameterized queries",
            "reference": "https://owasp.org/www-project-top-ten/",
            "cweid": "89",
            "wascid": "19",
            "evidence": "MySQL error: You have an error in your SQL syntax"
        }
    ]


@pytest.fixture
def sample_tenable_vulnerabilities():
    """Sample Tenable vulnerability data"""
    return [
        {
            "plugin_id": 12345,
            "plugin_name": "Apache HTTP Server Version Detection",
            "severity": 0,
            "count": 1
        },
        {
            "plugin_id": 67890,
            "plugin_name": "SSL Certificate Information",
            "severity": 0,
            "count": 1
        },
        {
            "plugin_id": 11111,
            "plugin_name": "HTTP Server Type and Version",
            "severity": 1,
            "count": 1
        }
    ]


@pytest.fixture
def sample_openvas_results():
    """Sample OpenVAS results XML"""
    return '''<results>
        <result id="1">
            <name>HTTP Server Type and Version</name>
            <description>The remote HTTP server type and version</description>
            <host>192.168.1.100</host>
            <port>80/tcp</port>
            <threat>Log</threat>
            <severity>0.0</severity>
            <nvt oid="1.3.6.1.4.1.25623.1.0.10107">
                <name>HTTP Server Type and Version</name>
                <tags>summary=Detect HTTP server type and version|solution=N/A</tags>
                <solution>N/A</solution>
            </nvt>
        </result>
        <result id="2">
            <name>SSL/TLS: Certificate Information</name>
            <description>This script displays SSL certificate information</description>
            <host>192.168.1.100</host>
            <port>443/tcp</port>
            <threat>Log</threat>
            <severity>0.0</severity>
            <nvt oid="1.3.6.1.4.1.25623.1.0.103692">
                <name>SSL/TLS: Certificate Information</name>
                <tags>summary=SSL certificate information|solution=N/A</tags>
                <solution>N/A</solution>
            </nvt>
        </result>
    </results>'''


# Test configuration
def pytest_configure(config):
    """Pytest configuration"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    for item in items:
        # Add unit marker to all tests by default
        if not any(mark.name in ['integration', 'slow'] for mark in item.iter_markers()):
            item.add_marker(pytest.mark.unit)