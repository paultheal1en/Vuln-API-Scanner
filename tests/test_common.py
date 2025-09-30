"""
Tests for common modules
"""
import pytest
from datetime import datetime

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (
    ScanTarget, ScanResult, Vulnerability, ScanStatus, SeverityLevel,
    APIResponse, ScanRequest, JSONFormatter, XMLFormatter, CSVFormatter,
    TXTFormatter, HTMLFormatter, validate_ip_address, validate_port,
    parse_port_list, convert_to_urls
)


class TestModels:
    """Test cases for data models"""

    def test_scan_target_creation(self):
        """Test ScanTarget creation"""
        target = ScanTarget("192.168.1.100", [80, 443])
        assert target.ip_address == "192.168.1.100"
        assert target.ports == [80, 443]
        assert target.protocol == "tcp"

    def test_scan_target_validation(self):
        """Test ScanTarget validation"""
        # Valid target
        target = ScanTarget("192.168.1.100", [80])
        # Should not raise exception

        # Invalid IP
        with pytest.raises(ValueError):
            ScanTarget("", [80])

        # Invalid ports
        with pytest.raises(ValueError):
            ScanTarget("192.168.1.100", [])

    def test_vulnerability_creation(self):
        """Test Vulnerability creation"""
        vuln = Vulnerability(
            id="12345",
            name="Test Vulnerability",
            severity=SeverityLevel.HIGH,
            description="Test description",
            solution="Test solution"
        )

        assert vuln.id == "12345"
        assert vuln.name == "Test Vulnerability"
        assert vuln.severity == SeverityLevel.HIGH
        assert vuln.description == "Test description"

    def test_vulnerability_to_dict(self):
        """Test Vulnerability to_dict method"""
        vuln = Vulnerability(
            id="12345",
            name="Test Vulnerability",
            severity=SeverityLevel.MEDIUM,
            description="Test description",
            cve_id="CVE-2023-12345",
            cvss_score=6.5
        )

        vuln_dict = vuln.to_dict()
        assert vuln_dict['id'] == "12345"
        assert vuln_dict['severity'] == "medium"
        assert vuln_dict['cve_id'] == "CVE-2023-12345"
        assert vuln_dict['cvss_score'] == 6.5

    def test_scan_result_creation(self):
        """Test ScanResult creation"""
        target = ScanTarget("192.168.1.100", [80])
        result = ScanResult(
            scan_id="test-scan",
            scanner_name="Test Scanner",
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now()
        )

        assert result.scan_id == "test-scan"
        assert result.scanner_name == "Test Scanner"
        assert result.status == ScanStatus.RUNNING
        assert result.vulnerability_count == 0

    def test_scan_result_with_vulnerabilities(self):
        """Test ScanResult with vulnerabilities"""
        target = ScanTarget("192.168.1.100", [80])
        vuln1 = Vulnerability(
            id="1", name="Vuln 1", severity=SeverityLevel.HIGH, description="Desc 1"
        )
        vuln2 = Vulnerability(
            id="2", name="Vuln 2", severity=SeverityLevel.MEDIUM, description="Desc 2"
        )

        result = ScanResult(
            scan_id="test-scan",
            scanner_name="Test Scanner",
            target=target,
            status=ScanStatus.COMPLETED,
            start_time=datetime.now(),
            vulnerabilities=[vuln1, vuln2]
        )

        assert result.vulnerability_count == 2
        severity_summary = result.severity_summary
        assert severity_summary['high'] == 1
        assert severity_summary['medium'] == 1
        assert severity_summary['low'] == 0

    def test_scan_result_duration(self):
        """Test ScanResult duration calculation"""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        end_time = datetime(2023, 1, 1, 12, 5, 30)

        target = ScanTarget("192.168.1.100", [80])
        result = ScanResult(
            scan_id="test-scan",
            scanner_name="Test Scanner",
            target=target,
            status=ScanStatus.COMPLETED,
            start_time=start_time,
            end_time=end_time
        )

        assert result.duration == 330.0  # 5 minutes 30 seconds

    def test_api_response_success(self):
        """Test APIResponse for success case"""
        response = APIResponse(
            success=True,
            data={"key": "value"},
            message="Operation successful"
        )

        response_dict = response.to_dict()
        assert response_dict['success'] is True
        assert response_dict['data'] == {"key": "value"}
        assert response_dict['message'] == "Operation successful"
        assert 'error_code' not in response_dict

    def test_api_response_error(self):
        """Test APIResponse for error case"""
        response = APIResponse(
            success=False,
            message="Operation failed",
            error_code="VALIDATION_ERROR"
        )

        response_dict = response.to_dict()
        assert response_dict['success'] is False
        assert response_dict['message'] == "Operation failed"
        assert response_dict['error_code'] == "VALIDATION_ERROR"
        assert 'data' not in response_dict

    def test_scan_request_creation(self):
        """Test ScanRequest creation"""
        request = ScanRequest(
            target_ip="192.168.1.100",
            ports=[80, 443],
            scan_options={"timeout": 300}
        )

        assert request.target_ip == "192.168.1.100"
        assert request.ports == [80, 443]
        assert request.scan_options == {"timeout": 300}

    def test_scan_request_from_dict(self):
        """Test ScanRequest from_dict method"""
        data = {
            "target_ip": "192.168.1.100",
            "ports": [80, 443],
            "scan_options": {"timeout": 300}
        }

        request = ScanRequest.from_dict(data)
        assert request.target_ip == "192.168.1.100"
        assert request.ports == [80, 443]
        assert request.scan_options == {"timeout": 300}

    def test_scan_request_to_scan_target(self):
        """Test ScanRequest to_scan_target method"""
        request = ScanRequest(
            target_ip="192.168.1.100",
            ports=[80, 443]
        )

        target = request.to_scan_target()
        assert isinstance(target, ScanTarget)
        assert target.ip_address == "192.168.1.100"
        assert target.ports == [80, 443]


class TestFormatters:
    """Test cases for output formatters"""

    def setup_method(self):
        """Setup test data"""
        target = ScanTarget("192.168.1.100", [80, 443])
        vuln = Vulnerability(
            id="12345",
            name="Test Vulnerability",
            severity=SeverityLevel.HIGH,
            description="Test description",
            solution="Test solution",
            cve_id="CVE-2023-12345",
            cvss_score=7.5
        )

        self.scan_result = ScanResult(
            scan_id="test-scan",
            scanner_name="Test Scanner",
            target=target,
            status=ScanStatus.COMPLETED,
            start_time=datetime(2023, 1, 1, 12, 0, 0),
            end_time=datetime(2023, 1, 1, 12, 5, 30),
            vulnerabilities=[vuln]
        )

    def test_json_formatter(self):
        """Test JSON formatter"""
        formatter = JSONFormatter()
        output = formatter.format(self.scan_result)

        assert isinstance(output, str)
        import json
        data = json.loads(output)
        assert data['scan_id'] == "test-scan"
        assert data['vulnerability_count'] == 1
        assert data['status'] == "completed"

    def test_json_formatter_content_type(self):
        """Test JSON formatter content type"""
        formatter = JSONFormatter()
        assert formatter.get_content_type() == "application/json"
        assert formatter.get_file_extension() == "json"

    def test_xml_formatter(self):
        """Test XML formatter"""
        formatter = XMLFormatter()
        output = formatter.format(self.scan_result)

        assert isinstance(output, str)
        assert output.startswith('<?xml') or output.startswith('<vulnerability_scan')
        assert 'test-scan' in output
        assert 'Test Vulnerability' in output

    def test_xml_formatter_content_type(self):
        """Test XML formatter content type"""
        formatter = XMLFormatter()
        assert formatter.get_content_type() == "application/xml"
        assert formatter.get_file_extension() == "xml"

    def test_csv_formatter(self):
        """Test CSV formatter"""
        formatter = CSVFormatter()
        output = formatter.format(self.scan_result)

        assert isinstance(output, str)
        lines = output.strip().split('\n')
        assert len(lines) >= 2  # Header + at least one data row
        assert 'Scan ID' in lines[0]  # Header
        assert 'test-scan' in lines[1]  # Data

    def test_csv_formatter_content_type(self):
        """Test CSV formatter content type"""
        formatter = CSVFormatter()
        assert formatter.get_content_type() == "text/csv"
        assert formatter.get_file_extension() == "csv"

    def test_txt_formatter(self):
        """Test TXT formatter"""
        formatter = TXTFormatter()
        output = formatter.format(self.scan_result)

        assert isinstance(output, str)
        assert "TEST SCANNER VULNERABILITY SCAN REPORT" in output
        assert "test-scan" in output
        assert "Test Vulnerability" in output
        assert "SUMMARY" in output

    def test_txt_formatter_content_type(self):
        """Test TXT formatter content type"""
        formatter = TXTFormatter()
        assert formatter.get_content_type() == "text/plain"
        assert formatter.get_file_extension() == "txt"

    def test_html_formatter(self):
        """Test HTML formatter"""
        formatter = HTMLFormatter()
        output = formatter.format(self.scan_result)

        assert isinstance(output, str)
        assert output.startswith('<!DOCTYPE html')
        assert '<html' in output
        assert 'test-scan' in output
        assert 'Test Vulnerability' in output

    def test_html_formatter_content_type(self):
        """Test HTML formatter content type"""
        formatter = HTMLFormatter()
        assert formatter.get_content_type() == "text/html"
        assert formatter.get_file_extension() == "html"

    def test_formatter_filename_generation(self):
        """Test formatter filename generation"""
        formatter = JSONFormatter()
        filename = formatter.get_filename(self.scan_result)

        assert filename.endswith('.json')
        assert 'test_scanner' in filename
        assert '192_168_1_100' in filename

    def test_formatter_validation_invalid_result(self):
        """Test formatter validation with invalid result"""
        formatter = JSONFormatter()

        with pytest.raises(ValueError):
            formatter.format(None)


class TestUtils:
    """Test cases for utility functions"""

    def test_validate_ip_address_valid(self):
        """Test IP address validation with valid IPs"""
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("10.0.0.1") is True
        assert validate_ip_address("127.0.0.1") is True
        assert validate_ip_address("::1") is True
        assert validate_ip_address("2001:db8::1") is True

    def test_validate_ip_address_invalid(self):
        """Test IP address validation with invalid IPs"""
        assert validate_ip_address("999.999.999.999") is False
        assert validate_ip_address("not-an-ip") is False
        assert validate_ip_address("") is False
        assert validate_ip_address("192.168.1") is False

    def test_validate_port_valid(self):
        """Test port validation with valid ports"""
        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(1) is True
        assert validate_port(65535) is True

    def test_validate_port_invalid(self):
        """Test port validation with invalid ports"""
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False
        assert validate_port("80") is False

    def test_parse_port_list_single_ports(self):
        """Test parsing single ports"""
        ports = parse_port_list("80,443,8080")
        assert ports == [80, 443, 8080]

    def test_parse_port_list_ranges(self):
        """Test parsing port ranges"""
        ports = parse_port_list("80-82,443")
        assert ports == [80, 81, 82, 443]

    def test_parse_port_list_mixed(self):
        """Test parsing mixed ports and ranges"""
        ports = parse_port_list("80,443,8000-8002")
        assert ports == [80, 443, 8000, 8001, 8002]

    def test_parse_port_list_duplicates(self):
        """Test parsing with duplicates (should be removed)"""
        ports = parse_port_list("80,80,443")
        assert ports == [80, 443]

    def test_convert_to_urls(self):
        """Test converting IP and ports to URLs"""
        urls = convert_to_urls("192.168.1.100", [80, 443])

        assert "http://192.168.1.100" in urls
        assert "https://192.168.1.100" in urls
        assert len(urls) == 2

    def test_convert_to_urls_custom_ports(self):
        """Test converting IP and custom ports to URLs"""
        urls = convert_to_urls("192.168.1.100", [8080, 8443])

        assert "http://192.168.1.100:8080" in urls
        assert "https://192.168.1.100:8443" in urls

    def test_convert_to_urls_single_protocol(self):
        """Test converting with single protocol"""
        urls = convert_to_urls("192.168.1.100", [80], ['http'])

        assert urls == ["http://192.168.1.100"]


if __name__ == '__main__':
    pytest.main([__file__])