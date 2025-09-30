"""
Tests for Nikto API
"""
import pytest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nikto_api.app import app
from nikto_api.nikto_scanner import NiktoScanner
from common import ScanTarget, ScanStatus


@pytest.fixture
def client():
    """Test client fixture"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_nikto_scanner():
    """Mock Nikto scanner fixture"""
    with patch('nikto_api.app.scanner') as mock_scanner:
        mock_scanner.is_nikto_available.return_value = True
        mock_scanner.get_nikto_version.return_value = "2.1.6"
        mock_scanner.get_supported_formats.return_value = ['json', 'xml', 'csv', 'txt', 'html']
        yield mock_scanner


class TestNiktoAPI:
    """Test cases for Nikto API"""

    def test_health_check(self, client, mock_nikto_scanner):
        """Test health check endpoint"""
        response = client.get('/health')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['service'] == 'Nikto API'
        assert 'nikto_available' in data
        assert 'supported_formats' in data

    def test_create_scan_success(self, client, mock_nikto_scanner):
        """Test successful scan creation"""
        mock_nikto_scanner.scan.return_value = "test-scan-id"

        response = client.post('/api/nikto/scan',
                             json={
                                 'target_ip': '192.168.1.100',
                                 'ports': [80, 443],
                                 'scan_options': {'timeout': 300}
                             })

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['scan_id'] == 'test-scan-id'
        assert data['data']['target_ip'] == '192.168.1.100'

    def test_create_scan_missing_body(self, client, mock_nikto_scanner):
        """Test scan creation with missing request body"""
        response = client.post('/api/nikto/scan')

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error_code'] == 'INVALID_REQUEST'

    def test_create_scan_invalid_target(self, client, mock_nikto_scanner):
        """Test scan creation with invalid target"""
        response = client.post('/api/nikto/scan',
                             json={
                                 'target_ip': '',
                                 'ports': []
                             })

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error_code'] == 'VALIDATION_ERROR'

    def test_get_scan_status_found(self, client, mock_nikto_scanner):
        """Test getting scan status for existing scan"""
        from common import ScanResult, ScanStatus, ScanTarget
        from datetime import datetime

        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="Nikto",
            target=ScanTarget("192.168.1.100", [80, 443]),
            status=ScanStatus.COMPLETED,
            start_time=datetime.now()
        )
        mock_nikto_scanner.get_scan_result.return_value = mock_result

        response = client.get('/api/nikto/scan/test-scan-id/status')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['scan_id'] == 'test-scan-id'
        assert data['data']['status'] == 'completed'

    def test_get_scan_status_not_found(self, client, mock_nikto_scanner):
        """Test getting scan status for non-existent scan"""
        mock_nikto_scanner.get_scan_result.return_value = None

        response = client.get('/api/nikto/scan/non-existent-id/status')

        assert response.status_code == 404
        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error_code'] == 'SCAN_NOT_FOUND'

    def test_get_scan_results_json(self, client, mock_nikto_scanner):
        """Test getting scan results in JSON format"""
        from common import ScanResult, ScanStatus, ScanTarget, Vulnerability, SeverityLevel
        from datetime import datetime

        vuln = Vulnerability(
            id="12345",
            name="Test Vulnerability",
            severity=SeverityLevel.HIGH,
            description="Test description",
            solution="Test solution"
        )

        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="Nikto",
            target=ScanTarget("192.168.1.100", [80]),
            status=ScanStatus.COMPLETED,
            start_time=datetime.now(),
            vulnerabilities=[vuln]
        )
        mock_nikto_scanner.get_scan_result.return_value = mock_result

        response = client.get('/api/nikto/scan/test-scan-id/results?format=json')

        assert response.status_code == 200
        # Should return JSON content
        data = json.loads(response.data)
        assert 'scan_id' in data
        assert data['vulnerability_count'] == 1

    def test_get_scan_results_unsupported_format(self, client, mock_nikto_scanner):
        """Test getting scan results with unsupported format"""
        from common import ScanResult, ScanStatus, ScanTarget
        from datetime import datetime

        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="Nikto",
            target=ScanTarget("192.168.1.100", [80]),
            status=ScanStatus.COMPLETED,
            start_time=datetime.now()
        )
        mock_nikto_scanner.get_scan_result.return_value = mock_result

        response = client.get('/api/nikto/scan/test-scan-id/results?format=unsupported')

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error_code'] == 'UNSUPPORTED_FORMAT'

    def test_stop_scan_success(self, client, mock_nikto_scanner):
        """Test successful scan stopping"""
        mock_nikto_scanner.stop_scan.return_value = True

        response = client.delete('/api/nikto/scan/test-scan-id')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True

    def test_stop_scan_failure(self, client, mock_nikto_scanner):
        """Test scan stopping failure"""
        mock_nikto_scanner.stop_scan.return_value = False

        response = client.delete('/api/nikto/scan/test-scan-id')

        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error_code'] == 'STOP_FAILED'

    def test_list_scans(self, client, mock_nikto_scanner):
        """Test listing all scans"""
        mock_scans = [
            {
                'scan_id': 'scan-1',
                'scanner': 'Nikto',
                'target_ip': '192.168.1.100',
                'status': 'completed',
                'vulnerability_count': 5
            },
            {
                'scan_id': 'scan-2',
                'scanner': 'Nikto',
                'target_ip': '192.168.1.101',
                'status': 'running',
                'vulnerability_count': 0
            }
        ]
        mock_nikto_scanner.list_scans.return_value = mock_scans

        response = client.get('/api/nikto/scans')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['total_count'] == 2
        assert len(data['data']['scans']) == 2

    def test_get_scanner_info(self, client, mock_nikto_scanner):
        """Test getting scanner information"""
        response = client.get('/api/nikto/info')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['scanner_name'] == 'Nikto'
        assert 'version' in data
        assert 'supported_formats' in data


class TestNiktoScanner:
    """Test cases for NiktoScanner class"""

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        scanner = NiktoScanner("/usr/bin/nikto")
        assert scanner.name == "Nikto"
        assert scanner.nikto_path == "/usr/bin/nikto"

    @patch('subprocess.run')
    def test_is_nikto_available_true(self, mock_subprocess):
        """Test Nikto availability check when available"""
        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = "Nikto 2.1.6"

        scanner = NiktoScanner()
        assert scanner.is_nikto_available() is True

    @patch('subprocess.run')
    def test_is_nikto_available_false(self, mock_subprocess):
        """Test Nikto availability check when not available"""
        mock_subprocess.side_effect = FileNotFoundError()

        scanner = NiktoScanner()
        assert scanner.is_nikto_available() is False

    def test_validate_target_valid(self):
        """Test target validation with valid target"""
        scanner = NiktoScanner()
        target = ScanTarget("192.168.1.100", [80, 443])
        assert scanner.validate_target(target) is True

    def test_validate_target_invalid_ip(self):
        """Test target validation with invalid IP"""
        scanner = NiktoScanner()
        target = ScanTarget("invalid-ip", [80])
        assert scanner.validate_target(target) is False

    def test_validate_target_invalid_port(self):
        """Test target validation with invalid port"""
        scanner = NiktoScanner()
        target = ScanTarget("192.168.1.100", [99999])
        assert scanner.validate_target(target) is False

    def test_get_supported_formats(self):
        """Test getting supported formats"""
        scanner = NiktoScanner()
        formats = scanner.get_supported_formats()
        expected_formats = ['json', 'xml', 'csv', 'txt', 'html']
        assert all(fmt in formats for fmt in expected_formats)

    @patch('nikto_api.nikto_scanner.subprocess.run')
    def test_scan_single_url_success(self, mock_subprocess):
        """Test scanning single URL successfully"""
        # Mock successful nikto execution
        mock_subprocess.return_value.returncode = 0

        # Create mock XML output
        xml_content = '''<?xml version="1.0"?>
        <niktoscan>
            <scandetails>
                <item id="123" osvdb="456" method="GET">
                    <uri>/test</uri>
                    <description>Test vulnerability</description>
                </item>
            </scandetails>
        </niktoscan>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            temp_file.write(xml_content)
            temp_file_path = temp_file.name

        scanner = NiktoScanner()

        # Mock the _scan_single_url method to use our temp file
        with patch.object(scanner, '_scan_single_url') as mock_scan:
            mock_scan.return_value = []  # Return empty list for simplicity

            target = ScanTarget("example.com", [80])
            scan_id = scanner.scan(target)

            assert scan_id is not None
            assert scan_id in scanner.active_scans

        # Cleanup
        os.unlink(temp_file_path)


if __name__ == '__main__':
    pytest.main([__file__])