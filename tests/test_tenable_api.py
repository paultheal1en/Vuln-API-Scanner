"""
Tests for Tenable API
"""
import pytest
import json
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tenable_api.app import app
from common import ScanTarget, ScanStatus, ScanResult, Vulnerability, SeverityLevel
from datetime import datetime


@pytest.fixture
def client():
    """Test client fixture"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_tenable_scanner():
    """Mock Tenable scanner fixture"""
    with patch('tenable_api.app.scanner') as mock_scanner:
        mock_scanner.is_tenable_available.return_value = True
        mock_scanner.get_tenable_version.return_value = "8.15.1"
        mock_scanner.get_supported_formats.return_value = ['json', 'xml', 'csv', 'txt', 'html']
        yield mock_scanner


class TestTenableAPI:
    """Test cases for Tenable API"""

    def test_health_check_with_credentials(self, client, mock_tenable_scanner):
        """Test health check endpoint with credentials configured"""
        with patch.dict(os.environ, {
            'TENABLE_ACCESS_KEY': 'test-access-key',
            'TENABLE_SECRET_KEY': 'test-secret-key'
        }):
            response = client.get('/health')
            assert response.status_code == 200

            data = json.loads(response.data)
            assert data['service'] == 'Tenable Nessus API'
            assert data['credentials_configured'] is True
            assert 'tenable_available' in data

    def test_health_check_without_credentials(self, client):
        """Test health check endpoint without credentials"""
        with patch.dict(os.environ, {}, clear=True):
            response = client.get('/health')
            assert response.status_code == 200

            data = json.loads(response.data)
            assert data['credentials_configured'] is False

    def test_create_scan_success(self, client, mock_tenable_scanner):
        """Test successful scan creation"""
        mock_tenable_scanner.scan.return_value = "test-scan-id"

        response = client.post('/api/tenable/scan',
                             json={
                                 'target_ip': '192.168.1.100',
                                 'ports': [22, 80, 443],
                                 'scan_options': {
                                     'policy_id': 'basic-network-scan',
                                     'scan_timeout': 3600
                                 }
                             })

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['scan_id'] == 'test-scan-id'
        assert data['data']['policy_id'] == 'basic-network-scan'

    def test_create_scan_without_credentials(self, client):
        """Test scan creation without credentials"""
        with patch('tenable_api.app.scanner', None):
            response = client.post('/api/tenable/scan',
                                 json={
                                     'target_ip': '192.168.1.100',
                                     'ports': [80, 443]
                                 })

            assert response.status_code == 503
            data = json.loads(response.data)
            assert data['success'] is False
            assert data['error_code'] == 'CREDENTIALS_MISSING'

    def test_get_scan_status_with_progress(self, client, mock_tenable_scanner):
        """Test getting scan status with progress information"""
        target = ScanTarget("192.168.1.100", [22, 80, 443])
        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="Tenable Nessus",
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now()
        )
        mock_tenable_scanner.get_scan_result.return_value = mock_result

        # Mock progress information
        mock_progress = {
            'status': 'running',
            'progress': 75,
            'start_time': '2023-01-01T12:00:00',
            'hosts_total': 1,
            'vulnerabilities_total': 15
        }
        mock_tenable_scanner.get_scan_progress.return_value = mock_progress

        response = client.get('/api/tenable/scan/test-scan-id/status')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['progress']['progress'] == 75
        assert data['data']['progress']['hosts_total'] == 1

    def test_get_scan_policies(self, client, mock_tenable_scanner):
        """Test getting available scan policies"""
        mock_policies = [
            {
                'id': 'policy-1',
                'name': 'Basic Network Scan',
                'description': 'Basic network vulnerability scan'
            },
            {
                'id': 'policy-2',
                'name': 'Web Application Tests',
                'description': 'Comprehensive web application tests'
            }
        ]
        mock_tenable_scanner._get_scan_policies.return_value = mock_policies

        response = client.get('/api/tenable/policies')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['total_count'] == 2
        assert len(data['data']['policies']) == 2

    def test_export_scan_results_nessus_format(self, client, mock_tenable_scanner):
        """Test exporting scan results in Nessus format"""
        target = ScanTarget("192.168.1.100", [80, 443])
        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="Tenable Nessus",
            target=target,
            status=ScanStatus.COMPLETED,
            start_time=datetime.now()
        )
        mock_tenable_scanner.get_scan_result.return_value = mock_result

        # Mock export data
        mock_export_data = b'<?xml version="1.0"?><NessusClientData_v2>...</NessusClientData_v2>'
        mock_tenable_scanner.export_scan_results.return_value = mock_export_data

        response = client.get('/api/tenable/scan/test-scan-id/export?format=nessus')

        assert response.status_code == 200
        assert response.mimetype == 'application/xml'
        assert b'NessusClientData_v2' in response.data

    def test_export_scan_results_unsupported_format(self, client, mock_tenable_scanner):
        """Test exporting scan results with unsupported format"""
        target = ScanTarget("192.168.1.100", [80])
        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="Tenable Nessus",
            target=target,
            status=ScanStatus.COMPLETED,
            start_time=datetime.now()
        )
        mock_tenable_scanner.get_scan_result.return_value = mock_result

        response = client.get('/api/tenable/scan/test-scan-id/export?format=unsupported')

        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'supported_formats' in data

    def test_export_scan_results_failure(self, client, mock_tenable_scanner):
        """Test export failure"""
        target = ScanTarget("192.168.1.100", [80])
        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="Tenable Nessus",
            target=target,
            status=ScanStatus.COMPLETED,
            start_time=datetime.now()
        )
        mock_tenable_scanner.get_scan_result.return_value = mock_result
        mock_tenable_scanner.export_scan_results.return_value = None

        response = client.get('/api/tenable/scan/test-scan-id/export?format=nessus')

        assert response.status_code == 500
        data = json.loads(response.data)
        assert 'Failed to export' in data['error']

    def test_get_scanner_info(self, client, mock_tenable_scanner):
        """Test getting scanner information"""
        response = client.get('/api/tenable/info')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['scanner_name'] == 'Tenable Nessus'
        assert 'version' in data
        assert 'url' in data
        assert 'credentials_configured' in data


class TestTenableScanner:
    """Test cases for TenableScanner class"""

    def test_scanner_initialization(self):
        """Test Tenable scanner initialization"""
        from tenable_api.tenable_scanner import TenableScanner

        scanner = TenableScanner(
            url="https://localhost:8834",
            access_key="test-access-key",
            secret_key="test-secret-key"
        )

        assert scanner.name == "Tenable Nessus"
        assert scanner.url == "https://localhost:8834"
        assert scanner.access_key == "test-access-key"
        assert scanner.secret_key == "test-secret-key"

    @patch('requests.Session.get')
    def test_is_tenable_available_true(self, mock_get):
        """Test Tenable availability check when available"""
        from tenable_api.tenable_scanner import TenableScanner

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        assert scanner.is_tenable_available() is True

    @patch('requests.Session.get')
    def test_is_tenable_available_false(self, mock_get):
        """Test Tenable availability check when not available"""
        from tenable_api.tenable_scanner import TenableScanner

        mock_get.side_effect = Exception("Connection failed")

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        assert scanner.is_tenable_available() is False

    @patch('requests.Session.get')
    def test_get_tenable_version(self, mock_get):
        """Test getting Tenable version"""
        from tenable_api.tenable_scanner import TenableScanner

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'server_version': '8.15.1'}
        mock_get.return_value = mock_response

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        version = scanner.get_tenable_version()
        assert version == "8.15.1"

    @patch('requests.Session.get')
    def test_get_scan_policies(self, mock_get):
        """Test getting scan policies"""
        from tenable_api.tenable_scanner import TenableScanner

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'policies': [
                {'id': '1', 'name': 'Basic Network Scan'},
                {'id': '2', 'name': 'Web Application Tests'}
            ]
        }
        mock_get.return_value = mock_response

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        policies = scanner._get_scan_policies()

        assert len(policies) == 2
        assert policies[0]['name'] == 'Basic Network Scan'

    @patch('requests.Session.post')
    def test_create_tenable_scan_success(self, mock_post):
        """Test successful Tenable scan creation"""
        from tenable_api.tenable_scanner import TenableScanner

        # Mock policies response
        mock_policies_response = MagicMock()
        mock_policies_response.status_code = 200
        mock_policies_response.json.return_value = {
            'policies': [{'id': 'policy-1', 'name': 'Basic Network Scan'}]
        }

        # Mock scan creation response
        mock_scan_response = MagicMock()
        mock_scan_response.status_code = 200
        mock_scan_response.json.return_value = {
            'scan': {'id': 12345}
        }

        mock_post.return_value = mock_scan_response

        scanner = TenableScanner("https://localhost:8834", "key", "secret")

        with patch.object(scanner, '_get_scan_policies') as mock_get_policies:
            mock_get_policies.return_value = [{'id': 'policy-1', 'name': 'Basic Network Scan'}]

            target = ScanTarget("192.168.1.100", [80, 443])
            scan_id = scanner._create_tenable_scan("test-scan", target, {})

            assert scan_id == 12345

    @patch('requests.Session.post')
    def test_launch_tenable_scan_success(self, mock_post):
        """Test successful Tenable scan launch"""
        from tenable_api.tenable_scanner import TenableScanner

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        success = scanner._launch_tenable_scan(12345)

        assert success is True

    @patch('requests.Session.get')
    def test_get_tenable_scan_status(self, mock_get):
        """Test getting Tenable scan status"""
        from tenable_api.tenable_scanner import TenableScanner

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'info': {
                'status': 'running',
                'progress': 75,
                'scan_start': '2023-01-01T12:00:00',
                'hostcount': 1
            }
        }
        mock_get.return_value = mock_response

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        status = scanner._get_tenable_scan_status(12345)

        assert status['status'] == 'running'
        assert status['progress'] == 75

    @patch('requests.Session.post')
    def test_stop_tenable_scan(self, mock_post):
        """Test stopping Tenable scan"""
        from tenable_api.tenable_scanner import TenableScanner

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        success = scanner._stop_tenable_scan(12345)

        assert success is True

    def test_parse_tenable_vulnerability(self):
        """Test parsing Tenable vulnerability"""
        from tenable_api.tenable_scanner import TenableScanner

        scanner = TenableScanner("https://localhost:8834", "key", "secret")

        vuln_summary = {
            'plugin_id': 12345,
            'plugin_name': 'Apache HTTP Server Version Detection',
            'severity': 2
        }

        vuln_instance = {
            'description': 'Apache version disclosure',
            'solution': 'Hide server version information',
            'hostname': 'example.com',
            'port': '80',
            'cvss_base_score': '5.0',
            'cve': ['CVE-2023-12345'],
            'plugin_output': 'Server: Apache/2.4.41'
        }

        vulnerability = scanner._parse_tenable_vulnerability(vuln_summary, vuln_instance)

        assert vulnerability is not None
        assert vulnerability.id == "12345"
        assert vulnerability.name == "Apache HTTP Server Version Detection"
        assert vulnerability.severity == SeverityLevel.MEDIUM
        assert vulnerability.cvss_score == 5.0
        assert vulnerability.cve_id == "CVE-2023-12345"

    def test_get_severity_score(self):
        """Test severity score mapping"""
        from tenable_api.tenable_scanner import TenableScanner

        scanner = TenableScanner("https://localhost:8834", "key", "secret")

        # Test severity mapping
        vuln_summary = {'severity': 4}
        vuln_instance = {}
        vuln = scanner._parse_tenable_vulnerability(vuln_summary, vuln_instance)
        assert vuln.severity == SeverityLevel.CRITICAL

        vuln_summary = {'severity': 3}
        vuln = scanner._parse_tenable_vulnerability(vuln_summary, vuln_instance)
        assert vuln.severity == SeverityLevel.HIGH

        vuln_summary = {'severity': 2}
        vuln = scanner._parse_tenable_vulnerability(vuln_summary, vuln_instance)
        assert vuln.severity == SeverityLevel.MEDIUM

        vuln_summary = {'severity': 1}
        vuln = scanner._parse_tenable_vulnerability(vuln_summary, vuln_instance)
        assert vuln.severity == SeverityLevel.LOW

        vuln_summary = {'severity': 0}
        vuln = scanner._parse_tenable_vulnerability(vuln_summary, vuln_instance)
        assert vuln.severity == SeverityLevel.INFORMATIONAL

    @patch('requests.Session')
    def test_export_scan_results_success(self, mock_session):
        """Test successful scan results export"""
        from tenable_api.tenable_scanner import TenableScanner

        # Mock export request
        mock_export_response = MagicMock()
        mock_export_response.status_code = 200
        mock_export_response.json.return_value = {'file': 'file-id-123'}

        # Mock status check
        mock_status_response = MagicMock()
        mock_status_response.status_code = 200
        mock_status_response.json.return_value = {'status': 'ready'}

        # Mock download
        mock_download_response = MagicMock()
        mock_download_response.status_code = 200
        mock_download_response.content = b'nessus file content'

        mock_session_instance = MagicMock()
        mock_session_instance.post.return_value = mock_export_response
        mock_session_instance.get.side_effect = [mock_status_response, mock_download_response]
        mock_session.return_value = mock_session_instance

        scanner = TenableScanner("https://localhost:8834", "key", "secret")
        scanner.session = mock_session_instance
        scanner.scan_mappings = {'test-scan': 12345}

        with patch('time.sleep'):  # Mock sleep to speed up test
            result = scanner.export_scan_results('test-scan', 'nessus')

        assert result == b'nessus file content'


if __name__ == '__main__':
    pytest.main([__file__])