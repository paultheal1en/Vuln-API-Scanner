"""
Tests for ZAP API
"""
import pytest
import json
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zap_api.app import app
from common import ScanTarget, ScanStatus, ScanResult, Vulnerability, SeverityLevel
from datetime import datetime


@pytest.fixture
def client():
    """Test client fixture"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_zap_scanner():
    """Mock ZAP scanner fixture"""
    with patch('zap_api.app.scanner') as mock_scanner:
        mock_scanner.is_zap_available.return_value = True
        mock_scanner.get_zap_version.return_value = "2.12.0"
        mock_scanner.get_supported_formats.return_value = ['json', 'xml', 'csv', 'txt', 'html']
        yield mock_scanner


class TestZAPAPI:
    """Test cases for ZAP API"""

    def test_health_check(self, client, mock_zap_scanner):
        """Test health check endpoint"""
        response = client.get('/health')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['service'] == 'OWASP ZAP API'
        assert 'zap_available' in data
        assert 'supported_formats' in data

    def test_create_scan_success(self, client, mock_zap_scanner):
        """Test successful scan creation"""
        mock_zap_scanner.scan.return_value = "test-scan-id"

        response = client.post('/api/zap/scan',
                             json={
                                 'target_ip': '192.168.1.100',
                                 'ports': [80, 443],
                                 'scan_options': {'scan_type': 'full'}
                             })

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['scan_id'] == 'test-scan-id'
        assert data['data']['scan_type'] == 'full'

    def test_create_spider_scan(self, client, mock_zap_scanner):
        """Test spider scan creation"""
        mock_zap_scanner.scan.return_value = "spider-scan-id"

        response = client.post('/api/zap/scan/spider',
                             json={
                                 'target_ip': 'example.com',
                                 'ports': [80],
                                 'scan_options': {
                                     'spider': {
                                         'max_depth': 3,
                                         'max_children': 10
                                     }
                                 }
                             })

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['scan_type'] == 'spider'

    def test_create_active_scan(self, client, mock_zap_scanner):
        """Test active scan creation"""
        mock_zap_scanner.scan.return_value = "active-scan-id"

        response = client.post('/api/zap/scan/active',
                             json={
                                 'target_ip': 'example.com',
                                 'ports': [80, 443],
                                 'scan_options': {
                                     'active_scan': {
                                         'policy_name': 'Default Policy'
                                     }
                                 }
                             })

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['scan_type'] == 'active'

    def test_get_scan_status_with_progress(self, client, mock_zap_scanner):
        """Test getting scan status with progress information"""
        target = ScanTarget("192.168.1.100", [80, 443])
        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="OWASP ZAP",
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now()
        )
        mock_zap_scanner.get_scan_result.return_value = mock_result

        # Mock progress information
        mock_progress = {
            'spider_progress': [{'id': 'spider-1', 'progress': 75}],
            'ascan_progress': [{'id': 'ascan-1', 'progress': 50}],
            'overall_progress': 62.5
        }
        mock_zap_scanner.get_scan_progress.return_value = mock_progress

        response = client.get('/api/zap/scan/test-scan-id/status')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['progress']['overall_progress'] == 62.5

    def test_get_spider_results(self, client, mock_zap_scanner):
        """Test getting spider scan results"""
        mock_urls = [
            "http://example.com/",
            "http://example.com/about",
            "http://example.com/contact",
            "http://example.com/login"
        ]
        mock_zap_scanner.get_spider_results.return_value = mock_urls

        response = client.get('/api/zap/scan/test-scan-id/spider-results')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['total_urls'] == 4
        assert "http://example.com/" in data['data']['discovered_urls']

    def test_create_new_session(self, client, mock_zap_scanner):
        """Test creating new ZAP session"""
        mock_zap_scanner.create_new_session.return_value = True

        response = client.post('/api/zap/session/new',
                             json={'session_name': 'test_session'})

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True

    def test_create_session_failure(self, client, mock_zap_scanner):
        """Test session creation failure"""
        mock_zap_scanner.create_new_session.return_value = False

        response = client.post('/api/zap/session/new')

        assert response.status_code == 500
        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error_code'] == 'SESSION_CREATE_FAILED'

    def test_stop_scan_success(self, client, mock_zap_scanner):
        """Test successful scan stopping"""
        mock_zap_scanner.stop_scan.return_value = True

        response = client.delete('/api/zap/scan/test-scan-id')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True

    def test_get_scanner_info(self, client, mock_zap_scanner):
        """Test getting scanner information"""
        response = client.get('/api/zap/info')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['scanner_name'] == 'OWASP ZAP'
        assert 'version' in data
        assert 'proxy_url' in data


class TestZAPScanner:
    """Test cases for ZAPScanner class"""

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_scanner_initialization(self, mock_zapv2):
        """Test ZAP scanner initialization"""
        from zap_api.zap_scanner import ZAPScanner

        scanner = ZAPScanner('http://127.0.0.1:8080', 'test-api-key')
        assert scanner.name == "OWASP ZAP"
        assert scanner.proxy_url == 'http://127.0.0.1:8080'
        assert scanner.api_key == 'test-api-key'

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_zap_available_true(self, mock_zapv2):
        """Test ZAP availability check when available"""
        from zap_api.zap_scanner import ZAPScanner

        mock_zap_instance = MagicMock()
        mock_zap_instance.core.version = "2.12.0"
        mock_zapv2.return_value = mock_zap_instance

        scanner = ZAPScanner()
        scanner.zap = mock_zap_instance
        assert scanner.is_zap_available() is True

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_zap_available_false(self, mock_zapv2):
        """Test ZAP availability check when not available"""
        from zap_api.zap_scanner import ZAPScanner

        scanner = ZAPScanner()
        scanner.zap = None
        assert scanner.is_zap_available() is False

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_parse_zap_alert(self, mock_zapv2):
        """Test parsing ZAP alert into vulnerability"""
        from zap_api.zap_scanner import ZAPScanner

        scanner = ZAPScanner()

        alert = {
            'id': '12345',
            'name': 'Cross Site Scripting (Reflected)',
            'risk': 'High',
            'confidence': 'Medium',
            'url': 'http://example.com/search',
            'param': 'q',
            'description': 'XSS vulnerability found',
            'solution': 'Validate input and encode output',
            'reference': 'https://owasp.org/www-project-top-ten/',
            'evidence': '<script>alert("XSS")</script>',
            'cvssScore': '7.3'
        }

        vulnerability = scanner._parse_zap_alert(alert)

        assert vulnerability is not None
        assert vulnerability.id == '12345'
        assert vulnerability.name == 'Cross Site Scripting (Reflected)'
        assert vulnerability.severity == SeverityLevel.HIGH
        assert vulnerability.cvss_score == 7.3
        assert vulnerability.affected_url == 'http://example.com/search'
        assert vulnerability.affected_parameter == 'q'

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_extract_cve_from_reference(self, mock_zapv2):
        """Test extracting CVE from reference string"""
        from zap_api.zap_scanner import ZAPScanner

        scanner = ZAPScanner()

        # Test with CVE present
        reference = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345"
        cve = scanner._extract_cve_from_reference(reference)
        assert cve == "CVE-2023-12345"

        # Test with no CVE
        reference = "https://example.com/security-info"
        cve = scanner._extract_cve_from_reference(reference)
        assert cve == ""

        # Test with empty reference
        cve = scanner._extract_cve_from_reference("")
        assert cve == ""

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_scan_with_options(self, mock_zapv2):
        """Test scan with various options"""
        from zap_api.zap_scanner import ZAPScanner

        mock_zap_instance = MagicMock()
        mock_zapv2.return_value = mock_zap_instance

        scanner = ZAPScanner()
        scanner.zap = mock_zap_instance

        target = ScanTarget("example.com", [80, 443])
        options = {
            'scan_type': 'full',
            'spider': {'max_depth': 5, 'max_children': 20},
            'active_scan': {'policy_name': 'Custom Policy'}
        }

        with patch.object(scanner, '_run_scan_thread') as mock_run:
            scan_id = scanner.scan(target, options)

            assert scan_id is not None
            assert scan_id in scanner.active_scans
            mock_run.assert_called_once()

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_get_scan_progress(self, mock_zapv2):
        """Test getting detailed scan progress"""
        from zap_api.zap_scanner import ZAPScanner

        mock_zap_instance = MagicMock()
        mock_zap_instance.spider.status.return_value = "75"
        mock_zap_instance.ascan.status.return_value = "50"
        mock_zapv2.return_value = mock_zap_instance

        scanner = ZAPScanner()
        scanner.zap = mock_zap_instance

        # Setup scan session
        scan_id = "test-scan"
        scanner.scan_sessions[scan_id] = {
            'spider_ids': ['spider-1'],
            'ascan_ids': ['ascan-1'],
            'targets': ['http://example.com']
        }

        progress = scanner.get_scan_progress(scan_id)

        assert 'spider_progress' in progress
        assert 'ascan_progress' in progress
        assert 'overall_progress' in progress
        assert progress['overall_progress'] == 62.5  # (75 + 50) / 2

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_stop_scan_success(self, mock_zapv2):
        """Test successful scan stopping"""
        from zap_api.zap_scanner import ZAPScanner

        mock_zap_instance = MagicMock()
        mock_zapv2.return_value = mock_zap_instance

        scanner = ZAPScanner()
        scanner.zap = mock_zap_instance

        # Setup scan session
        scan_id = "test-scan"
        scanner.scan_sessions[scan_id] = {
            'spider_ids': ['spider-1'],
            'ascan_ids': ['ascan-1']
        }

        # Setup active scan
        target = ScanTarget("example.com", [80])
        scanner.active_scans[scan_id] = ScanResult(
            scan_id=scan_id,
            scanner_name="OWASP ZAP",
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now()
        )

        success = scanner.stop_scan(scan_id)

        assert success is True
        mock_zap_instance.spider.stop.assert_called_with('spider-1')
        mock_zap_instance.ascan.stop.assert_called_with('ascan-1')

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_create_new_session(self, mock_zapv2):
        """Test creating new ZAP session"""
        from zap_api.zap_scanner import ZAPScanner

        mock_zap_instance = MagicMock()
        mock_zapv2.return_value = mock_zap_instance

        scanner = ZAPScanner()
        scanner.zap = mock_zap_instance

        success = scanner.create_new_session("test_session")

        assert success is True
        mock_zap_instance.core.new_session.assert_called_once()

    @patch('zap_api.zap_scanner.ZAPv2')
    def test_get_spider_results(self, mock_zapv2):
        """Test getting spider results"""
        from zap_api.zap_scanner import ZAPScanner

        mock_zap_instance = MagicMock()
        mock_zap_instance.spider.results.return_value = [
            "http://example.com/",
            "http://example.com/about"
        ]
        mock_zapv2.return_value = mock_zap_instance

        scanner = ZAPScanner()
        scanner.zap = mock_zap_instance

        # Setup scan session
        scan_id = "test-scan"
        scanner.scan_sessions[scan_id] = {
            'spider_ids': ['spider-1'],
            'ascan_ids': [],
            'targets': ['http://example.com']
        }

        urls = scanner.get_spider_results(scan_id)

        assert len(urls) == 2
        assert "http://example.com/" in urls
        assert "http://example.com/about" in urls


if __name__ == '__main__':
    pytest.main([__file__])