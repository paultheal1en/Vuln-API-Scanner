"""
Tests for OpenVAS API
"""
import pytest
import json
from unittest.mock import patch, MagicMock
import xml.etree.ElementTree as ET

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openvas_api.app import app
from common import ScanTarget, ScanStatus, ScanResult, Vulnerability, SeverityLevel
from datetime import datetime


@pytest.fixture
def client():
    """Test client fixture"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_openvas_scanner():
    """Mock OpenVAS scanner fixture"""
    with patch('openvas_api.app.scanner') as mock_scanner:
        mock_scanner.is_openvas_available.return_value = True
        mock_scanner.get_openvas_version.return_value = "21.4.4"
        mock_scanner.get_supported_formats.return_value = ['json', 'xml', 'csv', 'txt', 'html']
        yield mock_scanner


class TestOpenVASAPI:
    """Test cases for OpenVAS API"""

    def test_health_check(self, client, mock_openvas_scanner):
        """Test health check endpoint"""
        response = client.get('/health')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['service'] == 'OpenVAS API'
        assert 'openvas_available' in data
        assert 'supported_formats' in data
        assert 'socket_path' in data

    def test_create_scan_success(self, client, mock_openvas_scanner):
        """Test successful scan creation"""
        mock_openvas_scanner.scan.return_value = "test-scan-id"

        response = client.post('/api/openvas/scan',
                             json={
                                 'target_ip': '192.168.1.100',
                                 'ports': [22, 80, 443],
                                 'scan_options': {
                                     'config_id': 'full-and-fast-config',
                                     'scan_timeout': 3600
                                 }
                             })

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['scan_id'] == 'test-scan-id'
        assert data['data']['config_id'] == 'full-and-fast-config'

    def test_create_scan_runtime_error(self, client, mock_openvas_scanner):
        """Test scan creation with runtime error (GVM not available)"""
        mock_openvas_scanner.scan.side_effect = RuntimeError("python-gvm is not available")

        response = client.post('/api/openvas/scan',
                             json={
                                 'target_ip': '192.168.1.100',
                                 'ports': [80, 443]
                             })

        assert response.status_code == 503
        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error_code'] == 'OPENVAS_UNAVAILABLE'

    def test_get_scan_status_with_progress(self, client, mock_openvas_scanner):
        """Test getting scan status with progress information"""
        target = ScanTarget("192.168.1.100", [22, 80, 443])
        mock_result = ScanResult(
            scan_id="test-scan-id",
            scanner_name="OpenVAS",
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now()
        )
        mock_openvas_scanner.get_scan_result.return_value = mock_result

        # Mock progress information
        mock_progress = {
            'status': 'Running',
            'progress': '75%'
        }
        mock_openvas_scanner.get_scan_progress.return_value = mock_progress

        response = client.get('/api/openvas/scan/test-scan-id/status')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['progress']['status'] == 'Running'
        assert data['data']['progress']['progress'] == '75%'

    def test_get_scan_configs(self, client, mock_openvas_scanner):
        """Test getting available scan configurations"""
        mock_configs = [
            {
                'id': 'config-1',
                'name': 'Full and fast',
                'comment': 'Full and fast scan configuration'
            },
            {
                'id': 'config-2',
                'name': 'System Discovery',
                'comment': 'Network discovery scan'
            }
        ]
        mock_openvas_scanner.get_scan_configs.return_value = mock_configs

        response = client.get('/api/openvas/configs')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['data']['total_count'] == 2
        assert len(data['data']['configs']) == 2

    def test_get_scanner_info(self, client, mock_openvas_scanner):
        """Test getting scanner information"""
        response = client.get('/api/openvas/info')

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['scanner_name'] == 'OpenVAS'
        assert 'version' in data
        assert 'host' in data
        assert 'port' in data


class TestOpenVASScanner:
    """Test cases for OpenVASScanner class"""

    @patch('openvas_api.openvas_scanner.UnixSocketConnection')
    @patch('openvas_api.openvas_scanner.TLSConnection')
    @patch('openvas_api.openvas_scanner.Gmp')
    @patch('openvas_api.openvas_scanner.EtreeTransform')
    def test_scanner_initialization(self, mock_transform, mock_gmp, mock_tls, mock_unix):
        """Test OpenVAS scanner initialization"""
        from openvas_api.openvas_scanner import OpenVASScanner

        scanner = OpenVASScanner(
            host="localhost",
            port=9390,
            username="admin",
            password="password"
        )

        assert scanner.name == "OpenVAS"
        assert scanner.host == "localhost"
        assert scanner.port == 9390
        assert scanner.username == "admin"
        assert scanner.password == "password"

    @patch('openvas_api.openvas_scanner.UnixSocketConnection')
    @patch('openvas_api.openvas_scanner.TLSConnection')
    @patch('openvas_api.openvas_scanner.Gmp')
    @patch('openvas_api.openvas_scanner.EtreeTransform')
    def test_connect_with_socket(self, mock_transform, mock_gmp, mock_tls, mock_unix):
        """Test connection with Unix socket"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp_instance = MagicMock()
        mock_gmp.return_value = mock_gmp_instance

        with patch('os.path.exists', return_value=True):
            scanner = OpenVASScanner(socket_path="/run/gvmd/gvmd.sock")
            success = scanner._connect()

            assert success is True
            mock_unix.assert_called_once()
            mock_gmp_instance.authenticate.assert_called_once()

    @patch('openvas_api.openvas_scanner.UnixSocketConnection')
    @patch('openvas_api.openvas_scanner.TLSConnection')
    @patch('openvas_api.openvas_scanner.Gmp')
    @patch('openvas_api.openvas_scanner.EtreeTransform')
    def test_connect_with_tls(self, mock_transform, mock_gmp, mock_tls, mock_unix):
        """Test connection with TLS"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp_instance = MagicMock()
        mock_gmp.return_value = mock_gmp_instance

        scanner = OpenVASScanner(host="localhost", port=9390)
        success = scanner._connect()

        assert success is True
        mock_tls.assert_called_once_with(hostname="localhost", port=9390)
        mock_gmp_instance.authenticate.assert_called_once()

    @patch('openvas_api.openvas_scanner.UnixSocketConnection')
    @patch('openvas_api.openvas_scanner.TLSConnection')
    @patch('openvas_api.openvas_scanner.Gmp')
    @patch('openvas_api.openvas_scanner.EtreeTransform')
    def test_connect_failure(self, mock_transform, mock_gmp, mock_tls, mock_unix):
        """Test connection failure"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_tls.side_effect = Exception("Connection failed")

        scanner = OpenVASScanner()
        success = scanner._connect()

        assert success is False
        assert scanner.gmp is None

    def test_scanner_without_gvm(self):
        """Test scanner behavior when python-gvm is not available"""
        # Mock the imports to simulate missing python-gvm
        with patch('openvas_api.openvas_scanner.UnixSocketConnection', None):
            with patch('openvas_api.openvas_scanner.TLSConnection', None):
                with patch('openvas_api.openvas_scanner.Gmp', None):
                    with patch('openvas_api.openvas_scanner.EtreeTransform', None):
                        from openvas_api.openvas_scanner import OpenVASScanner

                        scanner = OpenVASScanner()

                        # Should raise RuntimeError when trying to scan
                        target = ScanTarget("192.168.1.100", [80])
                        with pytest.raises(RuntimeError):
                            scanner.scan(target)

    def test_parse_openvas_result(self):
        """Test parsing OpenVAS result XML"""
        from openvas_api.openvas_scanner import OpenVASScanner

        scanner = OpenVASScanner()

        # Create mock XML element
        result_xml = '''
        <result id="1">
            <name>HTTP Server Type and Version</name>
            <description>The remote HTTP server type and version</description>
            <host>192.168.1.100</host>
            <port>80/tcp</port>
            <threat>Log</threat>
            <severity>0.0</severity>
            <nvt oid="1.3.6.1.4.1.25623.1.0.10107">
                <name>HTTP Server Type and Version</name>
                <tags>summary=Detect HTTP server type and version|solution=N/A|insight=CVE-2023-12345</tags>
                <solution>N/A</solution>
                <refs>
                    <ref type="cve" id="CVE-2023-12345"/>
                    <ref type="url" id="https://example.com"/>
                </refs>
            </nvt>
        </result>
        '''

        result_elem = ET.fromstring(result_xml)
        vulnerability = scanner._parse_openvas_result(result_elem)

        assert vulnerability is not None
        assert vulnerability.id == "1.3.6.1.4.1.25623.1.0.10107"
        assert vulnerability.name == "HTTP Server Type and Version"
        assert vulnerability.severity == SeverityLevel.INFORMATIONAL
        assert vulnerability.cvss_score == 0.0
        assert "192.168.1.100" in vulnerability.evidence
        assert "80/tcp" in vulnerability.affected_parameter

    def test_parse_openvas_result_with_cve(self):
        """Test parsing OpenVAS result with CVE information"""
        from openvas_api.openvas_scanner import OpenVASScanner

        scanner = OpenVASScanner()

        result_xml = '''
        <result id="1">
            <name>Apache HTTP Server Multiple Vulnerabilities</name>
            <description>Multiple vulnerabilities in Apache HTTP Server</description>
            <host>192.168.1.100</host>
            <port>80/tcp</port>
            <threat>High</threat>
            <severity>7.5</severity>
            <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
                <name>Apache HTTP Server Multiple Vulnerabilities</name>
                <tags>summary=Multiple vulnerabilities|solution=Update Apache|CVE-2023-12345</tags>
                <solution>Update to the latest version</solution>
            </nvt>
        </result>
        '''

        result_elem = ET.fromstring(result_xml)
        vulnerability = scanner._parse_openvas_result(result_elem)

        assert vulnerability is not None
        assert vulnerability.severity == SeverityLevel.HIGH
        assert vulnerability.cvss_score == 7.5
        assert vulnerability.cve_id == "CVE-2023-12345"
        assert vulnerability.solution == "Update to the latest version"

    def test_create_openvas_target(self):
        """Test creating OpenVAS target"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()
        mock_response = MagicMock()
        mock_response.get.return_value = "target-id-123"
        mock_gmp.create_target.return_value = mock_response

        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        target = ScanTarget("192.168.1.100", [80, 443])
        target_id = scanner._create_openvas_target("scan-1", target, {})

        assert target_id == "target-id-123"
        mock_gmp.create_target.assert_called_once()

    def test_get_default_scan_config(self):
        """Test getting default scan configuration"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()

        # Mock XML response for configs
        configs_xml = '''
        <configs>
            <config id="config-1">
                <name>Full and fast</name>
            </config>
            <config id="config-2">
                <name>System Discovery</name>
            </config>
        </configs>
        '''

        mock_configs = ET.fromstring(configs_xml)
        mock_gmp.get_scan_configs.return_value = mock_configs

        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        config_id = scanner._get_default_scan_config()

        assert config_id == "config-1"  # Should return first config

    def test_get_default_scanner(self):
        """Test getting default scanner"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()

        # Mock XML response for scanners
        scanners_xml = '''
        <scanners>
            <scanner id="scanner-1">
                <name>OpenVAS Default Scanner</name>
            </scanner>
            <scanner id="scanner-2">
                <name>Custom Scanner</name>
            </scanner>
        </scanners>
        '''

        mock_scanners = ET.fromstring(scanners_xml)
        mock_gmp.get_scanners.return_value = mock_scanners

        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        scanner_id = scanner._get_default_scanner()

        assert scanner_id == "scanner-1"  # Should return OpenVAS scanner

    def test_create_openvas_task(self):
        """Test creating OpenVAS task"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()
        mock_response = MagicMock()
        mock_response.get.return_value = "task-id-123"
        mock_gmp.create_task.return_value = mock_response

        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        with patch.object(scanner, '_get_default_scan_config', return_value="config-1"):
            with patch.object(scanner, '_get_default_scanner', return_value="scanner-1"):
                task_id = scanner._create_openvas_task("scan-1", "target-1", {})

                assert task_id == "task-id-123"
                mock_gmp.create_task.assert_called_once()

    def test_start_openvas_task(self):
        """Test starting OpenVAS task"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()
        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        success = scanner._start_openvas_task("task-123")

        assert success is True
        mock_gmp.start_task.assert_called_once_with("task-123")

    def test_get_openvas_task_status(self):
        """Test getting OpenVAS task status"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()

        # Mock XML response for task status
        task_xml = '''
        <task>
            <status>Running</status>
            <progress>75</progress>
        </task>
        '''

        mock_task = ET.fromstring(task_xml)
        mock_gmp.get_task.return_value = mock_task

        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        status = scanner._get_openvas_task_status("task-123")

        assert status['status'] == 'Running'
        assert status['progress'] == '75'

    def test_stop_openvas_task(self):
        """Test stopping OpenVAS task"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()
        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        success = scanner._stop_openvas_task("task-123")

        assert success is True
        mock_gmp.stop_task.assert_called_once_with("task-123")

    def test_get_scan_configs(self):
        """Test getting scan configurations"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()

        # Mock XML response for configs
        configs_xml = '''
        <configs>
            <config id="config-1">
                <name>Full and fast</name>
                <comment>Full and fast scan configuration</comment>
            </config>
            <config id="config-2">
                <name>System Discovery</name>
                <comment>Network discovery scan</comment>
            </config>
        </configs>
        '''

        mock_configs = ET.fromstring(configs_xml)

        scanner = OpenVASScanner()

        with patch.object(scanner, '_connect', return_value=True):
            with patch.object(scanner, '_disconnect'):
                scanner.gmp = mock_gmp
                mock_gmp.get_scan_configs.return_value = mock_configs

                configs = scanner.get_scan_configs()

                assert len(configs) == 2
                assert configs[0]['id'] == 'config-1'
                assert configs[0]['name'] == 'Full and fast'
                assert configs[1]['id'] == 'config-2'

    def test_collect_scan_results(self):
        """Test collecting scan results"""
        from openvas_api.openvas_scanner import OpenVASScanner

        mock_gmp = MagicMock()

        # Mock task XML with report
        task_xml = '''
        <task>
            <last_report>
                <report id="report-123"/>
            </last_report>
        </task>
        '''

        # Mock report XML with results
        report_xml = '''
        <report>
            <results>
                <result id="1">
                    <name>Test Vulnerability</name>
                    <description>Test description</description>
                    <host>192.168.1.100</host>
                    <port>80/tcp</port>
                    <threat>Medium</threat>
                    <severity>5.0</severity>
                    <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
                        <name>Test Vulnerability</name>
                        <solution>Test solution</solution>
                    </nvt>
                </result>
            </results>
        </report>
        '''

        mock_task = ET.fromstring(task_xml)
        mock_report = ET.fromstring(report_xml)

        mock_gmp.get_task.return_value = mock_task
        mock_gmp.get_report.return_value = mock_report

        scanner = OpenVASScanner()
        scanner.gmp = mock_gmp

        # Initialize scan result
        target = ScanTarget("192.168.1.100", [80])
        scan_result = ScanResult(
            scan_id="test-scan",
            scanner_name="OpenVAS",
            target=target,
            status=ScanStatus.RUNNING,
            start_time=datetime.now()
        )
        scanner.active_scans["test-scan"] = scan_result

        scanner._collect_scan_results("test-scan", "task-123")

        assert len(scanner.active_scans["test-scan"].vulnerabilities) == 1
        vuln = scanner.active_scans["test-scan"].vulnerabilities[0]
        assert vuln.name == "Test Vulnerability"
        assert vuln.severity == SeverityLevel.MEDIUM


if __name__ == '__main__':
    pytest.main([__file__])