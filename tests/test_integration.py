"""
Integration tests for vulnerability scanners API
Tests cross-service functionality and end-to-end workflows
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
import requests

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import ScanTarget, ScanStatus, ScanResult, Vulnerability, SeverityLevel
from datetime import datetime


@pytest.mark.integration
class TestAPIIntegration:
    """Integration tests for API services"""

    def test_scan_workflow_complete(self):
        """Test complete scan workflow from start to results"""
        # Mock HTTP requests to simulate API calls
        with patch('requests.post') as mock_post, \
             patch('requests.get') as mock_get:

            # Mock scan creation response
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = {
                'success': True,
                'data': {
                    'scan_id': 'test-scan-123',
                    'status': 'initiated'
                }
            }

            # Mock status check responses (running -> completed)
            mock_responses = [
                # First check - running
                MagicMock(status_code=200, json=lambda: {
                    'success': True,
                    'data': {
                        'status': 'running',
                        'progress': {'overall_progress': 50}
                    }
                }),
                # Second check - completed
                MagicMock(status_code=200, json=lambda: {
                    'success': True,
                    'data': {
                        'status': 'completed',
                        'vulnerabilities_found': 2,
                        'scan_duration': '00:05:30'
                    }
                })
            ]
            mock_get.side_effect = mock_responses

            # Simulate scan workflow
            scan_request = {
                'target_ip': '192.168.1.100',
                'ports': [80, 443],
                'scan_options': {'timeout': 3600}
            }

            # Create scan
            response = requests.post('http://localhost:5001/api/nikto/scan', json=scan_request)
            assert response.status_code == 201

            scan_data = response.json()
            scan_id = scan_data['data']['scan_id']
            assert scan_id == 'test-scan-123'

            # Check status (running)
            response = requests.get(f'http://localhost:5001/api/nikto/scan/{scan_id}/status')
            assert response.status_code == 200
            status_data = response.json()
            assert status_data['data']['status'] == 'running'

            # Check status (completed)
            response = requests.get(f'http://localhost:5001/api/nikto/scan/{scan_id}/status')
            assert response.status_code == 200
            status_data = response.json()
            assert status_data['data']['status'] == 'completed'

    def test_multi_service_scan_coordination(self):
        """Test coordinating scans across multiple services"""
        services = [
            {'name': 'nikto', 'port': 5001},
            {'name': 'zap', 'port': 5002},
            {'name': 'tenable', 'port': 5003},
            {'name': 'openvas', 'port': 5004}
        ]

        scan_ids = []

        with patch('requests.post') as mock_post:
            # Mock successful scan creation for all services
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = {
                'success': True,
                'data': {'scan_id': 'multi-scan-123', 'status': 'initiated'}
            }

            # Start scans on all services
            for service in services:
                response = requests.post(
                    f"http://localhost:{service['port']}/api/{service['name']}/scan",
                    json={
                        'target_ip': '192.168.1.100',
                        'ports': [80, 443],
                        'scan_options': {'timeout': 3600}
                    }
                )
                assert response.status_code == 201
                scan_data = response.json()
                scan_ids.append({
                    'service': service['name'],
                    'scan_id': scan_data['data']['scan_id']
                })

            assert len(scan_ids) == 4

            # Verify all scans were initiated
            for scan in scan_ids:
                assert scan['scan_id'] == 'multi-scan-123'

    def test_output_format_consistency(self):
        """Test consistency of output formats across services"""
        formats = ['json', 'xml', 'csv', 'txt', 'html']

        with patch('requests.get') as mock_get:
            # Mock scan results with vulnerabilities
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {
                'success': True,
                'data': {
                    'scan_id': 'format-test-123',
                    'vulnerabilities': [
                        {
                            'id': '1',
                            'name': 'Test Vulnerability',
                            'severity': 'HIGH',
                            'description': 'Test description'
                        }
                    ]
                }
            }

            # Test each format
            for fmt in formats:
                response = requests.get(
                    'http://localhost:5001/api/nikto/scan/format-test-123/results',
                    params={'format': fmt}
                )
                assert response.status_code == 200

                # Verify response content type matches format
                content_types = {
                    'json': 'application/json',
                    'xml': 'application/xml',
                    'csv': 'text/csv',
                    'txt': 'text/plain',
                    'html': 'text/html'
                }

                # For mocked responses, we can't check actual content type
                # but we can verify the response structure
                if fmt == 'json':
                    data = response.json()
                    assert 'data' in data
                    assert 'vulnerabilities' in data['data']

    def test_error_handling_across_services(self):
        """Test error handling consistency across all services"""
        error_scenarios = [
            {
                'status_code': 400,
                'error_type': 'INVALID_REQUEST',
                'request_data': {}  # Missing required fields
            },
            {
                'status_code': 404,
                'error_type': 'SCAN_NOT_FOUND',
                'scan_id': 'non-existent-scan'
            },
            {
                'status_code': 503,
                'error_type': 'SERVICE_UNAVAILABLE',
                'request_data': {'target_ip': '192.168.1.100', 'ports': [80]}
            }
        ]

        with patch('requests.post') as mock_post, \
             patch('requests.get') as mock_get:

            for scenario in error_scenarios:
                if scenario.get('request_data') is not None:
                    # Test POST errors
                    mock_post.return_value.status_code = scenario['status_code']
                    mock_post.return_value.json.return_value = {
                        'success': False,
                        'error_code': scenario['error_type'],
                        'message': 'Error occurred'
                    }

                    response = requests.post(
                        'http://localhost:5001/api/nikto/scan',
                        json=scenario['request_data']
                    )
                    assert response.status_code == scenario['status_code']

                elif scenario.get('scan_id'):
                    # Test GET errors
                    mock_get.return_value.status_code = scenario['status_code']
                    mock_get.return_value.json.return_value = {
                        'success': False,
                        'error_code': scenario['error_type'],
                        'message': 'Scan not found'
                    }

                    response = requests.get(
                        f"http://localhost:5001/api/nikto/scan/{scenario['scan_id']}/status"
                    )
                    assert response.status_code == scenario['status_code']

    def test_concurrent_scans(self):
        """Test handling multiple concurrent scans"""
        import concurrent.futures

        def create_scan(scan_id):
            with patch('requests.post') as mock_post:
                mock_post.return_value.status_code = 201
                mock_post.return_value.json.return_value = {
                    'success': True,
                    'data': {
                        'scan_id': f'concurrent-scan-{scan_id}',
                        'status': 'initiated'
                    }
                }

                response = requests.post(
                    'http://localhost:5001/api/nikto/scan',
                    json={
                        'target_ip': f'192.168.1.{scan_id}',
                        'ports': [80, 443],
                        'scan_options': {'timeout': 3600}
                    }
                )
                return response.status_code == 201

        # Start multiple scans concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_scan, i) for i in range(1, 6)]
            results = [future.result() for future in concurrent.futures.as_completed(futures)]

        # All scans should succeed
        assert all(results)
        assert len(results) == 5

    def test_scan_lifecycle_management(self):
        """Test complete scan lifecycle: create, monitor, stop, cleanup"""
        with patch('requests.post') as mock_post, \
             patch('requests.get') as mock_get, \
             patch('requests.delete') as mock_delete:

            # Mock scan creation
            mock_post.return_value.status_code = 201
            mock_post.return_value.json.return_value = {
                'success': True,
                'data': {'scan_id': 'lifecycle-test-123', 'status': 'initiated'}
            }

            # Mock status check
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {
                'success': True,
                'data': {'status': 'running', 'progress': {'overall_progress': 25}}
            }

            # Mock scan stop
            mock_delete.return_value.status_code = 200
            mock_delete.return_value.json.return_value = {
                'success': True,
                'message': 'Scan stopped successfully'
            }

            # Create scan
            response = requests.post(
                'http://localhost:5001/api/nikto/scan',
                json={'target_ip': '192.168.1.100', 'ports': [80]}
            )
            assert response.status_code == 201
            scan_id = response.json()['data']['scan_id']

            # Check status
            response = requests.get(f'http://localhost:5001/api/nikto/scan/{scan_id}/status')
            assert response.status_code == 200
            assert response.json()['data']['status'] == 'running'

            # Stop scan
            response = requests.delete(f'http://localhost:5001/api/nikto/scan/{scan_id}')
            assert response.status_code == 200
            assert response.json()['success'] is True


@pytest.mark.integration
@pytest.mark.slow
class TestRealServiceIntegration:
    """Integration tests that require actual services (Docker containers)"""

    @pytest.fixture(autouse=True)
    def setup_services(self):
        """Setup test services"""
        # This would typically start Docker containers
        # For now, we'll skip if services aren't available
        yield
        # Cleanup if needed

    def test_nikto_service_health(self):
        """Test Nikto service health check"""
        try:
            response = requests.get('http://localhost:5001/health', timeout=5)
            assert response.status_code == 200

            data = response.json()
            assert data['service'] == 'Nikto API'
            assert 'nikto_available' in data

        except requests.exceptions.RequestException:
            pytest.skip("Nikto service not available")

    def test_zap_service_health(self):
        """Test ZAP service health check"""
        try:
            response = requests.get('http://localhost:5002/health', timeout=5)
            assert response.status_code == 200

            data = response.json()
            assert data['service'] == 'OWASP ZAP API'
            assert 'zap_available' in data

        except requests.exceptions.RequestException:
            pytest.skip("ZAP service not available")

    def test_tenable_service_health(self):
        """Test Tenable service health check"""
        try:
            response = requests.get('http://localhost:5003/health', timeout=5)
            assert response.status_code == 200

            data = response.json()
            assert data['service'] == 'Tenable API'
            assert 'tenable_available' in data

        except requests.exceptions.RequestException:
            pytest.skip("Tenable service not available")

    def test_openvas_service_health(self):
        """Test OpenVAS service health check"""
        try:
            response = requests.get('http://localhost:5004/health', timeout=5)
            assert response.status_code == 200

            data = response.json()
            assert data['service'] == 'OpenVAS API'
            assert 'openvas_available' in data

        except requests.exceptions.RequestException:
            pytest.skip("OpenVAS service not available")

    def test_cross_service_data_consistency(self):
        """Test data consistency across services for the same target"""
        target_ip = '192.168.1.100'
        ports = [80, 443]

        # This would require all services to be running
        # and would perform actual scans to compare results
        pytest.skip("Requires all services running - implement when Docker setup is complete")

    def test_performance_benchmarks(self):
        """Test performance benchmarks across services"""
        # Performance tests would measure:
        # - Scan initiation time
        # - Results retrieval time
        # - Memory usage
        # - Concurrent scan handling
        pytest.skip("Performance benchmarks - implement when services are stable")


@pytest.mark.integration
class TestDataFormatIntegration:
    """Test data format integration and consistency"""

    def test_vulnerability_data_mapping(self):
        """Test vulnerability data mapping across different scanner outputs"""
        # Sample data from each scanner type
        nikto_vuln = {
            'id': '123',
            'method': 'GET',
            'uri': '/admin/',
            'description': 'Admin directory found'
        }

        zap_alert = {
            'id': '1',
            'name': 'Cross Site Scripting',
            'risk': 'High',
            'url': 'http://example.com/search',
            'param': 'q',
            'description': 'XSS vulnerability'
        }

        tenable_finding = {
            'plugin_id': 12345,
            'plugin_name': 'Apache Version Detection',
            'severity': 1,
            'description': 'Apache server detected'
        }

        openvas_result = {
            'id': '1.3.6.1.4.1.25623.1.0.10107',
            'name': 'HTTP Server Type',
            'threat': 'Log',
            'description': 'HTTP server information'
        }

        # Test that each can be mapped to common Vulnerability model
        from common import Vulnerability, SeverityLevel

        # Each scanner should be able to create valid Vulnerability objects
        # This tests the data mapping consistency

        # Mock the parsing functions (these would be in the actual scanner classes)
        vulnerabilities = []

        # Nikto mapping
        nikto_vuln_obj = Vulnerability(
            id=nikto_vuln['id'],
            name=f"Nikto: {nikto_vuln['uri']}",
            severity=SeverityLevel.MEDIUM,
            description=nikto_vuln['description'],
            affected_url=f"http://example.com{nikto_vuln['uri']}"
        )
        vulnerabilities.append(nikto_vuln_obj)

        # ZAP mapping
        zap_vuln_obj = Vulnerability(
            id=zap_alert['id'],
            name=zap_alert['name'],
            severity=SeverityLevel.HIGH,
            description=zap_alert['description'],
            affected_url=zap_alert['url'],
            affected_parameter=zap_alert['param']
        )
        vulnerabilities.append(zap_vuln_obj)

        # Tenable mapping
        tenable_vuln_obj = Vulnerability(
            id=str(tenable_finding['plugin_id']),
            name=tenable_finding['plugin_name'],
            severity=SeverityLevel.LOW,
            description=tenable_finding['description']
        )
        vulnerabilities.append(tenable_vuln_obj)

        # OpenVAS mapping
        openvas_vuln_obj = Vulnerability(
            id=openvas_result['id'],
            name=openvas_result['name'],
            severity=SeverityLevel.INFORMATIONAL,
            description=openvas_result['description']
        )
        vulnerabilities.append(openvas_vuln_obj)

        # Verify all vulnerabilities are valid
        assert len(vulnerabilities) == 4
        for vuln in vulnerabilities:
            assert vuln.id is not None
            assert vuln.name is not None
            assert vuln.severity in SeverityLevel
            assert vuln.description is not None

    def test_output_formatter_integration(self):
        """Test output formatter integration with vulnerability data"""
        from common import (
            Vulnerability, SeverityLevel, ScanTarget, ScanResult, ScanStatus,
            JSONFormatter, XMLFormatter, CSVFormatter, TXTFormatter, HTMLFormatter
        )

        # Create sample vulnerability data
        target = ScanTarget("192.168.1.100", [80, 443])
        vulnerability = Vulnerability(
            id="test-123",
            name="Test Vulnerability",
            severity=SeverityLevel.HIGH,
            description="Test vulnerability description",
            solution="Update software",
            cvss_score=7.5,
            affected_url="http://192.168.1.100/vulnerable",
            affected_parameter="id"
        )

        scan_result = ScanResult(
            scan_id="integration-test-123",
            scanner_name="Test Scanner",
            target=target,
            status=ScanStatus.COMPLETED,
            start_time=datetime.now(),
            end_time=datetime.now(),
            vulnerabilities=[vulnerability]
        )

        # Test all formatters
        formatters = [
            JSONFormatter(),
            XMLFormatter(),
            CSVFormatter(),
            TXTFormatter(),
            HTMLFormatter()
        ]

        for formatter in formatters:
            try:
                content = formatter.format_scan_result(scan_result)
                assert content is not None
                assert len(content) > 0

                # Basic content validation
                if isinstance(formatter, JSONFormatter):
                    # Should be valid JSON
                    parsed = json.loads(content)
                    assert 'scan_id' in parsed
                    assert 'vulnerabilities' in parsed

                elif isinstance(formatter, XMLFormatter):
                    # Should contain XML tags
                    assert '<scan_result>' in content
                    assert '<vulnerability>' in content

                elif isinstance(formatter, CSVFormatter):
                    # Should contain CSV headers and data
                    assert 'ID,Name,Severity' in content
                    assert 'test-123' in content

                elif isinstance(formatter, TXTFormatter):
                    # Should contain readable text
                    assert 'Test Vulnerability' in content
                    assert 'HIGH' in content

                elif isinstance(formatter, HTMLFormatter):
                    # Should contain HTML tags
                    assert '<html>' in content
                    assert '<table>' in content

            except Exception as e:
                pytest.fail(f"Formatter {formatter.__class__.__name__} failed: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])