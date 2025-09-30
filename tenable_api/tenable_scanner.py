"""
Tenable Nessus vulnerability scanner implementation
"""
import requests
import time
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (
    BaseScanner, ScanTarget, ScanResult, ScanStatus,
    Vulnerability, SeverityLevel
)


class TenableScanner(BaseScanner):
    """Tenable Nessus vulnerability scanner implementation"""

    def __init__(self, url: str, access_key: str, secret_key: str):
        super().__init__("Tenable Nessus")
        self.url = url.rstrip('/')
        self.access_key = access_key
        self.secret_key = secret_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
            'Content-Type': 'application/json'
        })
        self.scan_mappings: Dict[str, int] = {}  # Map our scan_id to Tenable scan_id

    def scan(self, target: ScanTarget, options: Dict[str, Any] = None) -> str:
        """Start Tenable scan"""
        if not self.validate_target(target):
            raise ValueError("Invalid target configuration")

        scan_id = self.generate_scan_id()
        scan_result = self.create_scan_result(scan_id, target, options)
        self.active_scans[scan_id] = scan_result

        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_scan_thread,
            args=(scan_id, target, options or {})
        )
        thread.daemon = True
        thread.start()

        return scan_id

    def _run_scan_thread(self, scan_id: str, target: ScanTarget, options: Dict[str, Any]):
        """Run scan in background thread"""
        try:
            self.update_scan_status(scan_id, ScanStatus.RUNNING)

            # Create scan
            tenable_scan_id = self._create_tenable_scan(scan_id, target, options)
            if not tenable_scan_id:
                self.set_error(scan_id, "Failed to create Tenable scan")
                return

            self.scan_mappings[scan_id] = tenable_scan_id

            # Launch scan
            if not self._launch_tenable_scan(tenable_scan_id):
                self.set_error(scan_id, "Failed to launch Tenable scan")
                return

            # Wait for completion
            self._wait_for_scan_completion(scan_id, tenable_scan_id)

            # Get results
            self._collect_scan_results(scan_id, tenable_scan_id)

            self.update_scan_status(scan_id, ScanStatus.COMPLETED)
            self.logger.info(f"Tenable scan {scan_id} completed")

        except Exception as e:
            self.logger.error(f"Tenable scan {scan_id} failed: {e}")
            self.set_error(scan_id, str(e))

    def _create_tenable_scan(self, scan_id: str, target: ScanTarget, options: Dict[str, Any]) -> Optional[int]:
        """Create scan in Tenable"""
        try:
            # Get available policies
            policies = self._get_scan_policies()
            if not policies:
                self.logger.error("No scan policies available")
                return None

            # Select policy
            policy_id = options.get('policy_id')
            if not policy_id:
                # Use default policy (usually Basic Network Scan)
                default_policy = next(
                    (p for p in policies if 'Basic Network Scan' in p['name']),
                    policies[0] if policies else None
                )
                if default_policy:
                    policy_id = default_policy['id']
                else:
                    self.logger.error("No suitable policy found")
                    return None

            # Build targets string
            targets = target.ip_address
            if len(target.ports) < 10:  # Only specify ports if not too many
                port_list = ','.join(map(str, target.ports))
            else:
                port_list = None

            # Create scan configuration
            scan_config = {
                'uuid': policy_id,
                'settings': {
                    'name': f'API_Scan_{scan_id[:8]}_{target.ip_address}',
                    'text_targets': targets,
                    'enabled': False
                }
            }

            # Add port configuration if specified
            if port_list and len(target.ports) < 100:
                scan_config['settings']['port_range'] = port_list

            # Add additional options
            if 'scan_timeout' in options:
                scan_config['settings']['scan_timeout'] = options['scan_timeout']

            if 'max_hosts' in options:
                scan_config['settings']['max_hosts'] = options['max_hosts']

            # Create scan
            response = self.session.post(f'{self.url}/scans', json=scan_config)

            if response.status_code == 200:
                scan_data = response.json()
                tenable_scan_id = scan_data['scan']['id']
                self.logger.info(f"Created Tenable scan {tenable_scan_id} for {scan_id}")
                return tenable_scan_id
            else:
                self.logger.error(f"Failed to create scan: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            self.logger.error(f"Error creating Tenable scan: {e}")
            return None

    def _launch_tenable_scan(self, tenable_scan_id: int) -> bool:
        """Launch Tenable scan"""
        try:
            response = self.session.post(f'{self.url}/scans/{tenable_scan_id}/launch')

            if response.status_code == 200:
                self.logger.info(f"Launched Tenable scan {tenable_scan_id}")
                return True
            else:
                self.logger.error(f"Failed to launch scan: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            self.logger.error(f"Error launching Tenable scan: {e}")
            return False

    def _wait_for_scan_completion(self, scan_id: str, tenable_scan_id: int):
        """Wait for scan to complete"""
        while True:
            # Check if our scan was stopped
            if self.active_scans[scan_id].status == ScanStatus.STOPPED:
                self._stop_tenable_scan(tenable_scan_id)
                break

            # Check Tenable scan status
            status_info = self._get_tenable_scan_status(tenable_scan_id)
            if not status_info:
                time.sleep(10)
                continue

            status = status_info.get('status')
            self.logger.debug(f"Tenable scan {tenable_scan_id} status: {status}")

            if status in ['completed', 'canceled', 'aborted']:
                break
            elif status == 'running':
                time.sleep(15)  # Check every 15 seconds
            else:
                time.sleep(10)

    def _get_tenable_scan_status(self, tenable_scan_id: int) -> Optional[Dict[str, Any]]:
        """Get Tenable scan status"""
        try:
            response = self.session.get(f'{self.url}/scans/{tenable_scan_id}')

            if response.status_code == 200:
                scan_data = response.json()
                return scan_data['info']
            else:
                self.logger.warning(f"Failed to get scan status: {response.status_code}")
                return None

        except Exception as e:
            self.logger.error(f"Error getting Tenable scan status: {e}")
            return None

    def _collect_scan_results(self, scan_id: str, tenable_scan_id: int):
        """Collect scan results from Tenable"""
        try:
            # Get scan details
            response = self.session.get(f'{self.url}/scans/{tenable_scan_id}')

            if response.status_code != 200:
                self.logger.error(f"Failed to get scan results: {response.status_code}")
                return

            scan_data = response.json()

            # Process vulnerabilities
            if 'vulnerabilities' in scan_data:
                for vuln_summary in scan_data['vulnerabilities']:
                    # Get detailed vulnerability information
                    vuln_details = self._get_vulnerability_details(
                        tenable_scan_id,
                        vuln_summary['plugin_id']
                    )

                    if vuln_details:
                        for vuln_instance in vuln_details:
                            vulnerability = self._parse_tenable_vulnerability(vuln_summary, vuln_instance)
                            if vulnerability:
                                self.add_vulnerability(scan_id, vulnerability)

        except Exception as e:
            self.logger.error(f"Error collecting scan results: {e}")

    def _get_vulnerability_details(self, tenable_scan_id: int, plugin_id: int) -> List[Dict[str, Any]]:
        """Get detailed vulnerability information"""
        try:
            response = self.session.get(
                f'{self.url}/scans/{tenable_scan_id}/hosts',
                params={'plugin_id': plugin_id}
            )

            if response.status_code == 200:
                return response.json().get('outputs', [])
            else:
                return []

        except Exception as e:
            self.logger.error(f"Error getting vulnerability details: {e}")
            return []

    def _parse_tenable_vulnerability(self, vuln_summary: Dict[str, Any], vuln_instance: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse Tenable vulnerability into our format"""
        try:
            # Map Tenable severity to our severity levels
            severity_mapping = {
                4: SeverityLevel.CRITICAL,
                3: SeverityLevel.HIGH,
                2: SeverityLevel.MEDIUM,
                1: SeverityLevel.LOW,
                0: SeverityLevel.INFORMATIONAL
            }

            severity = severity_mapping.get(vuln_summary.get('severity', 0), SeverityLevel.INFORMATIONAL)

            # Extract CVE information
            cve_ids = []
            if 'cve' in vuln_instance:
                cve_ids = vuln_instance['cve'] if isinstance(vuln_instance['cve'], list) else [vuln_instance['cve']]

            # Build affected URL if port is specified
            affected_url = ""
            if 'port' in vuln_instance and vuln_instance['port']:
                port = vuln_instance['port']
                host = vuln_instance.get('hostname', 'unknown')
                if port in [80, 8080]:
                    affected_url = f"http://{host}:{port}"
                elif port in [443, 8443]:
                    affected_url = f"https://{host}:{port}"

            vulnerability = Vulnerability(
                id=str(vuln_summary.get('plugin_id', '')),
                name=vuln_summary.get('plugin_name', 'Unknown Vulnerability'),
                severity=severity,
                description=vuln_instance.get('description', ''),
                solution=vuln_instance.get('solution', ''),
                reference=vuln_instance.get('see_also', ''),
                cve_id=','.join(cve_ids) if cve_ids else '',
                cvss_score=float(vuln_instance.get('cvss_base_score', 0.0)),
                affected_url=affected_url,
                affected_parameter=vuln_instance.get('plugin_output', ''),
                evidence=vuln_instance.get('plugin_output', '')
            )

            return vulnerability

        except Exception as e:
            self.logger.error(f"Error parsing Tenable vulnerability: {e}")
            return None

    def _get_scan_policies(self) -> List[Dict[str, Any]]:
        """Get available scan policies"""
        try:
            response = self.session.get(f'{self.url}/policies')

            if response.status_code == 200:
                return response.json().get('policies', [])
            else:
                self.logger.error(f"Failed to get policies: {response.status_code}")
                return []

        except Exception as e:
            self.logger.error(f"Error getting scan policies: {e}")
            return []

    def _stop_tenable_scan(self, tenable_scan_id: int) -> bool:
        """Stop Tenable scan"""
        try:
            response = self.session.post(f'{self.url}/scans/{tenable_scan_id}/stop')

            if response.status_code == 200:
                self.logger.info(f"Stopped Tenable scan {tenable_scan_id}")
                return True
            else:
                self.logger.warning(f"Failed to stop scan: {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(f"Error stopping Tenable scan: {e}")
            return False

    def get_scan_status(self, scan_id: str) -> ScanStatus:
        """Get scan status"""
        if scan_id not in self.active_scans:
            return ScanStatus.FAILED

        return self.active_scans[scan_id].status

    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get complete scan result"""
        return self.active_scans.get(scan_id)

    def stop_scan(self, scan_id: str) -> bool:
        """Stop running scan"""
        if scan_id not in self.scan_mappings:
            return False

        try:
            tenable_scan_id = self.scan_mappings[scan_id]
            success = self._stop_tenable_scan(tenable_scan_id)

            if success:
                self.update_scan_status(scan_id, ScanStatus.STOPPED)

            return success

        except Exception as e:
            self.logger.error(f"Error stopping scan {scan_id}: {e}")
            return False

    def get_supported_formats(self) -> List[str]:
        """Get supported output formats"""
        return ['json', 'xml', 'csv', 'txt', 'html']

    def is_tenable_available(self) -> bool:
        """Check if Tenable is available"""
        try:
            response = self.session.get(f'{self.url}/server/status')
            return response.status_code == 200
        except Exception:
            return False

    def get_tenable_version(self) -> str:
        """Get Tenable version"""
        try:
            response = self.session.get(f'{self.url}/server/properties')
            if response.status_code == 200:
                props = response.json()
                return props.get('server_version', 'Unknown')
        except Exception:
            pass
        return "Unknown"

    def export_scan_results(self, scan_id: str, format_type: str = 'nessus') -> Optional[bytes]:
        """Export scan results in Tenable format"""
        if scan_id not in self.scan_mappings:
            return None

        try:
            tenable_scan_id = self.scan_mappings[scan_id]

            # Request export
            export_data = {"format": format_type}
            response = self.session.post(f'{self.url}/scans/{tenable_scan_id}/export', json=export_data)

            if response.status_code != 200:
                return None

            file_id = response.json()['file']

            # Wait for export to complete
            while True:
                status_response = self.session.get(f'{self.url}/scans/{tenable_scan_id}/export/{file_id}/status')
                if status_response.status_code == 200:
                    status = status_response.json()['status']
                    if status == 'ready':
                        break
                    elif status == 'error':
                        return None
                time.sleep(2)

            # Download file
            download_response = self.session.get(f'{self.url}/scans/{tenable_scan_id}/export/{file_id}/download')
            if download_response.status_code == 200:
                return download_response.content

        except Exception as e:
            self.logger.error(f"Error exporting scan results: {e}")

        return None

    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """Get detailed scan progress"""
        if scan_id not in self.scan_mappings:
            return {}

        try:
            tenable_scan_id = self.scan_mappings[scan_id]
            status_info = self._get_tenable_scan_status(tenable_scan_id)

            if status_info:
                return {
                    'status': status_info.get('status'),
                    'progress': status_info.get('progress', 0),
                    'start_time': status_info.get('scan_start'),
                    'end_time': status_info.get('scan_end'),
                    'hosts_total': status_info.get('hostcount', 0),
                    'vulnerabilities_total': status_info.get('totalchecks', 0)
                }

        except Exception as e:
            self.logger.error(f"Error getting scan progress: {e}")

        return {}