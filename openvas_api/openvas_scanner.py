"""
OpenVAS vulnerability scanner implementation
"""
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime
import xml.etree.ElementTree as ET
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
except ImportError:
    UnixSocketConnection = None
    TLSConnection = None
    Gmp = None
    EtreeTransform = None

from common import (
    BaseScanner, ScanTarget, ScanResult, ScanStatus,
    Vulnerability, SeverityLevel
)


class OpenVASScanner(BaseScanner):
    """OpenVAS vulnerability scanner implementation"""

    def __init__(self, host: str = "localhost", port: int = 9390,
                 username: str = "admin", password: str = "admin",
                 socket_path: str = None):
        super().__init__("OpenVAS")
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.socket_path = socket_path
        self.gmp = None
        self.connection = None
        self.task_mappings: Dict[str, str] = {}  # Map our scan_id to OpenVAS task_id

        # Check if python-gvm is available
        if not all([UnixSocketConnection, TLSConnection, Gmp, EtreeTransform]):
            self.logger.error("python-gvm is not installed. Please install it: pip install python-gvm")

    def _connect(self) -> bool:
        """Connect to OpenVAS Manager"""
        try:
            if self.socket_path and os.path.exists(self.socket_path):
                # Use Unix socket connection
                self.connection = UnixSocketConnection(path=self.socket_path)
            else:
                # Use TLS connection
                self.connection = TLSConnection(hostname=self.host, port=self.port)

            transform = EtreeTransform()
            self.gmp = Gmp(connection=self.connection, transform=transform)

            # Authenticate
            self.gmp.authenticate(self.username, self.password)
            self.logger.info("Successfully connected to OpenVAS")
            return True

        except Exception as e:
            self.logger.error(f"Failed to connect to OpenVAS: {e}")
            self.gmp = None
            self.connection = None
            return False

    def _disconnect(self):
        """Disconnect from OpenVAS"""
        try:
            if self.gmp:
                self.gmp.disconnect()
            if self.connection:
                self.connection.disconnect()
        except Exception as e:
            self.logger.warning(f"Error during disconnect: {e}")
        finally:
            self.gmp = None
            self.connection = None

    def scan(self, target: ScanTarget, options: Dict[str, Any] = None) -> str:
        """Start OpenVAS scan"""
        if not self.validate_target(target):
            raise ValueError("Invalid target configuration")

        if not all([UnixSocketConnection, TLSConnection, Gmp, EtreeTransform]):
            raise RuntimeError("python-gvm is not available")

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

            # Connect to OpenVAS
            if not self._connect():
                self.set_error(scan_id, "Failed to connect to OpenVAS")
                return

            # Create target
            target_id = self._create_openvas_target(scan_id, target, options)
            if not target_id:
                self.set_error(scan_id, "Failed to create OpenVAS target")
                return

            # Create task
            task_id = self._create_openvas_task(scan_id, target_id, options)
            if not task_id:
                self.set_error(scan_id, "Failed to create OpenVAS task")
                return

            self.task_mappings[scan_id] = task_id

            # Start task
            if not self._start_openvas_task(task_id):
                self.set_error(scan_id, "Failed to start OpenVAS task")
                return

            # Wait for completion
            self._wait_for_task_completion(scan_id, task_id)

            # Get results
            self._collect_scan_results(scan_id, task_id)

            self.update_scan_status(scan_id, ScanStatus.COMPLETED)
            self.logger.info(f"OpenVAS scan {scan_id} completed")

        except Exception as e:
            self.logger.error(f"OpenVAS scan {scan_id} failed: {e}")
            self.set_error(scan_id, str(e))
        finally:
            self._disconnect()

    def _create_openvas_target(self, scan_id: str, target: ScanTarget, options: Dict[str, Any]) -> Optional[str]:
        """Create target in OpenVAS"""
        try:
            target_name = f"API_Target_{scan_id[:8]}_{target.ip_address}"

            # Build hosts string
            hosts = [target.ip_address]

            # Create port range
            if len(target.ports) < 20:  # Only specify ports if not too many
                port_range = ','.join(map(str, target.ports))
            else:
                port_range = "1-65535"

            # Create target
            resp = self.gmp.create_target(
                name=target_name,
                hosts=hosts,
                port_range=port_range
            )

            target_id = resp.get('id')
            if target_id:
                self.logger.info(f"Created OpenVAS target {target_id} for {scan_id}")
                return target_id
            else:
                self.logger.error("Failed to create OpenVAS target")
                return None

        except Exception as e:
            self.logger.error(f"Error creating OpenVAS target: {e}")
            return None

    def _create_openvas_task(self, scan_id: str, target_id: str, options: Dict[str, Any]) -> Optional[str]:
        """Create task in OpenVAS"""
        try:
            task_name = f"API_Task_{scan_id[:8]}"

            # Get scan config
            config_id = options.get('config_id')
            if not config_id:
                config_id = self._get_default_scan_config()

            if not config_id:
                self.logger.error("No scan configuration available")
                return None

            # Get scanner ID
            scanner_id = self._get_default_scanner()
            if not scanner_id:
                self.logger.error("No scanner available")
                return None

            # Create task
            resp = self.gmp.create_task(
                name=task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )

            task_id = resp.get('id')
            if task_id:
                self.logger.info(f"Created OpenVAS task {task_id} for {scan_id}")
                return task_id
            else:
                self.logger.error("Failed to create OpenVAS task")
                return None

        except Exception as e:
            self.logger.error(f"Error creating OpenVAS task: {e}")
            return None

    def _get_default_scan_config(self) -> Optional[str]:
        """Get default scan configuration"""
        try:
            configs = self.gmp.get_scan_configs()

            # Look for Full and fast config
            for config in configs.xpath('config'):
                name = config.find('name').text
                if 'Full and fast' in name:
                    return config.get('id')

            # Fallback to first available config
            first_config = configs.xpath('config[1]')
            if first_config:
                return first_config[0].get('id')

            return None

        except Exception as e:
            self.logger.error(f"Error getting scan config: {e}")
            return None

    def _get_default_scanner(self) -> Optional[str]:
        """Get default scanner"""
        try:
            scanners = self.gmp.get_scanners()

            # Look for OpenVAS Default scanner
            for scanner in scanners.xpath('scanner'):
                name = scanner.find('name').text
                if 'OpenVAS' in name or 'Default' in name:
                    return scanner.get('id')

            # Fallback to first available scanner
            first_scanner = scanners.xpath('scanner[1]')
            if first_scanner:
                return first_scanner[0].get('id')

            return None

        except Exception as e:
            self.logger.error(f"Error getting scanner: {e}")
            return None

    def _start_openvas_task(self, task_id: str) -> bool:
        """Start OpenVAS task"""
        try:
            resp = self.gmp.start_task(task_id)
            self.logger.info(f"Started OpenVAS task {task_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error starting OpenVAS task: {e}")
            return False

    def _wait_for_task_completion(self, scan_id: str, task_id: str):
        """Wait for task to complete"""
        import time

        while True:
            # Check if our scan was stopped
            if self.active_scans[scan_id].status == ScanStatus.STOPPED:
                self._stop_openvas_task(task_id)
                break

            # Check task status
            task_status = self._get_openvas_task_status(task_id)
            if not task_status:
                time.sleep(10)
                continue

            status = task_status.get('status')
            self.logger.debug(f"OpenVAS task {task_id} status: {status}")

            if status in ['Done', 'Stopped', 'Interrupted']:
                break
            elif status == 'Running':
                time.sleep(15)  # Check every 15 seconds
            else:
                time.sleep(10)

    def _get_openvas_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get OpenVAS task status"""
        try:
            task = self.gmp.get_task(task_id)
            status_elem = task.find('status')
            progress_elem = task.find('progress')

            if status_elem is not None:
                return {
                    'status': status_elem.text,
                    'progress': progress_elem.text if progress_elem is not None else '0'
                }

            return None

        except Exception as e:
            self.logger.error(f"Error getting OpenVAS task status: {e}")
            return None

    def _collect_scan_results(self, scan_id: str, task_id: str):
        """Collect scan results from OpenVAS"""
        try:
            # Get task to find report ID
            task = self.gmp.get_task(task_id)
            last_report = task.find('.//last_report/report')

            if last_report is None:
                self.logger.warning("No report found for task")
                return

            report_id = last_report.get('id')
            if not report_id:
                self.logger.warning("No report ID found")
                return

            # Get report details
            report = self.gmp.get_report(report_id=report_id)

            # Parse results
            for result in report.xpath('.//result'):
                vulnerability = self._parse_openvas_result(result)
                if vulnerability:
                    self.add_vulnerability(scan_id, vulnerability)

        except Exception as e:
            self.logger.error(f"Error collecting scan results: {e}")

    def _parse_openvas_result(self, result_elem: ET.Element) -> Optional[Vulnerability]:
        """Parse OpenVAS result into Vulnerability object"""
        try:
            # Extract basic information
            nvt = result_elem.find('nvt')
            if nvt is None:
                return None

            nvt_oid = nvt.get('oid', '')
            name_elem = nvt.find('name')
            name = name_elem.text if name_elem is not None else 'Unknown Vulnerability'

            # Extract severity and threat
            severity_elem = result_elem.find('severity')
            threat_elem = result_elem.find('threat')

            severity_score = 0.0
            if severity_elem is not None:
                try:
                    severity_score = float(severity_elem.text)
                except (ValueError, TypeError):
                    pass

            threat = threat_elem.text if threat_elem is not None else 'Log'

            # Map OpenVAS threat levels to our severity levels
            severity_mapping = {
                'High': SeverityLevel.HIGH,
                'Medium': SeverityLevel.MEDIUM,
                'Low': SeverityLevel.LOW,
                'Log': SeverityLevel.INFORMATIONAL,
                'Debug': SeverityLevel.INFORMATIONAL,
                'False Positive': SeverityLevel.INFORMATIONAL
            }

            severity = severity_mapping.get(threat, SeverityLevel.INFORMATIONAL)

            # Extract additional details
            description_elem = result_elem.find('description')
            description = description_elem.text if description_elem is not None else ''

            # Extract host information
            host_elem = result_elem.find('host')
            host = host_elem.text if host_elem is not None else ''

            port_elem = result_elem.find('port')
            port = port_elem.text if port_elem is not None else ''

            # Build affected URL if applicable
            affected_url = ""
            if host and port and '/' in port:
                # Port format: "80/tcp" or "443/tcp"
                port_num = port.split('/')[0]
                if port_num in ['80', '8080']:
                    affected_url = f"http://{host}:{port_num}"
                elif port_num in ['443', '8443']:
                    affected_url = f"https://{host}:{port_num}"

            # Extract CVE information from tags
            cve_id = ""
            tags = nvt.find('tags')
            if tags is not None and tags.text:
                # Look for CVE in tags
                import re
                cve_match = re.search(r'CVE-\d{4}-\d{4,}', tags.text)
                if cve_match:
                    cve_id = cve_match.group(0)

            # Extract solution
            solution = ""
            solution_elem = nvt.find('solution')
            if solution_elem is not None and solution_elem.text:
                solution = solution_elem.text

            # Extract references
            reference = ""
            refs_elem = nvt.find('refs')
            if refs_elem is not None:
                ref_links = []
                for ref in refs_elem.findall('ref'):
                    ref_type = ref.get('type', '')
                    ref_id = ref.get('id', '')
                    if ref_type and ref_id:
                        ref_links.append(f"{ref_type}: {ref_id}")
                reference = '; '.join(ref_links)

            vulnerability = Vulnerability(
                id=nvt_oid,
                name=name,
                severity=severity,
                description=description,
                solution=solution,
                reference=reference,
                cve_id=cve_id,
                cvss_score=severity_score,
                affected_url=affected_url,
                affected_parameter=port,
                evidence=f"Host: {host}, Port: {port}"
            )

            return vulnerability

        except Exception as e:
            self.logger.error(f"Error parsing OpenVAS result: {e}")
            return None

    def _stop_openvas_task(self, task_id: str) -> bool:
        """Stop OpenVAS task"""
        try:
            self.gmp.stop_task(task_id)
            self.logger.info(f"Stopped OpenVAS task {task_id}")
            return True

        except Exception as e:
            self.logger.error(f"Error stopping OpenVAS task: {e}")
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
        if scan_id not in self.task_mappings:
            return False

        try:
            # Connect to stop the task
            if self._connect():
                task_id = self.task_mappings[scan_id]
                success = self._stop_openvas_task(task_id)
                self._disconnect()

                if success:
                    self.update_scan_status(scan_id, ScanStatus.STOPPED)

                return success

        except Exception as e:
            self.logger.error(f"Error stopping scan {scan_id}: {e}")

        return False

    def get_supported_formats(self) -> List[str]:
        """Get supported output formats"""
        return ['json', 'xml', 'csv', 'txt', 'html']

    def is_openvas_available(self) -> bool:
        """Check if OpenVAS is available"""
        try:
            if not all([UnixSocketConnection, TLSConnection, Gmp, EtreeTransform]):
                return False

            # Try to connect
            connected = self._connect()
            if connected:
                self._disconnect()
            return connected

        except Exception:
            return False

    def get_openvas_version(self) -> str:
        """Get OpenVAS version"""
        try:
            if self._connect():
                version = self.gmp.get_version()
                self._disconnect()
                return version.text if hasattr(version, 'text') else str(version)
        except Exception:
            pass
        return "Unknown"

    def get_scan_configs(self) -> List[Dict[str, Any]]:
        """Get available scan configurations"""
        configs = []
        try:
            if self._connect():
                config_list = self.gmp.get_scan_configs()
                for config in config_list.xpath('config'):
                    configs.append({
                        'id': config.get('id'),
                        'name': config.find('name').text,
                        'comment': config.find('comment').text if config.find('comment') is not None else ''
                    })
                self._disconnect()
        except Exception as e:
            self.logger.error(f"Error getting scan configs: {e}")

        return configs

    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """Get detailed scan progress"""
        if scan_id not in self.task_mappings:
            return {}

        try:
            if self._connect():
                task_id = self.task_mappings[scan_id]
                status_info = self._get_openvas_task_status(task_id)
                self._disconnect()

                if status_info:
                    return {
                        'status': status_info.get('status'),
                        'progress': f"{status_info.get('progress', 0)}%"
                    }

        except Exception as e:
            self.logger.error(f"Error getting scan progress: {e}")

        return {}