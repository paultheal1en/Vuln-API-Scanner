"""
OWASP ZAP vulnerability scanner implementation
"""
import time
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None

from common import (
    BaseScanner, ScanTarget, ScanResult, ScanStatus,
    Vulnerability, SeverityLevel, convert_to_urls
)


class ZAPScanner(BaseScanner):
    """OWASP ZAP vulnerability scanner implementation"""

    def __init__(self, proxy_url: str = 'http://127.0.0.1:8080', api_key: str = None):
        super().__init__("OWASP ZAP")
        self.proxy_url = proxy_url
        self.api_key = api_key
        self.zap = None
        self.scan_sessions: Dict[str, Dict[str, Any]] = {}

        # Initialize ZAP connection
        self._initialize_zap()

    def _initialize_zap(self):
        """Initialize ZAP connection"""
        if ZAPv2 is None:
            self.logger.error("python-owasp-zap-v2.4 is not installed")
            return

        try:
            proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            self.zap = ZAPv2(proxies=proxies, apikey=self.api_key)

            # Test connection
            version = self.zap.core.version
            self.logger.info(f"Connected to ZAP version: {version}")

        except Exception as e:
            self.logger.error(f"Failed to connect to ZAP: {e}")
            self.zap = None

    def scan(self, target: ScanTarget, options: Dict[str, Any] = None) -> str:
        """Start ZAP scan"""
        if not self.zap:
            raise RuntimeError("ZAP is not available")

        if not self.validate_target(target):
            raise ValueError("Invalid target configuration")

        scan_id = self.generate_scan_id()
        scan_result = self.create_scan_result(scan_id, target, options)
        self.active_scans[scan_id] = scan_result

        # Store scan session info
        self.scan_sessions[scan_id] = {
            'spider_ids': [],
            'ascan_ids': [],
            'targets': []
        }

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

            # Generate URLs from IP and ports
            urls = convert_to_urls(target.ip_address, target.ports, ['http', 'https'])
            self.scan_sessions[scan_id]['targets'] = urls

            scan_type = options.get('scan_type', 'full')

            for url in urls:
                self.logger.info(f"Scanning {url}")

                if scan_type in ['spider', 'full']:
                    self._run_spider_scan(scan_id, url, options)

                if scan_type in ['active', 'full']:
                    self._run_active_scan(scan_id, url, options)

            # Collect results
            self._collect_scan_results(scan_id, urls)

            self.update_scan_status(scan_id, ScanStatus.COMPLETED)
            self.logger.info(f"ZAP scan {scan_id} completed")

        except Exception as e:
            self.logger.error(f"ZAP scan {scan_id} failed: {e}")
            self.set_error(scan_id, str(e))

    def _run_spider_scan(self, scan_id: str, url: str, options: Dict[str, Any]):
        """Run spider scan on URL"""
        try:
            self.logger.info(f"Starting spider scan on {url}")

            # Configure spider options
            spider_options = options.get('spider', {})
            max_depth = spider_options.get('max_depth', 5)
            max_children = spider_options.get('max_children', 10)

            # Start spider
            spider_id = self.zap.spider.scan(url, maxchildren=max_children, depth=max_depth)
            self.scan_sessions[scan_id]['spider_ids'].append(spider_id)

            # Wait for spider to complete
            while int(self.zap.spider.status(spider_id)) < 100:
                time.sleep(2)
                # Check if scan was stopped
                if self.active_scans[scan_id].status == ScanStatus.STOPPED:
                    self.zap.spider.stop(spider_id)
                    break

            self.logger.info(f"Spider scan completed for {url}")

        except Exception as e:
            self.logger.error(f"Spider scan failed for {url}: {e}")

    def _run_active_scan(self, scan_id: str, url: str, options: Dict[str, Any]):
        """Run active scan on URL"""
        try:
            self.logger.info(f"Starting active scan on {url}")

            # Configure active scan options
            ascan_options = options.get('active_scan', {})
            scan_policy = ascan_options.get('policy_name', None)

            # Start active scan
            ascan_id = self.zap.ascan.scan(url, scanpolicyname=scan_policy)
            self.scan_sessions[scan_id]['ascan_ids'].append(ascan_id)

            # Wait for active scan to complete
            while int(self.zap.ascan.status(ascan_id)) < 100:
                time.sleep(5)
                # Check if scan was stopped
                if self.active_scans[scan_id].status == ScanStatus.STOPPED:
                    self.zap.ascan.stop(ascan_id)
                    break

            self.logger.info(f"Active scan completed for {url}")

        except Exception as e:
            self.logger.error(f"Active scan failed for {url}: {e}")

    def _collect_scan_results(self, scan_id: str, urls: List[str]):
        """Collect scan results from ZAP"""
        try:
            # Get alerts for all URLs
            for url in urls:
                alerts = self.zap.core.alerts(baseurl=url)

                for alert in alerts:
                    vulnerability = self._parse_zap_alert(alert)
                    if vulnerability:
                        self.add_vulnerability(scan_id, vulnerability)

        except Exception as e:
            self.logger.error(f"Failed to collect scan results: {e}")

    def _parse_zap_alert(self, alert: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse ZAP alert into Vulnerability object"""
        try:
            # Map ZAP risk levels to our severity levels
            risk_mapping = {
                'High': SeverityLevel.HIGH,
                'Medium': SeverityLevel.MEDIUM,
                'Low': SeverityLevel.LOW,
                'Informational': SeverityLevel.INFORMATIONAL
            }

            severity = risk_mapping.get(alert.get('risk', 'Informational'), SeverityLevel.INFORMATIONAL)

            # Extract CVSS score if available
            cvss_score = 0.0
            try:
                if 'cvssScore' in alert:
                    cvss_score = float(alert['cvssScore'])
            except (ValueError, TypeError):
                pass

            vulnerability = Vulnerability(
                id=alert.get('id', ''),
                name=alert.get('name', 'Unknown Alert'),
                severity=severity,
                description=alert.get('description', ''),
                solution=alert.get('solution', ''),
                reference=alert.get('reference', ''),
                cve_id=self._extract_cve_from_reference(alert.get('reference', '')),
                cvss_score=cvss_score,
                affected_url=alert.get('url', ''),
                affected_parameter=alert.get('param', ''),
                evidence=alert.get('evidence', '')
            )

            return vulnerability

        except Exception as e:
            self.logger.error(f"Error parsing ZAP alert: {e}")
            return None

    def _extract_cve_from_reference(self, reference: str) -> str:
        """Extract CVE ID from reference string"""
        import re
        if not reference:
            return ""

        cve_pattern = r'CVE-\d{4}-\d{4,}'
        match = re.search(cve_pattern, reference)
        return match.group(0) if match else ""

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
        if scan_id not in self.scan_sessions:
            return False

        try:
            session = self.scan_sessions[scan_id]

            # Stop spider scans
            for spider_id in session['spider_ids']:
                try:
                    self.zap.spider.stop(spider_id)
                except Exception as e:
                    self.logger.warning(f"Failed to stop spider {spider_id}: {e}")

            # Stop active scans
            for ascan_id in session['ascan_ids']:
                try:
                    self.zap.ascan.stop(ascan_id)
                except Exception as e:
                    self.logger.warning(f"Failed to stop active scan {ascan_id}: {e}")

            self.update_scan_status(scan_id, ScanStatus.STOPPED)
            return True

        except Exception as e:
            self.logger.error(f"Error stopping scan {scan_id}: {e}")
            return False

    def get_supported_formats(self) -> List[str]:
        """Get supported output formats"""
        return ['json', 'xml', 'csv', 'txt', 'html']

    def is_zap_available(self) -> bool:
        """Check if ZAP is available"""
        try:
            if not self.zap:
                return False
            version = self.zap.core.version
            return bool(version)
        except Exception:
            return False

    def get_zap_version(self) -> str:
        """Get ZAP version"""
        try:
            if self.zap:
                return self.zap.core.version
        except Exception:
            pass
        return "Unknown"

    def create_new_session(self, session_name: str = None) -> bool:
        """Create new ZAP session"""
        try:
            if not session_name:
                session_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

            self.zap.core.new_session(name=session_name, overwrite=True)
            return True

        except Exception as e:
            self.logger.error(f"Failed to create ZAP session: {e}")
            return False

    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """Get detailed scan progress"""
        if scan_id not in self.scan_sessions:
            return {}

        session = self.scan_sessions[scan_id]
        progress = {
            'spider_progress': [],
            'ascan_progress': [],
            'overall_progress': 0
        }

        try:
            # Get spider progress
            for spider_id in session['spider_ids']:
                try:
                    spider_progress = int(self.zap.spider.status(spider_id))
                    progress['spider_progress'].append({
                        'id': spider_id,
                        'progress': spider_progress
                    })
                except Exception:
                    pass

            # Get active scan progress
            for ascan_id in session['ascan_ids']:
                try:
                    ascan_progress = int(self.zap.ascan.status(ascan_id))
                    progress['ascan_progress'].append({
                        'id': ascan_id,
                        'progress': ascan_progress
                    })
                except Exception:
                    pass

            # Calculate overall progress
            all_progress = []
            all_progress.extend([sp['progress'] for sp in progress['spider_progress']])
            all_progress.extend([ap['progress'] for ap in progress['ascan_progress']])

            if all_progress:
                progress['overall_progress'] = sum(all_progress) / len(all_progress)

        except Exception as e:
            self.logger.error(f"Error getting scan progress: {e}")

        return progress

    def get_spider_results(self, scan_id: str) -> List[str]:
        """Get spider scan results (discovered URLs)"""
        if scan_id not in self.scan_sessions:
            return []

        urls = []
        session = self.scan_sessions[scan_id]

        try:
            for spider_id in session['spider_ids']:
                try:
                    spider_results = self.zap.spider.results(spider_id)
                    urls.extend(spider_results)
                except Exception as e:
                    self.logger.warning(f"Failed to get spider results for {spider_id}: {e}")

        except Exception as e:
            self.logger.error(f"Error getting spider results: {e}")

        return list(set(urls))  # Remove duplicates

    def export_zap_session(self, scan_id: str, file_path: str) -> bool:
        """Export ZAP session to file"""
        try:
            self.zap.core.save_session(file_path, overwrite=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to export ZAP session: {e}")
            return False