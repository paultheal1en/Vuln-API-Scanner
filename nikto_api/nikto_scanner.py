"""
Nikto vulnerability scanner implementation
"""
import subprocess
import tempfile
import os
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import threading
from datetime import datetime

import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (
    BaseScanner, ScanTarget, ScanResult, ScanStatus,
    Vulnerability, SeverityLevel, convert_to_urls
)


class NiktoScanner(BaseScanner):
    """Nikto vulnerability scanner implementation"""

    def __init__(self, nikto_path: str = "/usr/bin/nikto"):
        super().__init__("Nikto")
        self.nikto_path = nikto_path
        self.running_processes: Dict[str, subprocess.Popen] = {}

    def scan(self, target: ScanTarget, options: Dict[str, Any] = None) -> str:
        """Start Nikto scan"""
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

            # Generate URLs from IP and ports
            urls = convert_to_urls(target.ip_address, target.ports, ['http', 'https'])

            for url in urls:
                self.logger.info(f"Scanning {url}")
                vulnerabilities = self._scan_single_url(url, options)

                for vuln in vulnerabilities:
                    self.add_vulnerability(scan_id, vuln)

            self.update_scan_status(scan_id, ScanStatus.COMPLETED)
            self.logger.info(f"Nikto scan {scan_id} completed")

        except Exception as e:
            self.logger.error(f"Nikto scan {scan_id} failed: {e}")
            self.set_error(scan_id, str(e))

    def _scan_single_url(self, url: str, options: Dict[str, Any]) -> List[Vulnerability]:
        """Scan single URL with Nikto"""
        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            output_file = temp_file.name

        try:
            # Build nikto command
            cmd = self._build_nikto_command(url, output_file, options)

            # Run nikto
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            process = subprocess.run(
                cmd,
                timeout=options.get('timeout', 300),  # 5 minutes default
                capture_output=True,
                text=True
            )

            # Parse results
            vulnerabilities = self._parse_nikto_output(output_file, url)
            return vulnerabilities

        except subprocess.TimeoutExpired:
            self.logger.warning(f"Nikto scan timed out for {url}")
            return []
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {e}")
            return []
        finally:
            # Clean up temporary file
            if os.path.exists(output_file):
                os.unlink(output_file)

    def _build_nikto_command(self, url: str, output_file: str, options: Dict[str, Any]) -> List[str]:
        """Build nikto command line"""
        cmd = [
            self.nikto_path,
            '-h', url,
            '-o', output_file,
            '-Format', 'xml'
        ]

        # Add options
        if options.get('ssl'):
            cmd.append('-ssl')

        if 'pause' in options:
            cmd.extend(['-Pause', str(options['pause'])])

        if 'timeout' in options:
            cmd.extend(['-timeout', str(options['timeout'])])

        if 'plugins' in options:
            cmd.extend(['-Plugins', options['plugins']])

        if 'useragent' in options:
            cmd.extend(['-useragent', options['useragent']])

        if 'auth' in options:
            auth = options['auth']
            if 'basic' in auth:
                cmd.extend(['-id', f"{auth['basic']['username']}:{auth['basic']['password']}"])

        # Disable some noisy tests by default
        cmd.extend(['-nointeractive', '-ask', 'no'])

        return cmd

    def _parse_nikto_output(self, output_file: str, url: str) -> List[Vulnerability]:
        """Parse Nikto XML output"""
        vulnerabilities = []

        try:
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                return vulnerabilities

            tree = ET.parse(output_file)
            root = tree.getroot()

            # Parse scan items
            for item in root.findall('.//item'):
                vuln = self._parse_nikto_item(item, url)
                if vuln:
                    vulnerabilities.append(vuln)

        except ET.ParseError as e:
            self.logger.error(f"Failed to parse Nikto XML output: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing Nikto output: {e}")

        return vulnerabilities

    def _parse_nikto_item(self, item: ET.Element, base_url: str) -> Optional[Vulnerability]:
        """Parse individual Nikto vulnerability item"""
        try:
            vuln_id = item.get('id', '')
            osvdb_id = item.get('osvdb', '')
            method = item.get('method', 'GET')

            uri_elem = item.find('uri')
            uri = uri_elem.text if uri_elem is not None else ''

            desc_elem = item.find('description')
            description = desc_elem.text if desc_elem is not None else ''

            # Build full URL
            if uri and not uri.startswith('http'):
                if uri.startswith('/'):
                    affected_url = base_url + uri
                else:
                    affected_url = base_url + '/' + uri
            else:
                affected_url = uri or base_url

            # Determine severity based on description keywords
            severity = self._determine_severity(description)

            # Extract CVE if present
            cve_id = self._extract_cve_from_description(description)

            # Create vulnerability object
            vuln = Vulnerability(
                id=vuln_id or f"NIKTO-{osvdb_id}" if osvdb_id else f"NIKTO-{hash(description) % 10000}",
                name=self._extract_vulnerability_name(description),
                severity=severity,
                description=description,
                solution=self._get_generic_solution(severity),
                reference=f"OSVDB-{osvdb_id}" if osvdb_id else "",
                cve_id=cve_id,
                affected_url=affected_url,
                affected_parameter="",
                evidence=f"Method: {method}, URI: {uri}"
            )

            return vuln

        except Exception as e:
            self.logger.error(f"Error parsing Nikto item: {e}")
            return None

    def _determine_severity(self, description: str) -> SeverityLevel:
        """Determine vulnerability severity based on description"""
        desc_lower = description.lower()

        # High severity indicators
        high_indicators = [
            'sql injection', 'xss', 'cross-site scripting', 'command injection',
            'code injection', 'authentication bypass', 'directory traversal',
            'path traversal', 'remote code execution', 'arbitrary file'
        ]

        # Medium severity indicators
        medium_indicators = [
            'sensitive', 'password', 'configuration', 'backup', 'database',
            'admin', 'login', 'credential', 'session', 'cookie'
        ]

        # Low severity indicators
        low_indicators = [
            'information disclosure', 'version disclosure', 'banner',
            'server version', 'technology disclosure'
        ]

        if any(indicator in desc_lower for indicator in high_indicators):
            return SeverityLevel.HIGH
        elif any(indicator in desc_lower for indicator in medium_indicators):
            return SeverityLevel.MEDIUM
        elif any(indicator in desc_lower for indicator in low_indicators):
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFORMATIONAL

    def _extract_vulnerability_name(self, description: str) -> str:
        """Extract vulnerability name from description"""
        # Try to get the first sentence or first 100 characters
        first_sentence = description.split('.')[0]
        if len(first_sentence) <= 100:
            return first_sentence
        else:
            return description[:100] + "..."

    def _extract_cve_from_description(self, description: str) -> str:
        """Extract CVE ID from description if present"""
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        match = re.search(cve_pattern, description)
        return match.group(0) if match else ""

    def _get_generic_solution(self, severity: SeverityLevel) -> str:
        """Get generic solution based on severity"""
        solutions = {
            SeverityLevel.HIGH: "Immediate action required. Review and fix the vulnerability. Consider disabling the affected functionality until fixed.",
            SeverityLevel.MEDIUM: "Review the finding and implement appropriate security measures. Update software if applicable.",
            SeverityLevel.LOW: "Consider implementing security best practices. Monitor for unusual activity.",
            SeverityLevel.INFORMATIONAL: "Review for potential security implications. Consider hiding version information."
        }
        return solutions.get(severity, "Review the finding and take appropriate action.")

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
        if scan_id in self.running_processes:
            try:
                process = self.running_processes[scan_id]
                process.terminate()
                process.wait(timeout=5)
                del self.running_processes[scan_id]
                self.update_scan_status(scan_id, ScanStatus.STOPPED)
                return True
            except Exception as e:
                self.logger.error(f"Error stopping scan {scan_id}: {e}")
                return False

        return False

    def get_supported_formats(self) -> List[str]:
        """Get supported output formats"""
        return ['json', 'xml', 'csv', 'txt', 'html']

    def is_nikto_available(self) -> bool:
        """Check if Nikto is available"""
        try:
            result = subprocess.run(
                [self.nikto_path, '-Version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_nikto_version(self) -> str:
        """Get Nikto version"""
        try:
            result = subprocess.run(
                [self.nikto_path, '-Version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "Unknown"