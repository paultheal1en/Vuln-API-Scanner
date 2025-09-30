"""
Abstract base class for output formatters
"""
from abc import ABC, abstractmethod
from typing import Any, Dict
from .models import ScanResult


class BaseFormatter(ABC):
    """Abstract base class for all output formatters"""

    def __init__(self, format_name: str):
        self.format_name = format_name

    @abstractmethod
    def format(self, scan_result: ScanResult) -> str:
        """
        Format scan result to specific output format

        Args:
            scan_result: Complete scan result

        Returns:
            Formatted output as string
        """
        pass

    @abstractmethod
    def get_content_type(self) -> str:
        """Get MIME content type for this format"""
        pass

    @abstractmethod
    def get_file_extension(self) -> str:
        """Get file extension for this format"""
        pass

    def get_filename(self, scan_result: ScanResult) -> str:
        """Generate filename for download"""
        scanner = scan_result.scanner_name.lower()
        target_ip = scan_result.target.ip_address.replace('.', '_')
        timestamp = scan_result.start_time.strftime('%Y%m%d_%H%M%S')
        extension = self.get_file_extension()

        return f"{scanner}_{target_ip}_{timestamp}.{extension}"

    def validate_scan_result(self, scan_result: ScanResult) -> bool:
        """Validate scan result before formatting"""
        if not scan_result:
            return False

        if not scan_result.scan_id:
            return False

        if not scan_result.target:
            return False

        return True


class JSONFormatter(BaseFormatter):
    """JSON output formatter"""

    def __init__(self):
        super().__init__("json")

    def format(self, scan_result: ScanResult) -> str:
        import json
        if not self.validate_scan_result(scan_result):
            raise ValueError("Invalid scan result")

        return json.dumps(scan_result.to_dict(), indent=2, ensure_ascii=False)

    def get_content_type(self) -> str:
        return "application/json"

    def get_file_extension(self) -> str:
        return "json"


class XMLFormatter(BaseFormatter):
    """XML output formatter"""

    def __init__(self):
        super().__init__("xml")

    def format(self, scan_result: ScanResult) -> str:
        import xml.etree.ElementTree as ET

        if not self.validate_scan_result(scan_result):
            raise ValueError("Invalid scan result")

        root = ET.Element("vulnerability_scan")

        # Metadata
        meta = ET.SubElement(root, "metadata")
        ET.SubElement(meta, "scan_id").text = scan_result.scan_id
        ET.SubElement(meta, "scanner_name").text = scan_result.scanner_name
        ET.SubElement(meta, "target_ip").text = scan_result.target.ip_address
        ET.SubElement(meta, "ports").text = ','.join(map(str, scan_result.target.ports))
        ET.SubElement(meta, "status").text = scan_result.status.value
        ET.SubElement(meta, "start_time").text = scan_result.start_time.isoformat()
        if scan_result.end_time:
            ET.SubElement(meta, "end_time").text = scan_result.end_time.isoformat()
        if scan_result.duration:
            ET.SubElement(meta, "duration_seconds").text = str(scan_result.duration)

        # Summary
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "vulnerability_count").text = str(scan_result.vulnerability_count)

        severity_elem = ET.SubElement(summary, "severity_breakdown")
        for severity, count in scan_result.severity_summary.items():
            sev_elem = ET.SubElement(severity_elem, "severity")
            sev_elem.set("level", severity)
            sev_elem.text = str(count)

        # Vulnerabilities
        vulns_elem = ET.SubElement(root, "vulnerabilities")
        for vuln in scan_result.vulnerabilities:
            vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
            for key, value in vuln.to_dict().items():
                elem = ET.SubElement(vuln_elem, key)
                elem.text = str(value) if value is not None else ""

        # Error message if any
        if scan_result.error_message:
            ET.SubElement(root, "error_message").text = scan_result.error_message

        return ET.tostring(root, encoding='unicode')

    def get_content_type(self) -> str:
        return "application/xml"

    def get_file_extension(self) -> str:
        return "xml"


class CSVFormatter(BaseFormatter):
    """CSV output formatter"""

    def __init__(self):
        super().__init__("csv")

    def format(self, scan_result: ScanResult) -> str:
        import csv
        import io

        if not self.validate_scan_result(scan_result):
            raise ValueError("Invalid scan result")

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            'Scan ID', 'Scanner', 'Target IP', 'Target Ports', 'Scan Time',
            'Vulnerability ID', 'Name', 'Severity', 'CVSS Score', 'CVE ID',
            'Affected URL', 'Parameter', 'Description', 'Solution', 'Reference'
        ])

        # Data rows
        base_info = [
            scan_result.scan_id,
            scan_result.scanner_name,
            scan_result.target.ip_address,
            ','.join(map(str, scan_result.target.ports)),
            scan_result.start_time.isoformat()
        ]

        if scan_result.vulnerabilities:
            for vuln in scan_result.vulnerabilities:
                writer.writerow(base_info + [
                    vuln.id,
                    vuln.name,
                    vuln.severity.value,
                    vuln.cvss_score,
                    vuln.cve_id,
                    vuln.affected_url,
                    vuln.affected_parameter,
                    vuln.description,
                    vuln.solution,
                    vuln.reference
                ])
        else:
            # No vulnerabilities found
            writer.writerow(base_info + ['', 'No vulnerabilities found', '', '', '', '', '', '', '', ''])

        return output.getvalue()

    def get_content_type(self) -> str:
        return "text/csv"

    def get_file_extension(self) -> str:
        return "csv"


class TXTFormatter(BaseFormatter):
    """Plain text output formatter"""

    def __init__(self):
        super().__init__("txt")

    def format(self, scan_result: ScanResult) -> str:
        if not self.validate_scan_result(scan_result):
            raise ValueError("Invalid scan result")

        lines = []
        lines.append("=" * 80)
        lines.append(f"{scan_result.scanner_name.upper()} VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")

        # Basic info
        lines.append("SCAN INFORMATION")
        lines.append("-" * 40)
        lines.append(f"Scan ID: {scan_result.scan_id}")
        lines.append(f"Target IP: {scan_result.target.ip_address}")
        lines.append(f"Target Ports: {', '.join(map(str, scan_result.target.ports))}")
        lines.append(f"Scanner: {scan_result.scanner_name}")
        lines.append(f"Status: {scan_result.status.value}")
        lines.append(f"Start Time: {scan_result.start_time}")
        if scan_result.end_time:
            lines.append(f"End Time: {scan_result.end_time}")
        if scan_result.duration:
            lines.append(f"Duration: {scan_result.duration:.2f} seconds")
        lines.append("")

        # Summary
        lines.append("SUMMARY")
        lines.append("-" * 40)
        lines.append(f"Total Vulnerabilities: {scan_result.vulnerability_count}")

        severity_summary = scan_result.severity_summary
        lines.append(f"Critical: {severity_summary.get('critical', 0)}")
        lines.append(f"High: {severity_summary.get('high', 0)}")
        lines.append(f"Medium: {severity_summary.get('medium', 0)}")
        lines.append(f"Low: {severity_summary.get('low', 0)}")
        lines.append(f"Informational: {severity_summary.get('informational', 0)}")
        lines.append("")

        # Vulnerabilities
        if scan_result.vulnerabilities:
            lines.append("VULNERABILITIES")
            lines.append("-" * 40)

            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                lines.append(f"{i}. [{vuln.severity.value.upper()}] {vuln.name}")
                if vuln.affected_url:
                    lines.append(f"   URL: {vuln.affected_url}")
                if vuln.affected_parameter:
                    lines.append(f"   Parameter: {vuln.affected_parameter}")
                if vuln.cve_id:
                    lines.append(f"   CVE: {vuln.cve_id}")
                if vuln.cvss_score > 0:
                    lines.append(f"   CVSS Score: {vuln.cvss_score}")
                lines.append(f"   Description: {vuln.description}")
                if vuln.solution:
                    lines.append(f"   Solution: {vuln.solution}")
                if vuln.reference:
                    lines.append(f"   Reference: {vuln.reference}")
                lines.append("")
        else:
            lines.append("No vulnerabilities found.")
            lines.append("")

        # Error message
        if scan_result.error_message:
            lines.append("ERRORS")
            lines.append("-" * 40)
            lines.append(scan_result.error_message)
            lines.append("")

        lines.append("=" * 80)
        lines.append("End of Report")
        lines.append("=" * 80)

        return "\n".join(lines)

    def get_content_type(self) -> str:
        return "text/plain"

    def get_file_extension(self) -> str:
        return "txt"


class HTMLFormatter(BaseFormatter):
    """HTML output formatter"""

    def __init__(self):
        super().__init__("html")

    def format(self, scan_result: ScanResult) -> str:
        if not self.validate_scan_result(scan_result):
            raise ValueError("Invalid scan result")

        # Generate HTML report
        html = self._generate_html_template(scan_result)
        return html

    def _generate_html_template(self, scan_result: ScanResult) -> str:
        """Generate complete HTML report"""
        severity_summary = scan_result.severity_summary

        # Calculate risk score
        risk_score = (
            severity_summary.get('critical', 0) * 10 +
            severity_summary.get('high', 0) * 7 +
            severity_summary.get('medium', 0) * 4 +
            severity_summary.get('low', 0) * 2 +
            severity_summary.get('informational', 0) * 1
        )

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{scan_result.scanner_name} Vulnerability Scan Report</title>
    <style>
        {self._get_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>{scan_result.scanner_name} Vulnerability Scan Report</h1>
            <div class="scan-info">
                <div class="info-item">
                    <strong>Target:</strong> {scan_result.target.ip_address}
                </div>
                <div class="info-item">
                    <strong>Ports:</strong> {', '.join(map(str, scan_result.target.ports))}
                </div>
                <div class="info-item">
                    <strong>Scan ID:</strong> {scan_result.scan_id}
                </div>
                <div class="info-item">
                    <strong>Status:</strong> <span class="status-{scan_result.status.value}">{scan_result.status.value.title()}</span>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-number">{scan_result.vulnerability_count}</div>
                    <div class="summary-label">Total Vulnerabilities</div>
                </div>
                <div class="summary-card risk-score">
                    <div class="summary-number">{risk_score}</div>
                    <div class="summary-label">Risk Score</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{scan_result.duration or 0:.1f}s</div>
                    <div class="summary-label">Scan Duration</div>
                </div>
            </div>
        </div>

        <!-- Severity Breakdown -->
        <div class="section">
            <h2>Severity Breakdown</h2>
            <div class="severity-grid">
                <div class="severity-item critical">
                    <div class="severity-count">{severity_summary.get('critical', 0)}</div>
                    <div class="severity-label">Critical</div>
                </div>
                <div class="severity-item high">
                    <div class="severity-count">{severity_summary.get('high', 0)}</div>
                    <div class="severity-label">High</div>
                </div>
                <div class="severity-item medium">
                    <div class="severity-count">{severity_summary.get('medium', 0)}</div>
                    <div class="severity-label">Medium</div>
                </div>
                <div class="severity-item low">
                    <div class="severity-count">{severity_summary.get('low', 0)}</div>
                    <div class="severity-label">Low</div>
                </div>
                <div class="severity-item info">
                    <div class="severity-count">{severity_summary.get('informational', 0)}</div>
                    <div class="severity-label">Info</div>
                </div>
            </div>
        </div>

        <!-- Scan Details -->
        <div class="section">
            <h2>Scan Details</h2>
            <table class="details-table">
                <tr>
                    <td><strong>Start Time:</strong></td>
                    <td>{scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</td>
                </tr>
                <tr>
                    <td><strong>End Time:</strong></td>
                    <td>{scan_result.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if scan_result.end_time else 'N/A'}</td>
                </tr>
                <tr>
                    <td><strong>Duration:</strong></td>
                    <td>{scan_result.duration:.2f} seconds</td>
                </tr>
                <tr>
                    <td><strong>Scanner:</strong></td>
                    <td>{scan_result.scanner_name}</td>
                </tr>
            </table>
        </div>

        <!-- Vulnerabilities -->
        <div class="section">
            <h2>Vulnerabilities ({len(scan_result.vulnerabilities)})</h2>
            {self._generate_vulnerabilities_html(scan_result.vulnerabilities)}
        </div>

        {self._generate_error_section_html(scan_result.error_message) if scan_result.error_message else ''}

        <!-- Footer -->
        <div class="footer">
            <p>Report generated on {scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>Powered by Vulnerability Scanner API</p>
        </div>
    </div>
</body>
</html>
        """
        return html

    def _generate_vulnerabilities_html(self, vulnerabilities) -> str:
        """Generate HTML for vulnerabilities section"""
        if not vulnerabilities:
            return '<div class="no-vulns">No vulnerabilities found.</div>'

        html = '<div class="vulnerabilities">'

        for i, vuln in enumerate(vulnerabilities, 1):
            severity_class = vuln.severity.value.lower()

            html += f"""
            <div class="vulnerability {severity_class}">
                <div class="vuln-header">
                    <div class="vuln-title">
                        <span class="vuln-number">#{i}</span>
                        <span class="vuln-name">{self._escape_html(vuln.name)}</span>
                        <span class="severity-badge {severity_class}">{vuln.severity.value.title()}</span>
                    </div>
                    {f'<div class="cvss-score">CVSS: {vuln.cvss_score}</div>' if vuln.cvss_score > 0 else ''}
                </div>

                <div class="vuln-details">
                    {f'<div class="detail-item"><strong>URL:</strong> {self._escape_html(vuln.affected_url)}</div>' if vuln.affected_url else ''}
                    {f'<div class="detail-item"><strong>Parameter:</strong> {self._escape_html(vuln.affected_parameter)}</div>' if vuln.affected_parameter else ''}
                    {f'<div class="detail-item"><strong>CVE:</strong> {self._escape_html(vuln.cve_id)}</div>' if vuln.cve_id else ''}

                    <div class="detail-item">
                        <strong>Description:</strong>
                        <div class="description">{self._escape_html(vuln.description)}</div>
                    </div>

                    {f'<div class="detail-item"><strong>Solution:</strong><div class="solution">{self._escape_html(vuln.solution)}</div></div>' if vuln.solution else ''}
                    {f'<div class="detail-item"><strong>Reference:</strong> {self._escape_html(vuln.reference)}</div>' if vuln.reference else ''}
                    {f'<div class="detail-item"><strong>Evidence:</strong><div class="evidence">{self._escape_html(vuln.evidence)}</div></div>' if vuln.evidence else ''}
                </div>
            </div>
            """

        html += '</div>'
        return html

    def _generate_error_section_html(self, error_message: str) -> str:
        """Generate HTML for error section"""
        return f"""
        <div class="section error-section">
            <h2>Errors</h2>
            <div class="error-message">
                {self._escape_html(error_message)}
            </div>
        </div>
        """

    def _escape_html(self, text: str) -> str:
        """Escape HTML characters"""
        if not text:
            return ""

        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;"))

    def _get_css_styles(self) -> str:
        """Get CSS styles for HTML report"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
            text-align: center;
        }

        .scan-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .info-item {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
        }

        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .section h2 {
            background: #f8f9fa;
            padding: 20px 30px;
            margin: 0;
            border-bottom: 1px solid #dee2e6;
            font-size: 1.5em;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
        }

        .summary-card {
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
            border-radius: 10px;
            border: 2px solid #e9ecef;
        }

        .summary-card.risk-score {
            background: linear-gradient(45deg, #ff6b6b, #ee5a24);
            color: white;
        }

        .summary-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .summary-label {
            font-size: 1.1em;
            opacity: 0.8;
        }

        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            padding: 30px;
        }

        .severity-item {
            text-align: center;
            padding: 25px;
            border-radius: 10px;
            color: white;
        }

        .severity-item.critical { background: #d63031; }
        .severity-item.high { background: #e84142; }
        .severity-item.medium { background: #f39c12; }
        .severity-item.low { background: #00b894; }
        .severity-item.info { background: #74b9ff; }

        .severity-count {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .details-table {
            width: 100%;
            padding: 30px;
        }

        .details-table td {
            padding: 10px;
            border-bottom: 1px solid #eee;
        }

        .vulnerabilities {
            padding: 30px;
        }

        .vulnerability {
            margin-bottom: 25px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .vuln-header {
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .vulnerability.critical .vuln-header { background: #d63031; color: white; }
        .vulnerability.high .vuln-header { background: #e84142; color: white; }
        .vulnerability.medium .vuln-header { background: #f39c12; color: white; }
        .vulnerability.low .vuln-header { background: #00b894; color: white; }
        .vulnerability.informational .vuln-header { background: #74b9ff; color: white; }

        .vuln-title {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .vuln-number {
            background: rgba(255,255,255,0.2);
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
        }

        .vuln-name {
            font-size: 1.2em;
            font-weight: bold;
        }

        .severity-badge {
            padding: 5px 10px;
            border-radius: 5px;
            background: rgba(255,255,255,0.2);
            font-size: 0.9em;
        }

        .cvss-score {
            background: rgba(255,255,255,0.2);
            padding: 10px 15px;
            border-radius: 5px;
            font-weight: bold;
        }

        .vuln-details {
            padding: 25px;
            background: white;
        }

        .detail-item {
            margin-bottom: 15px;
        }

        .detail-item strong {
            color: #495057;
        }

        .description, .solution, .evidence {
            margin-top: 5px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }

        .no-vulns {
            padding: 30px;
            text-align: center;
            color: #28a745;
            font-size: 1.2em;
        }

        .error-section {
            border-left: 5px solid #dc3545;
        }

        .error-message {
            padding: 30px;
            background: #f8d7da;
            color: #721c24;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }

        .status-pending { color: #ffc107; }
        .status-running { color: #17a2b8; }
        .status-completed { color: #28a745; }
        .status-failed { color: #dc3545; }
        .status-stopped { color: #6c757d; }

        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header h1 { font-size: 2em; }
            .summary-grid, .severity-grid { grid-template-columns: 1fr; }
            .vuln-header { flex-direction: column; gap: 10px; }
        }

        @media print {
            body { background: white; }
            .section { box-shadow: none; border: 1px solid #ddd; }
            .header { background: #333 !important; }
        }
        """

    def get_content_type(self) -> str:
        return "text/html"

    def get_file_extension(self) -> str:
        return "html"