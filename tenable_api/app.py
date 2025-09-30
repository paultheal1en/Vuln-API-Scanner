"""
Tenable Nessus API Flask application
"""
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import os
import sys
import io

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common import (
    ScanRequest, APIResponse, JSONFormatter, XMLFormatter,
    CSVFormatter, TXTFormatter, HTMLFormatter, setup_logging
)
from tenable_scanner import TenableScanner

# Setup Flask app
app = Flask(__name__)
CORS(app)

# Setup logging
logger = setup_logging("tenable_api")

# Initialize scanner
tenable_url = os.getenv('TENABLE_URL', 'https://localhost:8834')
tenable_access_key = os.getenv('TENABLE_ACCESS_KEY')
tenable_secret_key = os.getenv('TENABLE_SECRET_KEY')

if not tenable_access_key or not tenable_secret_key:
    logger.warning("Tenable credentials not configured. Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY environment variables.")
    scanner = None
else:
    scanner = TenableScanner(tenable_url, tenable_access_key, tenable_secret_key)

# Initialize formatters
formatters = {
    'json': JSONFormatter(),
    'xml': XMLFormatter(),
    'csv': CSVFormatter(),
    'txt': TXTFormatter(),
    'html': HTMLFormatter()
}


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    tenable_available = scanner.is_tenable_available() if scanner else False
    tenable_version = scanner.get_tenable_version() if scanner else "N/A"

    return jsonify({
        'status': 'healthy' if tenable_available else 'degraded',
        'service': 'Tenable Nessus API',
        'tenable_available': tenable_available,
        'tenable_version': tenable_version,
        'tenable_url': tenable_url,
        'credentials_configured': bool(tenable_access_key and tenable_secret_key),
        'supported_formats': scanner.get_supported_formats() if scanner else []
    })


@app.route('/api/tenable/scan', methods=['POST'])
def create_scan():
    """Create new Tenable scan"""
    if not scanner:
        response = APIResponse(
            success=False,
            message="Tenable credentials not configured",
            error_code="CREDENTIALS_MISSING"
        )
        return jsonify(response.to_dict()), 503

    try:
        # Parse request
        data = request.get_json()
        if not data:
            return jsonify(APIResponse(
                success=False,
                message="Request body is required",
                error_code="INVALID_REQUEST"
            ).to_dict()), 400

        # Validate request
        scan_request = ScanRequest.from_dict(data)
        target = scan_request.to_scan_target()

        # Start scan
        scan_id = scanner.scan(target, scan_request.scan_options)

        response = APIResponse(
            success=True,
            data={
                'scan_id': scan_id,
                'target_ip': target.ip_address,
                'ports': target.ports,
                'status': 'started',
                'policy_id': scan_request.scan_options.get('policy_id')
            },
            message="Tenable scan started successfully"
        )

        return jsonify(response.to_dict()), 201

    except ValueError as e:
        response = APIResponse(
            success=False,
            message=str(e),
            error_code="VALIDATION_ERROR"
        )
        return jsonify(response.to_dict()), 400

    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/tenable/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
    if not scanner:
        return jsonify(APIResponse(
            success=False,
            message="Tenable not configured",
            error_code="SERVICE_UNAVAILABLE"
        ).to_dict()), 503

    try:
        scan_result = scanner.get_scan_result(scan_id)

        if not scan_result:
            response = APIResponse(
                success=False,
                message="Scan not found",
                error_code="SCAN_NOT_FOUND"
            )
            return jsonify(response.to_dict()), 404

        # Get detailed progress
        progress = scanner.get_scan_progress(scan_id)

        response = APIResponse(
            success=True,
            data={
                'scan_id': scan_id,
                'status': scan_result.status.value,
                'target_ip': scan_result.target.ip_address,
                'ports': scan_result.target.ports,
                'start_time': scan_result.start_time.isoformat(),
                'end_time': scan_result.end_time.isoformat() if scan_result.end_time else None,
                'duration': scan_result.duration,
                'vulnerability_count': scan_result.vulnerability_count,
                'severity_summary': scan_result.severity_summary,
                'progress': progress
            }
        )

        return jsonify(response.to_dict())

    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/tenable/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results in specified format"""
    if not scanner:
        return jsonify(APIResponse(
            success=False,
            message="Tenable not configured",
            error_code="SERVICE_UNAVAILABLE"
        ).to_dict()), 503

    try:
        # Get format parameter
        format_type = request.args.get('format', 'json').lower()

        if format_type not in formatters:
            response = APIResponse(
                success=False,
                message=f"Unsupported format: {format_type}",
                error_code="UNSUPPORTED_FORMAT"
            )
            return jsonify(response.to_dict()), 400

        # Get scan result
        scan_result = scanner.get_scan_result(scan_id)

        if not scan_result:
            response = APIResponse(
                success=False,
                message="Scan not found",
                error_code="SCAN_NOT_FOUND"
            )
            return jsonify(response.to_dict()), 404

        # Format output
        formatter = formatters[format_type]
        formatted_output = formatter.format(scan_result)

        # Return appropriate response
        if format_type == 'json':
            return Response(
                formatted_output,
                mimetype=formatter.get_content_type()
            )
        else:
            return Response(
                formatted_output,
                mimetype=formatter.get_content_type(),
                headers={
                    'Content-Disposition': f'attachment; filename="{formatter.get_filename(scan_result)}"'
                }
            )

    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/tenable/scan/<scan_id>/export', methods=['GET'])
def export_scan_results(scan_id):
    """Export scan results in Tenable native format"""
    if not scanner:
        return jsonify({'error': 'Tenable not configured'}), 503

    try:
        # Get format parameter
        format_type = request.args.get('format', 'nessus')
        valid_formats = ['nessus', 'pdf', 'html', 'csv', 'db']

        if format_type not in valid_formats:
            return jsonify({
                'error': f'Unsupported export format: {format_type}',
                'supported_formats': valid_formats
            }), 400

        # Get scan result to check if exists
        scan_result = scanner.get_scan_result(scan_id)
        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404

        # Export results
        exported_data = scanner.export_scan_results(scan_id, format_type)

        if not exported_data:
            return jsonify({'error': 'Failed to export scan results'}), 500

        # Determine content type
        content_types = {
            'nessus': 'application/xml',
            'pdf': 'application/pdf',
            'html': 'text/html',
            'csv': 'text/csv',
            'db': 'application/octet-stream'
        }

        content_type = content_types.get(format_type, 'application/octet-stream')
        filename = f"tenable_scan_{scan_id[:8]}.{format_type}"

        # Create file-like object
        file_obj = io.BytesIO(exported_data)

        return send_file(
            file_obj,
            as_attachment=True,
            download_name=filename,
            mimetype=content_type
        )

    except Exception as e:
        logger.error(f"Error exporting scan results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/tenable/scan/<scan_id>/download', methods=['GET'])
def download_results(scan_id):
    """Download scan results as file"""
    if not scanner:
        return jsonify({'error': 'Tenable not configured'}), 503

    try:
        # Get format parameter
        format_type = request.args.get('format', 'json').lower()

        if format_type not in formatters:
            return jsonify({
                'error': f'Unsupported format: {format_type}',
                'supported_formats': list(formatters.keys())
            }), 400

        # Get scan result
        scan_result = scanner.get_scan_result(scan_id)

        if not scan_result:
            return jsonify({'error': 'Scan not found'}), 404

        # Format output
        formatter = formatters[format_type]
        formatted_output = formatter.format(scan_result)
        filename = formatter.get_filename(scan_result)

        # Create file-like object
        file_obj = io.BytesIO(formatted_output.encode('utf-8'))

        return send_file(
            file_obj,
            as_attachment=True,
            download_name=filename,
            mimetype=formatter.get_content_type()
        )

    except Exception as e:
        logger.error(f"Error downloading results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/tenable/scan/<scan_id>', methods=['DELETE'])
def stop_scan(scan_id):
    """Stop running scan"""
    if not scanner:
        return jsonify(APIResponse(
            success=False,
            message="Tenable not configured",
            error_code="SERVICE_UNAVAILABLE"
        ).to_dict()), 503

    try:
        success = scanner.stop_scan(scan_id)

        if success:
            response = APIResponse(
                success=True,
                message="Scan stopped successfully"
            )
            return jsonify(response.to_dict())
        else:
            response = APIResponse(
                success=False,
                message="Failed to stop scan or scan not found",
                error_code="STOP_FAILED"
            )
            return jsonify(response.to_dict()), 400

    except Exception as e:
        logger.error(f"Error stopping scan: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/tenable/scans', methods=['GET'])
def list_scans():
    """List all scans"""
    if not scanner:
        return jsonify(APIResponse(
            success=False,
            message="Tenable not configured",
            error_code="SERVICE_UNAVAILABLE"
        ).to_dict()), 503

    try:
        scans = scanner.list_scans()

        response = APIResponse(
            success=True,
            data={
                'scans': scans,
                'total_count': len(scans)
            }
        )

        return jsonify(response.to_dict())

    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/tenable/policies', methods=['GET'])
def get_scan_policies():
    """Get available scan policies"""
    if not scanner:
        return jsonify(APIResponse(
            success=False,
            message="Tenable not configured",
            error_code="SERVICE_UNAVAILABLE"
        ).to_dict()), 503

    try:
        policies = scanner._get_scan_policies()

        response = APIResponse(
            success=True,
            data={
                'policies': policies,
                'total_count': len(policies)
            }
        )

        return jsonify(response.to_dict())

    except Exception as e:
        logger.error(f"Error getting policies: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/tenable/info', methods=['GET'])
def get_scanner_info():
    """Get scanner information"""
    return jsonify({
        'scanner_name': 'Tenable Nessus',
        'version': scanner.get_tenable_version() if scanner else "N/A",
        'url': tenable_url,
        'supported_formats': scanner.get_supported_formats() if scanner else [],
        'available': scanner.is_tenable_available() if scanner else False,
        'credentials_configured': bool(tenable_access_key and tenable_secret_key)
    })


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'message': 'Endpoint not found',
        'error_code': 'NOT_FOUND'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'success': False,
        'message': 'Internal server error',
        'error_code': 'INTERNAL_ERROR'
    }), 500


if __name__ == '__main__':
    # Check if Tenable is available
    if scanner and not scanner.is_tenable_available():
        logger.warning("Tenable is not available. Check configuration and network connectivity.")

    # Get configuration from environment
    host = os.getenv('TENABLE_API_HOST', '0.0.0.0')
    port = int(os.getenv('TENABLE_API_PORT', 5003))
    debug = os.getenv('TENABLE_API_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting Tenable API server on {host}:{port}")
    logger.info(f"Tenable URL: {tenable_url}")
    app.run(host=host, port=port, debug=debug)