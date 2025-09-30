"""
OWASP ZAP API Flask application
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
    CSVFormatter, TXTFormatter, setup_logging
)
from zap_scanner import ZAPScanner

# Setup Flask app
app = Flask(__name__)
CORS(app)

# Setup logging
logger = setup_logging("zap_api")

# Initialize scanner
zap_proxy_url = os.getenv('ZAP_PROXY_URL', 'http://127.0.0.1:8080')
zap_api_key = os.getenv('ZAP_API_KEY', None)
scanner = ZAPScanner(proxy_url=zap_proxy_url, api_key=zap_api_key)

# Initialize formatters
formatters = {
    'json': JSONFormatter(),
    'xml': XMLFormatter(),
    'csv': CSVFormatter(),
    'txt': TXTFormatter()
}


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    zap_available = scanner.is_zap_available()
    zap_version = scanner.get_zap_version()

    return jsonify({
        'status': 'healthy' if zap_available else 'degraded',
        'service': 'OWASP ZAP API',
        'zap_available': zap_available,
        'zap_version': zap_version,
        'zap_proxy_url': zap_proxy_url,
        'supported_formats': scanner.get_supported_formats()
    })


@app.route('/api/zap/scan', methods=['POST'])
def create_scan():
    """Create new ZAP scan"""
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
                'scan_type': scan_request.scan_options.get('scan_type', 'full')
            },
            message="ZAP scan started successfully"
        )

        return jsonify(response.to_dict()), 201

    except ValueError as e:
        response = APIResponse(
            success=False,
            message=str(e),
            error_code="VALIDATION_ERROR"
        )
        return jsonify(response.to_dict()), 400

    except RuntimeError as e:
        response = APIResponse(
            success=False,
            message=str(e),
            error_code="ZAP_UNAVAILABLE"
        )
        return jsonify(response.to_dict()), 503

    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/zap/scan/spider', methods=['POST'])
def create_spider_scan():
    """Create spider-only scan"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(APIResponse(
                success=False,
                message="Request body is required",
                error_code="INVALID_REQUEST"
            ).to_dict()), 400

        # Set scan type to spider
        data['scan_options'] = data.get('scan_options', {})
        data['scan_options']['scan_type'] = 'spider'

        scan_request = ScanRequest.from_dict(data)
        target = scan_request.to_scan_target()

        scan_id = scanner.scan(target, scan_request.scan_options)

        response = APIResponse(
            success=True,
            data={
                'scan_id': scan_id,
                'target_ip': target.ip_address,
                'ports': target.ports,
                'status': 'started',
                'scan_type': 'spider'
            },
            message="ZAP spider scan started successfully"
        )

        return jsonify(response.to_dict()), 201

    except Exception as e:
        logger.error(f"Error creating spider scan: {e}")
        response = APIResponse(
            success=False,
            message=str(e),
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/zap/scan/active', methods=['POST'])
def create_active_scan():
    """Create active-only scan"""
    try:
        data = request.get_json()
        if not data:
            return jsonify(APIResponse(
                success=False,
                message="Request body is required",
                error_code="INVALID_REQUEST"
            ).to_dict()), 400

        # Set scan type to active
        data['scan_options'] = data.get('scan_options', {})
        data['scan_options']['scan_type'] = 'active'

        scan_request = ScanRequest.from_dict(data)
        target = scan_request.to_scan_target()

        scan_id = scanner.scan(target, scan_request.scan_options)

        response = APIResponse(
            success=True,
            data={
                'scan_id': scan_id,
                'target_ip': target.ip_address,
                'ports': target.ports,
                'status': 'started',
                'scan_type': 'active'
            },
            message="ZAP active scan started successfully"
        )

        return jsonify(response.to_dict()), 201

    except Exception as e:
        logger.error(f"Error creating active scan: {e}")
        response = APIResponse(
            success=False,
            message=str(e),
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/zap/scan/<scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status"""
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


@app.route('/api/zap/scan/<scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get scan results in specified format"""
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


@app.route('/api/zap/scan/<scan_id>/spider-results', methods=['GET'])
def get_spider_results(scan_id):
    """Get spider scan results (discovered URLs)"""
    try:
        urls = scanner.get_spider_results(scan_id)

        response = APIResponse(
            success=True,
            data={
                'scan_id': scan_id,
                'discovered_urls': urls,
                'total_urls': len(urls)
            }
        )

        return jsonify(response.to_dict())

    except Exception as e:
        logger.error(f"Error getting spider results: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/zap/scan/<scan_id>/download', methods=['GET'])
def download_results(scan_id):
    """Download scan results as file"""
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


@app.route('/api/zap/scan/<scan_id>', methods=['DELETE'])
def stop_scan(scan_id):
    """Stop running scan"""
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


@app.route('/api/zap/scans', methods=['GET'])
def list_scans():
    """List all scans"""
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


@app.route('/api/zap/session/new', methods=['POST'])
def create_session():
    """Create new ZAP session"""
    try:
        data = request.get_json() or {}
        session_name = data.get('session_name')

        success = scanner.create_new_session(session_name)

        if success:
            response = APIResponse(
                success=True,
                message="New ZAP session created successfully"
            )
            return jsonify(response.to_dict())
        else:
            response = APIResponse(
                success=False,
                message="Failed to create ZAP session",
                error_code="SESSION_CREATE_FAILED"
            )
            return jsonify(response.to_dict()), 500

    except Exception as e:
        logger.error(f"Error creating session: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/zap/info', methods=['GET'])
def get_scanner_info():
    """Get scanner information"""
    return jsonify({
        'scanner_name': 'OWASP ZAP',
        'version': scanner.get_zap_version(),
        'proxy_url': zap_proxy_url,
        'supported_formats': scanner.get_supported_formats(),
        'available': scanner.is_zap_available()
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
    # Check if ZAP is available
    if not scanner.is_zap_available():
        logger.warning("ZAP is not available. Make sure ZAP is running and accessible.")

    # Get configuration from environment
    host = os.getenv('ZAP_API_HOST', '0.0.0.0')
    port = int(os.getenv('ZAP_API_PORT', 5002))
    debug = os.getenv('ZAP_API_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting ZAP API server on {host}:{port}")
    logger.info(f"ZAP Proxy URL: {zap_proxy_url}")
    app.run(host=host, port=port, debug=debug)