"""
OpenVAS API Flask application
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
from openvas_scanner import OpenVASScanner

# Setup Flask app
app = Flask(__name__)
CORS(app)

# Setup logging
logger = setup_logging("openvas_api")

# Initialize scanner
openvas_host = os.getenv('OPENVAS_HOST', 'localhost')
openvas_port = int(os.getenv('OPENVAS_PORT', 9390))
openvas_user = os.getenv('OPENVAS_USER', 'admin')
openvas_password = os.getenv('OPENVAS_PASSWORD', 'admin')
openvas_socket = os.getenv('OPENVAS_SOCKET_PATH', '/run/gvmd/gvmd.sock')

scanner = OpenVASScanner(
    host=openvas_host,
    port=openvas_port,
    username=openvas_user,
    password=openvas_password,
    socket_path=openvas_socket if os.path.exists(openvas_socket) else None
)

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
    openvas_available = scanner.is_openvas_available()
    openvas_version = scanner.get_openvas_version()

    return jsonify({
        'status': 'healthy' if openvas_available else 'degraded',
        'service': 'OpenVAS API',
        'openvas_available': openvas_available,
        'openvas_version': openvas_version,
        'openvas_host': openvas_host,
        'openvas_port': openvas_port,
        'socket_path': openvas_socket,
        'supported_formats': scanner.get_supported_formats()
    })


@app.route('/api/openvas/scan', methods=['POST'])
def create_scan():
    """Create new OpenVAS scan"""
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
                'config_id': scan_request.scan_options.get('config_id')
            },
            message="OpenVAS scan started successfully"
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
            error_code="OPENVAS_UNAVAILABLE"
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


@app.route('/api/openvas/scan/<scan_id>/status', methods=['GET'])
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


@app.route('/api/openvas/scan/<scan_id>/results', methods=['GET'])
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


@app.route('/api/openvas/scan/<scan_id>/download', methods=['GET'])
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


@app.route('/api/openvas/scan/<scan_id>', methods=['DELETE'])
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


@app.route('/api/openvas/scans', methods=['GET'])
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


@app.route('/api/openvas/configs', methods=['GET'])
def get_scan_configs():
    """Get available scan configurations"""
    try:
        configs = scanner.get_scan_configs()

        response = APIResponse(
            success=True,
            data={
                'configs': configs,
                'total_count': len(configs)
            }
        )

        return jsonify(response.to_dict())

    except Exception as e:
        logger.error(f"Error getting scan configs: {e}")
        response = APIResponse(
            success=False,
            message="Internal server error",
            error_code="INTERNAL_ERROR"
        )
        return jsonify(response.to_dict()), 500


@app.route('/api/openvas/info', methods=['GET'])
def get_scanner_info():
    """Get scanner information"""
    return jsonify({
        'scanner_name': 'OpenVAS',
        'version': scanner.get_openvas_version(),
        'host': openvas_host,
        'port': openvas_port,
        'socket_path': openvas_socket,
        'supported_formats': scanner.get_supported_formats(),
        'available': scanner.is_openvas_available()
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
    # Check if OpenVAS is available
    if not scanner.is_openvas_available():
        logger.warning("OpenVAS is not available. Check configuration and ensure OpenVAS is running.")

    # Get configuration from environment
    host = os.getenv('OPENVAS_API_HOST', '0.0.0.0')
    port = int(os.getenv('OPENVAS_API_PORT', 5004))
    debug = os.getenv('OPENVAS_API_DEBUG', 'False').lower() == 'true'

    logger.info(f"Starting OpenVAS API server on {host}:{port}")
    logger.info(f"OpenVAS connection: {openvas_host}:{openvas_port}")
    app.run(host=host, port=port, debug=debug)