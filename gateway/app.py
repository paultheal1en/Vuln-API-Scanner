"""
API Gateway for Vulnerability Scanners
Routes requests to appropriate scanner services
"""
import os
import logging
import requests
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Service endpoints
SERVICES = {
    'nikto': os.getenv('NIKTO_API_URL', 'http://nikto-api:5001'),
    'zap': os.getenv('ZAP_API_URL', 'http://zap-api:5002'),
    'tenable': os.getenv('TENABLE_API_URL', 'http://tenable-api:5003'),
    'openvas': os.getenv('OPENVAS_API_URL', 'http://openvas-api:5004')
}


@app.route('/health')
def health_check():
    """Gateway health check"""
    service_status = {}

    for service_name, service_url in SERVICES.items():
        try:
            response = requests.get(f"{service_url}/health", timeout=5)
            service_status[service_name] = {
                'status': 'healthy' if response.status_code == 200 else 'unhealthy',
                'url': service_url
            }
        except Exception as e:
            service_status[service_name] = {
                'status': 'unavailable',
                'error': str(e),
                'url': service_url
            }

    return jsonify({
        'service': 'Vulnerability Scanners API Gateway',
        'status': 'healthy',
        'services': service_status,
        'available_scanners': list(SERVICES.keys())
    })


@app.route('/api/<scanner>/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy_request(scanner, path):
    """Proxy requests to appropriate scanner service"""
    if scanner not in SERVICES:
        return jsonify({
            'success': False,
            'error_code': 'INVALID_SCANNER',
            'message': f'Scanner "{scanner}" not found',
            'available_scanners': list(SERVICES.keys())
        }), 404

    service_url = SERVICES[scanner]
    target_url = f"{service_url}/api/{scanner}/{path}"

    try:
        # Forward the request
        response = requests.request(
            method=request.method,
            url=target_url,
            headers={key: value for key, value in request.headers if key != 'Host'},
            data=request.get_data(),
            params=request.args,
            allow_redirects=False,
            timeout=30
        )

        # Forward the response
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in response.raw.headers.items()
                  if name.lower() not in excluded_headers]

        return Response(response.content, response.status_code, headers)

    except requests.exceptions.Timeout:
        return jsonify({
            'success': False,
            'error_code': 'SERVICE_TIMEOUT',
            'message': f'Service {scanner} timed out'
        }), 504

    except requests.exceptions.ConnectionError:
        return jsonify({
            'success': False,
            'error_code': 'SERVICE_UNAVAILABLE',
            'message': f'Service {scanner} is unavailable'
        }), 503

    except Exception as e:
        logger.error(f"Error proxying request to {scanner}: {e}")
        return jsonify({
            'success': False,
            'error_code': 'GATEWAY_ERROR',
            'message': 'Internal gateway error'
        }), 500


@app.route('/api/scan/multi', methods=['POST'])
def multi_scanner_scan():
    """Start scans on multiple scanners simultaneously"""
    try:
        data = request.get_json()
        scanners = data.get('scanners', list(SERVICES.keys()))
        scan_request = {
            'target_ip': data.get('target_ip'),
            'ports': data.get('ports'),
            'scan_options': data.get('scan_options', {})
        }

        results = {}

        for scanner in scanners:
            if scanner not in SERVICES:
                results[scanner] = {
                    'success': False,
                    'error': f'Scanner {scanner} not available'
                }
                continue

            try:
                service_url = SERVICES[scanner]
                response = requests.post(
                    f"{service_url}/api/{scanner}/scan",
                    json=scan_request,
                    timeout=30
                )

                if response.status_code == 201:
                    results[scanner] = {
                        'success': True,
                        'data': response.json().get('data', {})
                    }
                else:
                    results[scanner] = {
                        'success': False,
                        'error': response.json().get('message', 'Unknown error')
                    }

            except Exception as e:
                results[scanner] = {
                    'success': False,
                    'error': str(e)
                }

        return jsonify({
            'success': True,
            'data': {
                'multi_scan_id': f"multi-{data.get('target_ip', 'unknown')}",
                'scanners': results,
                'target_ip': data.get('target_ip'),
                'ports': data.get('ports')
            }
        }), 201

    except Exception as e:
        logger.error(f"Multi-scan error: {e}")
        return jsonify({
            'success': False,
            'error_code': 'MULTI_SCAN_ERROR',
            'message': str(e)
        }), 500


@app.route('/api/scan/status/multi/<multi_scan_id>')
def multi_scanner_status(multi_scan_id):
    """Get status from multiple scanners"""
    try:
        # Extract target IP from multi_scan_id (simplified)
        target_parts = multi_scan_id.split('-')
        if len(target_parts) < 2:
            return jsonify({
                'success': False,
                'error_code': 'INVALID_MULTI_SCAN_ID',
                'message': 'Invalid multi-scan ID format'
            }), 400

        results = {}

        for scanner in SERVICES.keys():
            try:
                service_url = SERVICES[scanner]
                # This would need actual scan IDs - simplified for demo
                response = requests.get(
                    f"{service_url}/api/{scanner}/scan/active",
                    timeout=10
                )

                if response.status_code == 200:
                    results[scanner] = {
                        'success': True,
                        'data': response.json().get('data', {})
                    }
                else:
                    results[scanner] = {
                        'success': False,
                        'error': 'No active scans or service error'
                    }

            except Exception as e:
                results[scanner] = {
                    'success': False,
                    'error': str(e)
                }

        return jsonify({
            'success': True,
            'data': {
                'multi_scan_id': multi_scan_id,
                'scanners': results
            }
        })

    except Exception as e:
        logger.error(f"Multi-status error: {e}")
        return jsonify({
            'success': False,
            'error_code': 'MULTI_STATUS_ERROR',
            'message': str(e)
        }), 500


if __name__ == '__main__':
    host = os.getenv('GATEWAY_HOST', '0.0.0.0')
    port = int(os.getenv('GATEWAY_PORT', 5000))
    debug = os.getenv('GATEWAY_DEBUG', 'false').lower() == 'true'

    logger.info(f"Starting API Gateway on {host}:{port}")
    logger.info(f"Service endpoints: {SERVICES}")

    app.run(host=host, port=port, debug=debug)