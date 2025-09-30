# API Usage Examples

## Table of Contents
- [Nikto API Examples](#nikto-api-examples)
- [OWASP ZAP API Examples](#owasp-zap-api-examples)
- [Tenable API Examples](#tenable-api-examples)
- [OpenVAS API Examples](#openvas-api-examples)
- [Common Response Formats](#common-response-formats)

## Nikto API Examples

### Basic Web Vulnerability Scan

```bash
# Start a basic scan
curl -X POST http://localhost:5001/api/nikto/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "example.com",
    "ports": [80, 443, 8080],
    "scan_options": {
      "timeout": 300,
      "pause": 1,
      "ssl": true
    }
  }'

# Response
{
  "success": true,
  "data": {
    "scan_id": "12345678-1234-1234-1234-123456789012",
    "target_ip": "example.com",
    "ports": [80, 443, 8080],
    "status": "started"
  },
  "message": "Nikto scan started successfully"
}
```

### Advanced Scan with Authentication

```bash
curl -X POST http://localhost:5001/api/nikto/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "192.168.1.100",
    "ports": [80, 443],
    "scan_options": {
      "timeout": 600,
      "pause": 2,
      "ssl": true,
      "plugins": "@@ALL",
      "useragent": "Custom Scanner Bot",
      "auth": {
        "basic": {
          "username": "admin",
          "password": "password123"
        }
      }
    }
  }'
```

### Check Scan Status

```bash
curl http://localhost:5001/api/nikto/scan/12345678-1234-1234-1234-123456789012/status

# Response
{
  "success": true,
  "data": {
    "scan_id": "12345678-1234-1234-1234-123456789012",
    "status": "completed",
    "target_ip": "example.com",
    "ports": [80, 443, 8080],
    "start_time": "2025-01-01T12:00:00.000000",
    "end_time": "2025-01-01T12:05:30.000000",
    "duration": 330.0,
    "vulnerability_count": 5,
    "severity_summary": {
      "critical": 0,
      "high": 1,
      "medium": 2,
      "low": 2,
      "informational": 0
    }
  }
}
```

### Get Results in Different Formats

```bash
# JSON format (default)
curl http://localhost:5001/api/nikto/scan/12345678-1234-1234-1234-123456789012/results

# HTML report
curl http://localhost:5001/api/nikto/scan/12345678-1234-1234-1234-123456789012/results?format=html

# CSV for analysis
curl http://localhost:5001/api/nikto/scan/12345678-1234-1234-1234-123456789012/results?format=csv

# Download as file
curl http://localhost:5001/api/nikto/scan/12345678-1234-1234-1234-123456789012/download?format=html \
  -o nikto_report.html
```

## OWASP ZAP API Examples

### Spider Scan (Discovery Only)

```bash
curl -X POST http://localhost:5002/api/zap/scan/spider \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "example.com",
    "ports": [80, 443],
    "scan_options": {
      "spider": {
        "max_depth": 3,
        "max_children": 10
      }
    }
  }'
```

### Active Security Scan

```bash
curl -X POST http://localhost:5002/api/zap/scan/active \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "testphp.vulnweb.com",
    "ports": [80],
    "scan_options": {
      "active_scan": {
        "policy_name": "Default Policy"
      }
    }
  }'
```

### Full Scan (Spider + Active)

```bash
curl -X POST http://localhost:5002/api/zap/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "192.168.1.100",
    "ports": [80, 443, 8080],
    "scan_options": {
      "scan_type": "full",
      "spider": {
        "max_depth": 5,
        "max_children": 20
      },
      "active_scan": {
        "policy_name": "Default Policy"
      }
    }
  }'
```

### Get Spider Results (Discovered URLs)

```bash
curl http://localhost:5002/api/zap/scan/12345678-1234-1234-1234-123456789012/spider-results

# Response
{
  "success": true,
  "data": {
    "scan_id": "12345678-1234-1234-1234-123456789012",
    "discovered_urls": [
      "http://example.com/",
      "http://example.com/about",
      "http://example.com/contact",
      "http://example.com/login"
    ],
    "total_urls": 4
  }
}
```

## Tenable API Examples

### Basic Vulnerability Assessment

```bash
curl -X POST http://localhost:5003/api/tenable/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "192.168.1.100",
    "ports": [22, 80, 443, 3389],
    "scan_options": {
      "policy_id": "basic-network-scan-policy-id",
      "scan_timeout": 3600,
      "max_hosts": 10
    }
  }'
```

### Get Available Scan Policies

```bash
curl http://localhost:5003/api/tenable/policies

# Response
{
  "success": true,
  "data": {
    "policies": [
      {
        "id": "policy-1",
        "name": "Basic Network Scan",
        "description": "Basic network scan policy"
      },
      {
        "id": "policy-2",
        "name": "Web Application Tests",
        "description": "Comprehensive web application security tests"
      }
    ],
    "total_count": 2
  }
}
```

### Export Results in Tenable Format

```bash
# Export as Nessus file
curl http://localhost:5003/api/tenable/scan/12345678-1234-1234-1234-123456789012/export?format=nessus \
  -o scan_results.nessus

# Export as PDF report
curl http://localhost:5003/api/tenable/scan/12345678-1234-1234-1234-123456789012/export?format=pdf \
  -o scan_report.pdf
```

## OpenVAS API Examples

### Comprehensive Network Scan

```bash
curl -X POST http://localhost:5004/api/openvas/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "192.168.1.0/24",
    "ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
    "scan_options": {
      "config_id": "full-and-fast-config-id"
    }
  }'
```

### Get Available Scan Configurations

```bash
curl http://localhost:5004/api/openvas/configs

# Response
{
  "success": true,
  "data": {
    "configs": [
      {
        "id": "config-1",
        "name": "Full and fast",
        "comment": "Full and fast scan configuration"
      },
      {
        "id": "config-2",
        "name": "System Discovery",
        "comment": "Network discovery scan"
      }
    ],
    "total_count": 2
  }
}
```

## Common Response Formats

### Successful Scan Result (JSON)

```json
{
  "scan_id": "12345678-1234-1234-1234-123456789012",
  "scanner_name": "Nikto",
  "target": {
    "ip_address": "example.com",
    "ports": [80, 443],
    "protocol": "tcp"
  },
  "status": "completed",
  "start_time": "2025-01-01T12:00:00.000000",
  "end_time": "2025-01-01T12:05:30.000000",
  "duration": 330.0,
  "vulnerability_count": 3,
  "severity_summary": {
    "critical": 0,
    "high": 1,
    "medium": 1,
    "low": 1,
    "informational": 0
  },
  "vulnerabilities": [
    {
      "id": "12345",
      "name": "Outdated Server Version",
      "severity": "medium",
      "description": "Server version disclosure may aid attackers",
      "solution": "Update server software to latest version",
      "reference": "https://example.com/security-advisory",
      "cve_id": "CVE-2023-12345",
      "cvss_score": 5.3,
      "affected_url": "http://example.com",
      "affected_parameter": "",
      "evidence": "Server: Apache/2.2.15"
    }
  ],
  "scan_options": {
    "timeout": 300
  },
  "error_message": ""
}
```

### Error Response

```json
{
  "success": false,
  "message": "Target IP is required",
  "error_code": "VALIDATION_ERROR"
}
```

## Python Examples

### Using requests library

```python
import requests
import time
import json

# Start a scan
def start_nikto_scan(target_ip, ports):
    url = "http://localhost:5001/api/nikto/scan"
    payload = {
        "target_ip": target_ip,
        "ports": ports,
        "scan_options": {
            "timeout": 300,
            "ssl": True
        }
    }

    response = requests.post(url, json=payload)
    if response.status_code == 201:
        return response.json()['data']['scan_id']
    else:
        raise Exception(f"Failed to start scan: {response.text}")

# Wait for scan completion
def wait_for_scan_completion(scan_id, api_url):
    while True:
        status_url = f"{api_url}/api/nikto/scan/{scan_id}/status"
        response = requests.get(status_url)

        if response.status_code == 200:
            status = response.json()['data']['status']
            print(f"Scan status: {status}")

            if status in ['completed', 'failed', 'stopped']:
                break

        time.sleep(10)

# Get results
def get_scan_results(scan_id, api_url, format='json'):
    results_url = f"{api_url}/api/nikto/scan/{scan_id}/results"
    if format != 'json':
        results_url += f"?format={format}"

    response = requests.get(results_url)
    if response.status_code == 200:
        if format == 'json':
            return response.json()
        else:
            return response.text
    else:
        raise Exception(f"Failed to get results: {response.text}")

# Example usage
if __name__ == "__main__":
    # Start scan
    scan_id = start_nikto_scan("example.com", [80, 443])
    print(f"Started scan: {scan_id}")

    # Wait for completion
    wait_for_scan_completion(scan_id, "http://localhost:5001")

    # Get results
    results = get_scan_results(scan_id, "http://localhost:5001")
    print(json.dumps(results, indent=2))
```

### Async scan management

```python
import asyncio
import aiohttp
import json

async def scan_multiple_targets(targets):
    """Scan multiple targets concurrently"""
    async with aiohttp.ClientSession() as session:
        tasks = []

        # Start all scans
        for target in targets:
            task = asyncio.create_task(
                start_and_wait_scan(session, target['ip'], target['ports'])
            )
            tasks.append(task)

        # Wait for all scans to complete
        results = await asyncio.gather(*tasks)
        return results

async def start_and_wait_scan(session, target_ip, ports):
    """Start scan and wait for completion"""
    # Start scan
    payload = {
        "target_ip": target_ip,
        "ports": ports,
        "scan_options": {"timeout": 300}
    }

    async with session.post(
        "http://localhost:5001/api/nikto/scan",
        json=payload
    ) as response:
        if response.status != 201:
            return {"error": "Failed to start scan"}

        data = await response.json()
        scan_id = data['data']['scan_id']

    # Wait for completion
    while True:
        async with session.get(
            f"http://localhost:5001/api/nikto/scan/{scan_id}/status"
        ) as response:
            if response.status == 200:
                data = await response.json()
                status = data['data']['status']

                if status == 'completed':
                    # Get results
                    async with session.get(
                        f"http://localhost:5001/api/nikto/scan/{scan_id}/results"
                    ) as results_response:
                        return await results_response.json()
                elif status == 'failed':
                    return {"error": "Scan failed"}

        await asyncio.sleep(10)

# Usage
targets = [
    {"ip": "example.com", "ports": [80, 443]},
    {"ip": "test.com", "ports": [80, 8080]},
    {"ip": "demo.com", "ports": [443]}
]

results = asyncio.run(scan_multiple_targets(targets))
print(json.dumps(results, indent=2))
```

## Testing and Validation

### Health Check All Services

```bash
#!/bin/bash
# health_check.sh

services=(
    "http://localhost:5001/health|Nikto"
    "http://localhost:5002/health|ZAP"
    "http://localhost:5003/health|Tenable"
    "http://localhost:5004/health|OpenVAS"
)

for service in "${services[@]}"; do
    IFS='|' read -r url name <<< "$service"

    echo "Checking $name..."
    response=$(curl -s "$url")
    status=$(echo "$response" | jq -r '.status // "unknown"')

    if [ "$status" = "healthy" ]; then
        echo "✅ $name is healthy"
    else
        echo "❌ $name is not healthy: $status"
    fi
    echo
done
```

### Scan Test Script

```bash
#!/bin/bash
# test_scans.sh

echo "Testing vulnerability scanners..."

# Test Nikto
echo "Testing Nikto..."
scan_id=$(curl -s -X POST http://localhost:5001/api/nikto/scan \
  -H "Content-Type: application/json" \
  -d '{"target_ip": "httpbin.org", "ports": [80], "scan_options": {"timeout": 60}}' | \
  jq -r '.data.scan_id')

if [ "$scan_id" != "null" ]; then
    echo "✅ Nikto scan started: $scan_id"
else
    echo "❌ Nikto scan failed"
fi
```