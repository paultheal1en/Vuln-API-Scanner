# Nikto API

RESTful API wrapper cho Nikto web vulnerability scanner.

## Cài đặt

```bash
# Cài đặt Nikto
sudo apt-get install nikto

# Cài đặt Python dependencies
pip install -r ../requirements.txt
```

## Chạy API

```bash
python app.py
```

API sẽ chạy trên port 5001 mặc định.

## API Endpoints

### Health Check
```
GET /health
```

### Tạo Scan Mới
```
POST /api/nikto/scan
Content-Type: application/json

{
  "target_ip": "192.168.1.100",
  "ports": [80, 443, 8080],
  "scan_options": {
    "timeout": 300,
    "pause": 1,
    "ssl": true,
    "plugins": "@@ALL",
    "useragent": "Custom User Agent",
    "auth": {
      "basic": {
        "username": "admin",
        "password": "password"
      }
    }
  }
}
```

### Kiểm tra Status
```
GET /api/nikto/scan/{scan_id}/status
```

### Lấy Kết quả
```
GET /api/nikto/scan/{scan_id}/results?format=json
GET /api/nikto/scan/{scan_id}/results?format=xml
GET /api/nikto/scan/{scan_id}/results?format=csv
GET /api/nikto/scan/{scan_id}/results?format=txt
```

### Download File
```
GET /api/nikto/scan/{scan_id}/download?format=json
```

### Dừng Scan
```
DELETE /api/nikto/scan/{scan_id}
```

### List Scans
```
GET /api/nikto/scans
```

### Scanner Info
```
GET /api/nikto/info
```

## Response Format

### Success Response
```json
{
  "success": true,
  "data": {
    "scan_id": "uuid",
    "target_ip": "192.168.1.100",
    "ports": [80, 443],
    "status": "started"
  },
  "message": "Scan started successfully"
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error description",
  "error_code": "ERROR_CODE"
}
```

## Scan Options

| Option | Type | Description |
|--------|------|-------------|
| timeout | int | Scan timeout in seconds (default: 300) |
| pause | int | Pause between requests in seconds |
| ssl | bool | Force SSL mode |
| plugins | string | Nikto plugins to use (default: @@ALL) |
| useragent | string | Custom User-Agent string |
| auth.basic | object | Basic authentication credentials |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| NIKTO_API_HOST | 0.0.0.0 | API host |
| NIKTO_API_PORT | 5001 | API port |
| NIKTO_API_DEBUG | False | Debug mode |

## Usage Examples

### Curl Examples

```bash
# Tạo scan
curl -X POST http://localhost:5001/api/nikto/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "192.168.1.100",
    "ports": [80, 443],
    "scan_options": {
      "timeout": 180,
      "pause": 1
    }
  }'

# Kiểm tra status
curl http://localhost:5001/api/nikto/scan/{scan_id}/status

# Lấy kết quả JSON
curl http://localhost:5001/api/nikto/scan/{scan_id}/results?format=json

# Download CSV
curl http://localhost:5001/api/nikto/scan/{scan_id}/download?format=csv -o results.csv
```

### Python Examples

```python
import requests

# Tạo scan
response = requests.post('http://localhost:5001/api/nikto/scan', json={
    "target_ip": "example.com",
    "ports": [80, 443],
    "scan_options": {
        "timeout": 300,
        "ssl": True
    }
})

scan_data = response.json()
scan_id = scan_data['data']['scan_id']

# Kiểm tra status
status_response = requests.get(f'http://localhost:5001/api/nikto/scan/{scan_id}/status')
print(status_response.json())

# Lấy kết quả
results_response = requests.get(f'http://localhost:5001/api/nikto/scan/{scan_id}/results')
print(results_response.json())
```