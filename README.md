# Vulnerability Scanners API

Unified API wrapper cho các công cụ quét lỗ hổng bảo mật phổ biến: Nikto, OWASP ZAP, Tenable Nessus, và OpenVAS.

## 🚀 Quick Start

### Cài đặt nhanh với Docker

```bash
# Clone repository
git clone <repository-url>
cd vulnerability-scanners-api

# Khởi tạo môi trường
make init

# Chỉnh sửa file .env với credentials của bạn
nano .env

# Quick start với Nikto và ZAP
make quick-start

# Hoặc start tất cả services
make up
```

### Kiểm tra health

```bash
make health
```

## 📋 API Endpoints

| Service | Port | Endpoint | Description |
|---------|------|----------|-------------|
| Nikto API | 5001 | http://localhost:5001 | Web vulnerability scanner |
| ZAP API | 5002 | http://localhost:5002 | OWASP ZAP security testing |
| Tenable API | 5003 | http://localhost:5003 | Professional vulnerability management |
| OpenVAS API | 5004 | http://localhost:5004 | Comprehensive vulnerability assessment |

## 🔧 Input/Output Format

### Standard Input
```json
{
  "target_ip": "192.168.1.100",
  "ports": [80, 443, 8080, 8443],
  "scan_options": {
    "timeout": 300,
    "scan_type": "full"
  }
}
```

### Output Formats Hỗ trợ
- `json` - JSON format (default)
- `xml` - XML format
- `html` - HTML report với styling
- `csv` - CSV format cho analysis
- `txt` - Plain text report

## 📖 Usage Examples

### Nikto Scan

```bash
# Tạo scan
curl -X POST http://localhost:5001/api/nikto/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "example.com",
    "ports": [80, 443],
    "scan_options": {
      "timeout": 180,
      "pause": 1,
      "ssl": true
    }
  }'

# Response
{
  "success": true,
  "data": {
    "scan_id": "uuid-here",
    "target_ip": "example.com",
    "ports": [80, 443],
    "status": "started"
  }
}

# Kiểm tra status
curl http://localhost:5001/api/nikto/scan/{scan_id}/status

# Lấy kết quả
curl http://localhost:5001/api/nikto/scan/{scan_id}/results?format=html

# Download file
curl http://localhost:5001/api/nikto/scan/{scan_id}/download?format=csv -o results.csv
```

### ZAP Scan

```bash
# Spider scan
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

# Active scan
curl -X POST http://localhost:5002/api/zap/scan/active \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "example.com",
    "ports": [80, 443]
  }'

# Full scan (spider + active)
curl -X POST http://localhost:5002/api/zap/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "example.com",
    "ports": [80, 443],
    "scan_options": {
      "scan_type": "full"
    }
  }'
```

## 🐳 Docker Services

### Core Services
- **nikto-api**: Nikto web vulnerability scanner API
- **zap-api**: OWASP ZAP security testing API
- **zap**: OWASP ZAP daemon
- **tenable-api**: Tenable Nessus API wrapper
- **nessus**: Nessus scanner daemon
- **openvas-api**: OpenVAS API wrapper
- **openvas**: OpenVAS scanner

### Supporting Services
- **redis**: Caching layer (optional)
- **postgres**: Results database (optional)
- **api-gateway**: Unified API access (optional)

## ⚙️ Configuration

### Environment Variables

```bash
# Tenable
TENABLE_ACCESS_KEY=your_access_key
TENABLE_SECRET_KEY=your_secret_key
NESSUS_ACTIVATION_CODE=your_activation_code

# ZAP
ZAP_API_KEY=your-zap-api-key

# OpenVAS
OPENVAS_USER=admin
OPENVAS_PASSWORD=admin123

# Database
POSTGRES_DB=scanners
POSTGRES_USER=scanner_user
POSTGRES_PASSWORD=scanner_pass
```

### Scan Options

#### Nikto Options
```json
{
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
```

#### ZAP Options
```json
{
  "scan_type": "full|spider|active",
  "spider": {
    "max_depth": 5,
    "max_children": 10
  },
  "active_scan": {
    "policy_name": "Default Policy"
  }
}
```

## 🔍 Response Format

### Success Response
```json
{
  "success": true,
  "data": {
    "scan_id": "uuid",
    "target_ip": "192.168.1.100",
    "ports": [80, 443],
    "status": "completed",
    "vulnerability_count": 5,
    "severity_summary": {
      "critical": 0,
      "high": 2,
      "medium": 2,
      "low": 1,
      "informational": 0
    },
    "vulnerabilities": [...]
  },
  "message": "Scan completed successfully"
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

## 🛠️ Development

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run individual APIs
python nikto_api/app.py    # Port 5001
python zap_api/app.py      # Port 5002

# Run tests
make test

# Linting
make lint
```

### Adding New Scanner

1. Create new directory: `{scanner}_api/`
2. Implement `{scanner}_scanner.py` extending `BaseScanner`
3. Create `app.py` with Flask routes
4. Add Dockerfile
5. Update docker-compose.yml

## 📊 Monitoring

### Health Checks
```bash
# Kiểm tra tất cả services
make health

# Resource usage
make monitor

# Logs
make logs
```

### Backup
```bash
# Backup scan data
make backup
```

## 📚 Documentation

### API Documentation
- Swagger/OpenAPI specs có sẵn tại `/docs` endpoint
- Postman collections trong `/docs` folder

### Individual APIs
- [Nikto API](nikto_api/README.md)
- [ZAP API](zap_api/README.md)
- [Tenable API](tenable_api/README.md) (coming soon)
- [OpenVAS API](openvas_api/README.md) (coming soon)

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

- GitHub Issues: Report bugs and feature requests
- Documentation: Check individual API README files
- Health endpoints: Monitor service status

---

**Made with ❤️ for the security community**
