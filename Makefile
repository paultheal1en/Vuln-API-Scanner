# Vulnerability Scanners API Makefile

.PHONY: help build up down restart logs clean test lint nikto zap tenable openvas

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Vulnerability Scanners API$(NC)"
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Docker operations
build: ## Build all Docker images
	@echo "$(YELLOW)Building Docker images...$(NC)"
	docker-compose build

up: ## Start all services
	@echo "$(GREEN)Starting all services...$(NC)"
	docker-compose up -d

down: ## Stop all services
	@echo "$(RED)Stopping all services...$(NC)"
	docker-compose down

restart: down up ## Restart all services

logs: ## Show logs for all services
	docker-compose logs -f

clean: ## Clean up Docker resources
	@echo "$(RED)Cleaning up Docker resources...$(NC)"
	docker-compose down -v
	docker system prune -f

# Individual service management
nikto: ## Start only Nikto API
	@echo "$(GREEN)Starting Nikto API...$(NC)"
	docker-compose up -d nikto-api

zap: ## Start ZAP and ZAP API
	@echo "$(GREEN)Starting ZAP services...$(NC)"
	docker-compose up -d zap zap-api

tenable: ## Start Tenable/Nessus services
	@echo "$(GREEN)Starting Tenable services...$(NC)"
	docker-compose up -d nessus tenable-api

openvas: ## Start OpenVAS services
	@echo "$(GREEN)Starting OpenVAS services...$(NC)"
	docker-compose up -d openvas openvas-api

# Development
dev: ## Start services in development mode
	@echo "$(YELLOW)Starting in development mode...$(NC)"
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Testing
test: ## Run tests
	@echo "$(BLUE)Running tests...$(NC)"
	docker-compose exec nikto-api python -m pytest tests/ -v
	docker-compose exec zap-api python -m pytest tests/ -v

lint: ## Run linting
	@echo "$(BLUE)Running linting...$(NC)"
	docker-compose exec nikto-api python -m flake8 .
	docker-compose exec zap-api python -m flake8 .

# Health checks
health: ## Check health of all services
	@echo "$(BLUE)Checking service health...$(NC)"
	@curl -s http://localhost:5001/health | jq '.' || echo "$(RED)Nikto API not responding$(NC)"
	@curl -s http://localhost:5002/health | jq '.' || echo "$(RED)ZAP API not responding$(NC)"
	@curl -s http://localhost:5003/health | jq '.' || echo "$(RED)Tenable API not responding$(NC)"
	@curl -s http://localhost:5004/health | jq '.' || echo "$(RED)OpenVAS API not responding$(NC)"

# Utility commands
backup: ## Backup scan data
	@echo "$(YELLOW)Creating backup...$(NC)"
	docker run --rm -v vulnerability-scanners-api_openvas-data:/data -v $(PWD)/backups:/backup alpine tar czf /backup/openvas-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /data .
	docker run --rm -v vulnerability-scanners-api_nessus-data:/data -v $(PWD)/backups:/backup alpine tar czf /backup/nessus-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz -C /data .

init: ## Initialize environment
	@echo "$(YELLOW)Initializing environment...$(NC)"
	cp .env.example .env
	mkdir -p scans backups logs
	@echo "$(GREEN)Environment initialized. Please edit .env file with your credentials.$(NC)"

# API examples
example-nikto: ## Run example Nikto scan
	@echo "$(BLUE)Running example Nikto scan...$(NC)"
	curl -X POST http://localhost:5001/api/nikto/scan \
		-H "Content-Type: application/json" \
		-d '{"target_ip": "example.com", "ports": [80, 443], "scan_options": {"timeout": 60}}'

example-zap: ## Run example ZAP scan
	@echo "$(BLUE)Running example ZAP scan...$(NC)"
	curl -X POST http://localhost:5002/api/zap/scan \
		-H "Content-Type: application/json" \
		-d '{"target_ip": "example.com", "ports": [80, 443], "scan_options": {"scan_type": "spider"}}'

# Documentation
docs: ## Generate API documentation
	@echo "$(BLUE)Generating API documentation...$(NC)"
	@echo "API endpoints available at:"
	@echo "$(GREEN)Nikto API:$(NC)    http://localhost:5001"
	@echo "$(GREEN)ZAP API:$(NC)      http://localhost:5002"
	@echo "$(GREEN)Tenable API:$(NC)  http://localhost:5003"
	@echo "$(GREEN)OpenVAS API:$(NC)  http://localhost:5004"

# Monitoring
monitor: ## Show resource usage
	@echo "$(BLUE)Resource usage:$(NC)"
	docker stats --no-stream

# Quick setup for testing
quick-start: init build nikto zap ## Quick start with Nikto and ZAP only
	@echo "$(GREEN)Quick start complete!$(NC)"
	@echo "$(YELLOW)Nikto API:$(NC) http://localhost:5001"
	@echo "$(YELLOW)ZAP API:$(NC)   http://localhost:5002"
	@echo "$(YELLOW)ZAP Proxy:$(NC) http://localhost:8080"