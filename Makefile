SHELL := /bin/bash

# Docker Compose files
COMPOSE_FILE = docker-compose.yml
DEV_COMPOSE_FILE = docker-compose.dev.override.yml

# Service endpoints - all traffic goes through nginx proxy
NGINX_URL = https://localhost
NGINX_HTTP_URL = http://localhost

# Development mode flag - set DEV=false for production testing
DEV ?= true
DEV_FLAG = $(if $(filter true,$(DEV)),--dev,)

# Python runner command
PYTHON_RUNNER ?= uv run

.PHONY: help dev-full dev-up dev-down test-all test-health test-attestation test-app test-redirect test-acme test-certificate test-cors test-ekm-headers wait-services

help:
	@echo "Shade Framework - Build, Run, and Test"
	@echo "======================================="
	@echo ""
	@echo "🚀 Development Commands:"
	@echo "  dev-full      Full dev workflow: build, up, wait, test"
	@echo "  dev-up        Start services in development mode"
	@echo "  dev-down      Stop development services"
	@echo ""
	@echo "🧪 Test Commands:"
	@echo "  test-all          Run the default local test suite via Python test script"
	@echo "  test-health       Test health endpoint"
	@echo "  test-attestation  Test attestation service endpoints (TDX-only)"
	@echo "  test-app          Test app proxy endpoints"
	@echo "  test-redirect     Test HTTP to HTTPS redirect"
	@echo "  test-acme         Test ACME challenge endpoint"
	@echo "  test-certificate  Test SSL certificate validation"
	@echo "  test-cors         Test CORS configuration on multiple endpoints"
	@echo "  test-ekm-headers  Test EKM header forwarding (dev mode only)"
	@echo "  unit-tests        Run unit tests (shade) with coverage reporting"
	@echo ""
	@echo "⚙️  Environment Variables:"
	@echo "  DEV             Set to 'false' for production mode testing"
	@echo "                  (default: true - development mode)"
	@echo "  PYTHON_RUNNER   Set how to run python scripts"
	@echo "                  (default: uv run)"
	@echo ""
	@echo "💡 Examples:"
	@echo "  make dev-full                          # Full development workflow"
	@echo "  make dev-up                            # Start dev docker compose"
	@echo "  make test-attestation                  # Test only attestation endpoints on a TDX host"
	@echo "  DEV=false make test-all                # Run all tests in production mode"
	@echo "  PYTHON_RUNNER=python3 make test-all    # Run python scripts using python3"

# Development workflow
dev-full: dev-down dev-up
	DEV=true $(MAKE) wait-services
	DEV=true $(MAKE) test-all
	$(MAKE) dev-down

dev-up:
	@echo "🚀 Starting services in development mode..."
	docker compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) up -d --build

dev-down:
	@echo "🛑 Stopping development services..."
	docker compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) down

wait-services:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --wait --base-url $(NGINX_URL)

test-all:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --all --base-url $(NGINX_URL) --http-url $(NGINX_HTTP_URL)

test-health:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --health --base-url $(NGINX_URL)

test-attestation:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --attestation --base-url $(NGINX_URL)

test-app:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --app --base-url $(NGINX_URL)

test-redirect:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --redirect --base-url $(NGINX_URL) --http-url $(NGINX_HTTP_URL)

test-acme:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --acme --base-url $(NGINX_URL) --http-url $(NGINX_HTTP_URL)

test-certificate:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --certificate --base-url $(NGINX_URL)

test-cors:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --cors --base-url $(NGINX_URL)

test-ekm-headers:
	$(PYTHON_RUNNER) test_cvm.py $(DEV_FLAG) --ekm-headers --base-url $(NGINX_URL)

unit-tests:
	$(PYTHON_RUNNER) pytest --cov=shade --cov-report=term-missing --cov-fail-under=98 tests/ -v
