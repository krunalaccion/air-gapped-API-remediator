PYTHON ?= python3
PORT ?= 8080
IMAGE_NAME ?= airgap-remediator:latest

.PHONY: help install install-dev test run mcp lint docker-build docker-run clean

help:
	@echo "Available targets:"
	@echo "  make install       Install package in editable/standard mode"
	@echo "  make install-dev   Install package with dev dependencies"
	@echo "  make test          Run full unittest suite"
	@echo "  make run           Start the Web Control Center on port $(PORT)"
	@echo "  make mcp           Start the MCP JSON-RPC stdio server"
	@echo "  make lint          Compile-check Python files and verify clean imports"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-run    Start application via docker compose"
	@echo "  make clean         Remove Python bytecode caches and build artifacts"

install:
	$(PYTHON) -m pip install .

install-dev:
	$(PYTHON) -m pip install -e ".[dev,extras]"

test:
	$(PYTHON) -m unittest discover -s tests -v

run:
	$(PYTHON) web_server.py $(PORT)

mcp:
	$(PYTHON) -m agents.git_agent.mcp_server

lint:
	$(PYTHON) -m compileall -q agents orchestrator tests web_server.py airgap_remediator.py
	$(PYTHON) -c "import web_server; print('Import check OK')"

docker-build:
	docker build -t $(IMAGE_NAME) .

docker-run:
	docker compose up --build

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist *.egg-info .pytest_cache

