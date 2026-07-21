.PHONY: help setup check test lint fmt dev dev-seed down logs clean deploy-pi logs-pi

help:
	@echo "Local development:"
	@echo "  make setup      Create venv and install everything"
	@echo "  make check      Run the full PR gate (lint, format, types, tests)"
	@echo "  make test       Tests only"
	@echo "  make fmt        Auto-format and auto-fix lint"
	@echo ""
	@echo "Docker stack:"
	@echo "  make dev        Server + three probes, taking real measurements"
	@echo "  make dev-seed   As above, plus seven days of synthetic history"
	@echo "  make logs       Tail all containers"
	@echo "  make down       Stop and remove volumes"
	@echo ""
	@echo "Raspberry Pi:"
	@echo "  make deploy-pi  rsync source, reinstall, restart services"
	@echo "  make logs-pi    Tail the Pi's journald output"

setup:
	uv venv --python 3.11
	uv pip install -e ".[dev,agent,server]"
	./scripts/install-hooks.sh

check:
	./scripts/pr.sh check

test:
	.venv/bin/python -m pytest -q

lint:
	.venv/bin/python -m ruff check src tests
	.venv/bin/python -m mypy

fmt:
	.venv/bin/python -m ruff check --fix src tests
	.venv/bin/python -m ruff format src tests

dev:
	docker compose up --build -d
	@echo "server:    http://localhost:8080/api/v1/health"
	@echo "api docs:  http://localhost:8080/docs"

# Seeds first so the history is in place before live probes start appending to it.
dev-seed:
	docker compose --profile seed up --build -d server
	docker compose --profile seed run --rm seeder
	docker compose up -d

logs:
	docker compose logs -f

down:
	docker compose down -v

clean: down
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache data

# --- Raspberry Pi -----------------------------------------------------------
# Production on the Pi is systemd + a uv venv, NOT Docker: a container would put a
# network layer between the monitor and the host stack, which is the thing being
# measured. Rsync also beats rebuilding ARM images for a tight iteration loop.

PI_HOST ?= netdbg@netdbg.local
PI_DIR  ?= /opt/netdbg

deploy-pi:
	rsync -az --delete --exclude '__pycache__' \
		src/ pyproject.toml README.md uv.lock $(PI_HOST):$(PI_DIR)/
	ssh $(PI_HOST) 'cd $(PI_DIR) && uv sync && sudo systemctl restart netdbg-server netdbg-agent'

logs-pi:
	ssh $(PI_HOST) 'journalctl -u netdbg-server -u netdbg-agent -f'
