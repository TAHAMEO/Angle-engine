SHELL := /bin/bash
BACKEND := backend
PY := $(BACKEND)/.venv/bin/python
VENV_BIN := $(BACKEND)/.venv/bin

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Create the backend virtualenv and install dependencies
	cd $(BACKEND) && python3 -m venv .venv && .venv/bin/pip install -q --upgrade pip setuptools wheel \
		&& .venv/bin/pip install -q -e ".[dev,pdf]"

.PHONY: services
services: ## Start local PostgreSQL and Redis (initialising PostgreSQL on first run)
	@if [ ! -f var/postgres/data/PG_VERSION ]; then scripts/dev-postgres.sh init; else scripts/dev-postgres.sh start; fi
	scripts/dev-redis.sh start

.PHONY: services-stop
services-stop: ## Stop local PostgreSQL and Redis
	scripts/dev-postgres.sh stop
	scripts/dev-redis.sh stop

.PHONY: migrate
migrate: ## Apply database migrations to the development database
	cd $(BACKEND) && .venv/bin/alembic upgrade head

.PHONY: test
test: ## Run the backend test suite
	cd $(BACKEND) && .venv/bin/pytest -q

.PHONY: lint
lint: ## Lint the backend
	cd $(BACKEND) && .venv/bin/ruff check src tests

.PHONY: typecheck
typecheck: ## Type-check the backend
	cd $(BACKEND) && .venv/bin/mypy src

.PHONY: api
api: ## Run the API with auto-reload (development)
	cd $(BACKEND) && .venv/bin/uvicorn angel_engine.main:create_app --factory --reload --port 8000

.PHONY: worker
worker: ## Run the background worker (all queues)
	cd $(BACKEND) && .venv/bin/python -m angel_engine.worker --queues analysis,egress,ai,maintenance
