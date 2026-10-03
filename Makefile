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
	cd $(BACKEND) && .venv/bin/uvicorn angel_engine.main:create_app --factory --reload --port 8000 --no-access-log

.PHONY: worker
worker: ## Run the background worker (all queues)
	cd $(BACKEND) && .venv/bin/python -m angel_engine.worker --queues analysis,egress,ai,maintenance

.PHONY: openapi
openapi: ## Export the API schema snapshot and regenerate the web client's types
	cd $(BACKEND) && .venv/bin/angel-engine openapi --output ../frontend/openapi.json
	cd frontend && pnpm gen:api

.PHONY: seed-demo
seed-demo: ## Load the offline demo dataset (requires fixtures mode and the offline demo AI)
	cd $(BACKEND) && .venv/bin/angel-engine seed-demo

.PHONY: web-install
web-install: ## Install the web client's dependencies
	cd frontend && pnpm install --frozen-lockfile

.PHONY: web-dev
web-dev: ## Run the web client against the local API (http://localhost:3000)
	cd frontend && ANGEL_DEV_API_ORIGIN=http://127.0.0.1:8000 pnpm dev

.PHONY: web-check
web-check: ## Lint, type-check, test and verify the web client's API types
	cd frontend && pnpm lint && pnpm typecheck && pnpm test && pnpm check:api

.PHONY: e2e
e2e: ## Build the web client and run the Playwright end-to-end suite (starts a disposable backend)
	cd frontend && ANGEL_DEV_API_ORIGIN=http://127.0.0.1:8000 pnpm build && pnpm e2e

# The demo always publishes Caddy on 127.0.0.1 (docker-compose.demo.yml). ANGEL_BIND_ADDRESS is defined only so that
# older Compose versions do not warn that it is unset; never export it globally, it would override deploy/.env.
DEMO_COMPOSE := ANGEL_DOMAIN=localhost ANGEL_BIND_ADDRESS= docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.demo.yml

.PHONY: compose-config
compose-config: ## Validate the Docker Compose files (production and demo)
	ANGEL_DOMAIN=$${ANGEL_DOMAIN:-angel.example.org} docker compose -f deploy/docker-compose.yml config -q
	$(DEMO_COMPOSE) config -q

.PHONY: up
up: ## Build and start the production stack (needs deploy/.env)
	deploy/preflight.sh
	deploy/generate-secrets.sh
	docker compose -f deploy/docker-compose.yml up -d --build

.PHONY: demo
demo: ## Build and start the offline demo on https://localhost and load the demo data
	deploy/preflight.sh
	deploy/generate-secrets.sh
	$(DEMO_COMPOSE) up -d --build
	$(DEMO_COMPOSE) run --rm api angel-engine seed-demo

.PHONY: demo-stop
demo-stop: ## Stop the offline demo (its data is kept; `make demo` starts it again)
	$(DEMO_COMPOSE) down

.PHONY: demo-reset
demo-reset: ## Delete the offline demo: its containers and all Angel Engine data in Docker on this machine
	@printf '%s\n%s' "This deletes the Angel Engine containers and ALL Angel Engine data in Docker on this machine" \
		"(the demo's, or a real installation's: they share one Compose project). Type delete to continue: "
	@read -r answer && [ "$$answer" = delete ] || { echo "Cancelled; nothing was deleted."; exit 1; }
	$(DEMO_COMPOSE) down -v
