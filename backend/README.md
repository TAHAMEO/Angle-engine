# angel-engine (backend)

The FastAPI API, background worker, image pipeline, connectors, policy engine, AI layer and report renderer of
**Angel Engine**, a lawful, privacy-first OSINT investigation platform.

- Product overview and quick start: [`../README.md`](../README.md)
- Architecture, security, data model, API, connectors and operations: [`../docs/`](../docs/)

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,pdf]"
.venv/bin/angel-engine --help        # keys, create-admin, seed-demo, openapi
.venv/bin/pytest -q                  # needs the local PostgreSQL and Redis (make services)
```
