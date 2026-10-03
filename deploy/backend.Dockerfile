# syntax=docker/dockerfile:1.7
# Angel Engine API and workers (one image; the command selects the role).
FROM python:3.12-slim-bookworm AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
# Tesseract (OCR), Pango/HarfBuzz (PDF reports), fonts for rendering; no compilers in the runtime image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      tesseract-ocr tesseract-ocr-eng \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 \
      libglib2.0-0 fonts-dejavu-core fonts-liberation2 tini \
 && rm -rf /var/lib/apt/lists/*

FROM base AS build
WORKDIR /build
COPY backend/README.md /build/backend/README.md
COPY backend/pyproject.toml /build/backend/pyproject.toml
COPY backend/src /build/backend/src
RUN pip wheel --wheel-dir /wheels "/build/backend[pdf,s3]"

FROM base AS runtime
RUN groupadd --gid 10001 angel && useradd --uid 10001 --gid angel --no-create-home --shell /usr/sbin/nologin angel
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links /wheels "angel-engine[pdf,s3]" && rm -rf /wheels
WORKDIR /app
COPY backend/alembic.ini /app/alembic.ini
COPY backend/alembic /app/alembic
RUN mkdir -p /var/lib/angel-engine/storage /var/lib/angel-engine/keys \
 && chown -R angel:angel /var/lib/angel-engine
USER angel
ENV ANGEL_ENV=production \
    ANGEL_STORAGE_PATH=/var/lib/angel-engine/storage \
    ANGEL_KEYRING_PATH=/var/lib/angel-engine/keys/keyring.json
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
# Behind Caddy on an internal network only; trust its X-Forwarded-For for client-IP pseudonyms.
CMD ["uvicorn", "angel_engine.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header", "--no-access-log"]
