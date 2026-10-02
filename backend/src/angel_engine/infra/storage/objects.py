"""Object storage for encrypted blobs. Keys are random identifiers, never user-supplied file names.

Blobs are encrypted by the caller (per-object keys wrapped by the investigation DEK) *before* they reach
storage, so the storage backend only ever sees ciphertext.

Key layout: everything that belongs to an investigation lives under ``inv/<investigation_id>/`` (see
:func:`investigation_prefix`) so deleting an investigation can remove every blob by prefix; per-user
exports live under ``exports/<user_id>/``.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from pathlib import Path
from typing import Protocol

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9/_.-]{2,300}$")


class StorageError(RuntimeError):
    pass


def investigation_prefix(investigation_id: object) -> str:
    return f"inv/{investigation_id}/"


def investigation_object_key(investigation_id: object, kind: str, object_id: object) -> str:
    return f"{investigation_prefix(investigation_id)}{kind}/{object_id}"


def _check_key(key: str) -> str:
    if not _KEY_RE.match(key) or ".." in key or key.startswith("/"):
        raise StorageError("invalid object key")
    return key


class ObjectStore(Protocol):
    async def put(self, key: str, data: bytes) -> None: ...
    async def get(self, key: str) -> bytes: ...
    async def delete(self, key: str) -> None: ...
    async def delete_prefix(self, prefix: str) -> int: ...
    async def exists(self, key: str) -> bool: ...


class LocalObjectStore:
    """Filesystem store (development, tests, single-node deployments with an encrypted volume)."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, key: str) -> Path:
        path = (self.root / _check_key(key)).resolve()
        if self.root not in path.parents:
            raise StorageError("invalid object key")
        return path

    async def put(self, key: str, data: bytes) -> None:
        path = self._path(key)

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = path.with_suffix(path.suffix + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)

        await asyncio.to_thread(_write)

    async def get(self, key: str) -> bytes:
        path = self._path(key)
        try:
            return await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError as exc:
            raise StorageError("object not found") from exc

    async def delete(self, key: str) -> None:
        path = self._path(key)
        await asyncio.to_thread(lambda: path.unlink(missing_ok=True))

    async def delete_prefix(self, prefix: str) -> int:
        if not prefix.endswith("/"):
            raise StorageError("prefix must end with '/'")
        path = self._path(prefix.rstrip("/"))

        def _remove() -> int:
            if not path.exists():
                return 0
            count = sum(1 for p in path.rglob("*") if p.is_file())
            shutil.rmtree(path)
            return count

        return await asyncio.to_thread(_remove)

    async def exists(self, key: str) -> bool:
        return await asyncio.to_thread(self._path(key).exists)


class S3ObjectStore:
    """S3-compatible store (MinIO, AWS S3). Requires the optional ``s3`` extra (boto3)."""

    def __init__(
        self, *, bucket: str, endpoint_url: str | None, region: str, access_key: str | None, secret_key: str | None
    ) -> None:
        import boto3  # optional dependency

        self.bucket = bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    async def put(self, key: str, data: bytes) -> None:
        await asyncio.to_thread(
            self._client.put_object,
            Bucket=self.bucket,
            Key=_check_key(key),
            Body=data,
            ServerSideEncryption="AES256",
        )

    async def get(self, key: str) -> bytes:
        try:
            response = await asyncio.to_thread(self._client.get_object, Bucket=self.bucket, Key=_check_key(key))
        except Exception as exc:
            raise StorageError("object not found") from exc
        body: bytes = await asyncio.to_thread(response["Body"].read)
        return body

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._client.delete_object, Bucket=self.bucket, Key=_check_key(key))

    async def delete_prefix(self, prefix: str) -> int:
        if not prefix.endswith("/"):
            raise StorageError("prefix must end with '/'")
        _check_key(prefix)

        def _remove() -> int:
            removed = 0
            paginator = self._client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
                if keys:
                    self._client.delete_objects(Bucket=self.bucket, Delete={"Objects": keys, "Quiet": True})
                    removed += len(keys)
            return removed

        return await asyncio.to_thread(_remove)

    async def exists(self, key: str) -> bool:
        try:
            await asyncio.to_thread(self._client.head_object, Bucket=self.bucket, Key=_check_key(key))
        except Exception:
            return False
        return True
