"""Administrative command line.

``angel-engine keys init`` · ``angel-engine create-admin`` · ``angel-engine seed-demo`` · ``angel-engine openapi``
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import secrets
import sys

from sqlalchemy import select

from angel_engine.config import get_settings


def _keys_init(args: argparse.Namespace) -> int:
    from angel_engine.crypto.keys import FileKeyring

    settings = get_settings()
    path = settings.keyring_path
    if path.exists() and not args.force:
        print(f"keyring already exists at {path}")  # noqa: T201
        return 0
    FileKeyring(path, create=True)
    print(f"created keyring at {path} (mode 0600) — store it outside database backups")  # noqa: T201
    return 0


async def _create_admin(email: str, name: str, password: str) -> None:
    from angel_engine.app_state import build_services
    from angel_engine.audit.chain import AuditEvent, append_now
    from angel_engine.auth.passwords import hash_password, policy_violations
    from angel_engine.core.clock import utcnow
    from angel_engine.db.models import User
    from angel_engine.legal.documents import current_versions

    problems = policy_violations(password, context_words=(email.split("@", maxsplit=1)[0], name))
    if problems:
        raise SystemExit("; ".join(problems))
    svc = build_services(get_settings())
    try:
        async with svc.db.session("app") as db:
            if (await db.execute(select(User.id).where(User.email == email))).first() is not None:
                raise SystemExit("a user with this email already exists")
            user = User(
                email=email,
                display_name=name,
                password_hash=await hash_password(password),
                role="admin",
                status="active",
                approved_at=utcnow(),
                terms_version_accepted=current_versions()["terms"],
                terms_accepted_at=utcnow(),
            )
            db.add(user)
            await db.flush()
            await append_now(
                db,
                svc.audit_key,
                [
                    AuditEvent(
                        action="admin.bootstrap_admin_created",
                        actor_type="system",
                        target_type="user",
                        target_id=str(user.id),
                    )
                ],
            )
    finally:
        await svc.close()


def _create_admin_cmd(args: argparse.Namespace) -> int:
    password = args.password or ""
    if not password:
        if sys.stdin.isatty():
            password = getpass.getpass("Password (min 12 characters): ")
        else:
            password = secrets.token_urlsafe(18)
            print(f"generated password: {password}")  # noqa: T201
    asyncio.run(_create_admin(args.email, args.name, password))
    print(f"created administrator {args.email}; multi-factor enrollment is required at first sign-in")  # noqa: T201
    return 0


def _seed_demo_cmd(args: argparse.Namespace) -> int:
    from angel_engine.demo.seed import run_seed

    asyncio.run(run_seed(reset=args.reset))
    return 0


def _openapi_cmd(args: argparse.Namespace) -> int:
    """Write the OpenAPI document (the web client generates its types from this snapshot)."""
    import json
    from pathlib import Path

    from angel_engine.config import Settings
    from angel_engine.main import create_app

    document = create_app(Settings(env="development")).openapi()
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        Path(args.output).write_text(text, encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="angel-engine")
    sub = parser.add_subparsers(dest="command", required=True)
    keys = sub.add_parser("keys", help="key management")
    keys_sub = keys.add_subparsers(dest="keys_command", required=True)
    init = keys_sub.add_parser("init", help="create the keyring file")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=_keys_init)
    admin = sub.add_parser("create-admin", help="create the first administrator")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", required=True)
    admin.add_argument("--password")
    admin.set_defaults(func=_create_admin_cmd)
    seed = sub.add_parser("seed-demo", help="load the offline demo dataset (development/e2e only)")
    seed.add_argument("--reset", action="store_true")
    seed.set_defaults(func=_seed_demo_cmd)
    openapi = sub.add_parser("openapi", help="write the OpenAPI document (for generated web-client types)")
    openapi.add_argument("--output", default="-")
    openapi.set_defaults(func=_openapi_cmd)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
