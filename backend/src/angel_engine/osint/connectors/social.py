"""Public profiles and public social media: GitHub, Mastodon, Bluesky.

Profile lookups are person-oriented: they require a recorded purpose, and in restricted mode they need a
supervisor's approval. Account opt-outs are honoured — a Mastodon account that is not discoverable or
indexable, or a Bluesky account labelled ``!no-unauthenticated``, becomes a manual-review reference only.
For individuals only the e-mail *domain* is kept and no location is recorded.
"""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import quote

from angel_engine.osint.connectors.base import Connector, ConnectorContext, ConnectorError, clip, parse_date
from angel_engine.osint.connectors.publications import strip_html
from angel_engine.osint.types import (
    AccessStatus,
    ConnectorInfo,
    ConnectorQuery,
    ConnectorResult,
    EntityDraft,
    EvidenceType,
    InputType,
    ManualReference,
    NormalizedRecord,
    RelationshipDraft,
    SourceCategory,
)

_HANDLE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


class GitHub(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="github",
        name="GitHub public profiles",
        category=SourceCategory.PUBLIC_PROFILES,
        description="Public organization or account profiles on GitHub (repositories count, website, creation "
        "date). E-mail addresses are reduced to their domain.",
        input_types=(InputType.USERNAME, InputType.ORGANIZATION),
        docs_url="https://docs.github.com/en/rest/users/users",
        terms_note="Public profile fields only; 60 requests/hour without a token.",
        requires_key="github_token",
        key_optional=True,
        person_oriented=True,
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        login = query.value.strip().lstrip("@")
        if not _HANDLE.match(login):
            raise ConnectorError("invalid_query", "not a GitHub login")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token := ctx.secret(self.info.requires_key):
            headers["Authorization"] = f"Bearer {token}"
        data = await self.get_json(ctx, f"https://api.github.com/users/{quote(login)}", headers=headers)
        if not data:
            return ConnectorResult(warnings=(f"No public GitHub account named {login}.",))
        is_org = data.get("type") == "Organization"
        name = data.get("name") or data.get("login") or login
        url = data.get("html_url") or f"https://github.com/{login}"
        parts = [f"GitHub {'organization' if is_org else 'account'} {data.get('login')}"]
        if data.get("name"):
            parts.append(f"(display name “{clip(data['name'], 80)}”)")
        parts.append(f"has {data.get('public_repos', 0)} public repositories")
        created = parse_date(data.get("created_at"))
        if created:
            parts.append(f"and was created on {created.date().isoformat()}")
        excerpt = " ".join(parts) + "."
        if data.get("blog"):
            excerpt += f" Website: {data['blog']}."
        if data.get("email"):
            excerpt += f" Public e-mail domain: {str(data['email']).rsplit('@', 1)[-1]}."
        if is_org and data.get("location"):
            excerpt += f" Location (as stated): {clip(data['location'], 60)}."
        entities = [
            EntityDraft(
                "username", f"@{data.get('login', login)}", data.get("login", login).lower(), {"platform": "github"}
            )
        ]
        relationships = []
        if is_org:
            entities.append(EntityDraft("organization", name, name))
            relationships.append(
                RelationshipDraft(data.get("login", login).lower(), "username", "operated_by", name, "organization")
            )
        return ConnectorResult(
            records=(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_PROFILES,
                    url=url,
                    title=f"GitHub: {data.get('login', login)}",
                    excerpt=excerpt,
                    statement=f"The public GitHub {'organization' if is_org else 'account'} {data.get('login', login)} "
                    f"lists {data.get('public_repos', 0)} public repositories.",
                    evidence_type=EvidenceType.TEXT_EXCERPT,
                    published_at=created,
                    publisher=f"github:{login.lower()}",
                    entities=tuple(entities),
                    relationships=tuple(relationships),
                    organization_context=is_org,
                ),
            )
        )


class Mastodon(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="mastodon",
        name="Mastodon public profiles",
        category=SourceCategory.PUBLIC_SOCIAL_MEDIA,
        description="Public Mastodon account profiles (accounts that opted out of discovery are not collected).",
        input_types=(InputType.USERNAME,),
        docs_url="https://docs.joinmastodon.org/methods/accounts/#lookup",
        terms_note="Honours the account's discoverable/indexable settings; 300 requests per 5 minutes.",
        person_oriented=True,
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        handle = query.value.strip().lstrip("@")
        user, _, instance = handle.partition("@")
        instance = instance.lower()
        if not _HANDLE.match(user) or not _DOMAIN.match(instance):
            raise ConnectorError("invalid_query", "use the form @user@instance.example")
        data = await self.get_json(ctx, f"https://{instance}/api/v1/accounts/lookup", params={"acct": user})
        profile_url = f"https://{instance}/@{user}"
        if not data:
            return ConnectorResult(warnings=(f"No public Mastodon account @{handle}.",))
        if data.get("discoverable") is False or data.get("indexable") is False:
            return ConnectorResult(
                references=(
                    ManualReference(
                        data.get("url") or profile_url,
                        AccessStatus.REFERENCE_ONLY,
                        "This account has opted out of discovery or search indexing; it is listed for manual review "
                        "only.",
                    ),
                )
            )
        created = parse_date(data.get("created_at"))
        bio = clip(strip_html(data.get("note")), 500)
        excerpt = (
            f"Mastodon account @{data.get('acct', user)}@{instance}"
            + (f" (display name “{clip(data.get('display_name'), 80)}”)" if data.get("display_name") else "")
            + f", {data.get('statuses_count', 0)} posts, {data.get('followers_count', 0)} followers"
            + (f", created {created.date().isoformat()}" if created else "")
            + "."
            + (f" Bio: {bio}" if bio else "")
        )
        return ConnectorResult(
            records=(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_SOCIAL_MEDIA,
                    url=data.get("url") or profile_url,
                    title=f"Mastodon: @{user}@{instance}",
                    excerpt=excerpt,
                    statement=f"A public Mastodon account @{user}@{instance} exists"
                    + (f", created on {created.date().isoformat()}." if created else "."),
                    evidence_type=EvidenceType.TEXT_EXCERPT,
                    published_at=created,
                    publisher=f"@{user}@{instance}",
                    entities=(
                        EntityDraft(
                            "username", f"@{user}@{instance}", f"{user}@{instance}".lower(), {"platform": "mastodon"}
                        ),
                    ),
                ),
            )
        )


class Bluesky(Connector):
    info: ClassVar[ConnectorInfo] = ConnectorInfo(
        id="bluesky",
        name="Bluesky public profiles",
        category=SourceCategory.PUBLIC_SOCIAL_MEDIA,
        description="Public Bluesky profiles via the public AppView (accounts that restrict logged-out viewing "
        "are not collected).",
        input_types=(InputType.USERNAME,),
        docs_url="https://docs.bsky.app/docs/api/app-bsky-actor-get-profile",
        terms_note="Honours the !no-unauthenticated self-label.",
        person_oriented=True,
        allowed_in_restricted_mode=True,
        min_interval_s=1.0,
    )

    async def search(self, query: ConnectorQuery, ctx: ConnectorContext) -> ConnectorResult:
        handle = query.value.strip().lstrip("@").lower()
        if not _DOMAIN.match(handle):
            raise ConnectorError("invalid_query", "use a handle such as name.bsky.social")
        data = await self.get_json(
            ctx, "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile", params={"actor": handle}
        )
        profile_url = f"https://bsky.app/profile/{handle}"
        if not data:
            return ConnectorResult(warnings=(f"No public Bluesky profile for {handle}.",))
        labels = {str(label.get("val")) for label in data.get("labels", []) if isinstance(label, dict)}
        if "!no-unauthenticated" in labels:
            return ConnectorResult(
                references=(
                    ManualReference(
                        profile_url,
                        AccessStatus.REFERENCE_ONLY,
                        "The account asks not to be shown to logged-out viewers; listed for manual review only.",
                    ),
                )
            )
        created = parse_date(data.get("createdAt"))
        bio = clip(data.get("description"), 500)
        excerpt = (
            f"Bluesky profile {data.get('handle', handle)}"
            + (f" (display name “{clip(data.get('displayName'), 80)}”)" if data.get("displayName") else "")
            + f", {data.get('postsCount', 0)} posts, {data.get('followersCount', 0)} followers"
            + (f", created {created.date().isoformat()}" if created else "")
            + "."
            + (f" Bio: {bio}" if bio else "")
        )
        return ConnectorResult(
            records=(
                NormalizedRecord(
                    connector_id=self.info.id,
                    category=SourceCategory.PUBLIC_SOCIAL_MEDIA,
                    url=profile_url,
                    title=f"Bluesky: {handle}",
                    excerpt=excerpt,
                    statement=f"A public Bluesky profile {handle} exists"
                    + (f", created on {created.date().isoformat()}." if created else "."),
                    evidence_type=EvidenceType.TEXT_EXCERPT,
                    published_at=created,
                    publisher=f"bluesky:{handle}",
                    entities=(EntityDraft("username", f"@{handle}", handle, {"platform": "bluesky"}),),
                ),
            )
        )
