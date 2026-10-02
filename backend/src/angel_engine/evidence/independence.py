"""Independence of evidence for corroboration.

Two pieces of evidence only count as independent when they come from different origins: different
publishers (registrable domain), owners (admin-curated ownership groups), accounts on a platform, or
images — and they are not syndicated copies of the same text.
"""

from __future__ import annotations

from angel_engine.db.models import EvidenceItem, Source

SOCIAL_CATEGORIES = frozenset({"public_social_media", "public_profiles", "public_forums"})


def origin_key(evidence: EvidenceItem, source: Source | None) -> str:
    if evidence.syndication_cluster_id is not None:
        return f"syndication:{evidence.syndication_cluster_id}"
    if source is not None:
        if source.ownership_group:
            return f"owner:{source.ownership_group.casefold()}"
        if source.source_category in SOCIAL_CATEGORIES and source.publisher:
            return f"account:{source.registrable_domain}#{source.publisher.casefold()}"
        return f"publisher:{source.registrable_domain}"
    return f"image:{evidence.origin_image_id}"
