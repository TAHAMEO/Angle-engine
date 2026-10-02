"""Lawful alternatives offered with policy decisions (refusals always carry at least two)."""

from __future__ import annotations

from collections.abc import Iterable

from angel_engine.policy.types import Alternative, Category

AUP_GUIDANCE = Alternative(
    kind="guidance",
    label="Review the Acceptable Use Policy for the lawful purposes Angel Engine supports",
    template=None,
    connector_id=None,
)
_VERIFY_PUBLIC = (
    Alternative(
        kind="query",
        label="Verify publicly documented organizations and their websites",
        template="official website and registry record of {organization}",
    ),
    Alternative(
        kind="query",
        label="Find published articles about a public event or public statement",
        template="news coverage of {event}",
    ),
)

_BY_CATEGORY: dict[Category, tuple[Alternative, ...]] = {
    Category.HOME_ADDRESS: (
        Alternative(
            kind="connector",
            label="Look up the registered business address of an organization in a company registry",
            template="registered office address of {organization}",
            connector_id="gleif",
        ),
        Alternative(
            kind="connector",
            label="Find the business address an organization reports in its SEC filings",
            template="business address in filings of {organization}",
            connector_id="sec_edgar",
        ),
        Alternative(
            kind="query",
            label="Find published articles about a public event",
            template="news coverage of {event}",
        ),
    ),
    Category.FACIAL_IDENTIFICATION: (
        Alternative(
            kind="guidance",
            label="Analyze non-biometric clues in the image: visible text, logos, landmarks, signage and metadata",
        ),
        Alternative(
            kind="connector",
            label="Find earlier public copies of the image using a face-blurred copy, where permitted",
            template="earlier public copies of this image (face-blurred)",
            connector_id="reverse_image",
        ),
    ),
    Category.LOCATION_TRACKING: (
        Alternative(
            kind="guidance",
            label="Identify the broad, public-level location of a landmark or venue",
            template="city or region of the landmark {landmark}",
        ),
        Alternative(
            kind="query",
            label="Check the published schedule of a public event",
            template="official schedule of {event}",
        ),
    ),
    Category.PRIVATE_CONTACT_INFO: (
        Alternative(
            kind="query",
            label="Find the official public contact channels of an organization (press office, customer service)",
            template="official contact page of {organization}",
        ),
        Alternative(
            kind="connector",
            label="Look up an organization's registered details in a company registry",
            template="registry record of {organization}",
            connector_id="gleif",
        ),
    ),
    Category.PRIVATE_PERSONAL_DATA: (
        Alternative(
            kind="query",
            label="Research publicly documented official roles and statements",
            template="official role and public statements of {role}",
        ),
        Alternative(
            kind="query",
            label="Find published articles about a public event",
            template="news coverage of {event}",
        ),
    ),
    Category.LEAKED_OR_RESTRICTED_DATA: (
        Alternative(
            kind="query",
            label="Find public breach disclosures, regulator notices and news coverage",
            template="public disclosure of a data breach at {organization}",
        ),
        Alternative(
            kind="connector",
            label="Review Certificate Transparency logs for a domain",
            template="certificates issued for {domain}",
            connector_id="certificate_transparency",
        ),
        Alternative(
            kind="connector",
            label="Review public DNS records for a domain",
            template="DNS records of {domain}",
            connector_id="dns",
        ),
    ),
    Category.SENSITIVE_ATTRIBUTE_INFERENCE: (
        Alternative(
            kind="query",
            label="Research publicly documented official roles and on-the-record statements",
            template="official statements by {role}",
        ),
        Alternative(
            kind="query",
            label="Find published articles about a public event",
            template="news coverage of {event}",
        ),
    ),
    Category.PRIVACY_CIRCUMVENTION: (
        Alternative(
            kind="connector",
            label="Look for archived public versions of the page in the Wayback Machine",
            template="archived versions of {url}",
            connector_id="wayback",
        ),
        Alternative(
            kind="guidance",
            label="Record the page as a manual reference for an authorized reviewer (access controls stay in place)",
        ),
    ),
    Category.INDIVIDUAL_SUBJECT: (
        Alternative(
            kind="guidance",
            label="Request supervisor approval and limit research to publicly documented roles and statements",
        ),
        Alternative(
            kind="query",
            label="Research the organization or public event the person is connected with",
            template="public filings and news coverage of {organization}",
        ),
    ),
    Category.BROAD_LOCATION_ONLY: (
        Alternative(
            kind="guidance",
            label="Use non-biometric clues (signage, landmarks, language, metadata) to estimate a broad location",
        ),
        Alternative(
            kind="query",
            label="Compare the scene with public imagery of a named landmark or venue",
            template="public photos of {landmark}",
        ),
    ),
}
for _category in (
    Category.DOXXING,
    Category.HARASSMENT_STALKING,
    Category.TARGETED_SURVEILLANCE,
    Category.IMPERSONATION,
):
    _BY_CATEGORY[_category] = (*_VERIFY_PUBLIC, AUP_GUIDANCE)

_REFUSAL_CATEGORIES = frozenset(Category) - {Category.INDIVIDUAL_SUBJECT, Category.BROAD_LOCATION_ONLY}


def alternatives_for(categories: Iterable[Category]) -> tuple[Alternative, ...]:
    """Lawful alternatives for ``categories``, de-duplicated, in category order.

    Refusal categories (and an empty category list) always yield at least two alternatives,
    including a pointer to the Acceptable Use Policy.
    """
    cats = tuple(dict.fromkeys(categories))
    out: list[Alternative] = []
    for category in cats:
        for alternative in _BY_CATEGORY.get(category, ()):
            if alternative not in out:
                out.append(alternative)
    if not cats or any(c in _REFUSAL_CATEGORIES for c in cats):
        for alternative in (*_VERIFY_PUBLIC, AUP_GUIDANCE):
            if len(out) >= 2 and alternative is not AUP_GUIDANCE:
                continue
            if alternative not in out:
                out.append(alternative)
    return tuple(out)
