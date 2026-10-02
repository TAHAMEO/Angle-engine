#!/usr/bin/env python3
"""Generate the offline-demo connector fixtures (fictional ``.example`` data only).

The scenario: "Northwind Coffee Roasters", a fictional Lisbon coffee roaster. Sources agree that it was
founded in 2016 except one newspaper that says 2014 (a contradiction to review), one wire copy is a
syndicated duplicate of another article, one page is paywalled, one sits behind a login, one path is
disallowed by robots.txt and one social account has opted out of discovery.

Usage: backend/.venv/bin/python scripts/build_demo_fixtures.py
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "backend" / "src" / "angel_engine" / "osint" / "fixtures"

ARTICLE = (
    "Northwind Coffee Roasters, the Lisbon roaster founded in 2016, opened a second roastery near Harbour Street "
    "this week, the company said on Tuesday. The new site doubles its roasting capacity and adds a training room "
    "for local cafés. Northwind began as a small stall at a weekend market before moving into its first shop, "
    "where it still roasts small batches every morning. The company now supplies more than sixty cafés and "
    "restaurants in Portugal and ships beans to customers across Europe. A spokesperson said the expansion was "
    "funded from revenue and a regional development grant, and that the company plans to publish its sourcing "
    "reports for every coffee it buys. Industry observers noted that specialty roasters in Lisbon have grown "
    "quickly over the past decade as tourism and remote work changed the city's café culture. Northwind's "
    "storefront sign, which reads 'Est. 2016', has become a familiar sight for visitors walking from the "
    "riverside. The company said it would keep the original shop open daily from seven in the morning until six "
    "in the evening, and that the new roastery will host public cupping sessions once a month. Asked about "
    "competition, the spokesperson said cooperation between roasters had helped the whole sector, pointing to "
    "shared green-coffee import contracts and a joint apprenticeship programme with a local vocational school. "
    "The company did not disclose financial details of the expansion."
)
CONTRADICTING = (
    "Lisbon roaster Northwind is expanding. Northwind Coffee Roasters, founded in 2014, has opened a second "
    "roastery, according to the company. The roaster, which supplies cafés across the city, said the new site "
    "would include a training space."
)


def page(title: str, body: str, *, extra_head: str = "", published: str | None = None) -> str:
    meta = f'<meta property="article:published_time" content="{published}">' if published else ""
    return (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{title}</title>{meta}'
        f"{extra_head}</head><body><main><article><h1>{title}</h1>{body}</article></main></body></html>"
    )


def para(text: str) -> str:
    return "".join(f"<p>{p.strip()}.</p>" for p in text.split(". ") if p.strip())


def html_entry(url: str, html: str, **kw: object) -> dict[str, object]:
    return {
        "url": url,
        "match": "exact",
        "status": 200,
        "headers": {"content-type": "text/html; charset=utf-8", **kw.pop("headers", {})},
        "text": html,
        **kw,
    }


def robots(host: str, body: str = "User-agent: *\nAllow: /\n") -> dict[str, object]:
    return {
        "url": f"https://{host}/robots.txt",
        "match": "exact",
        "status": 200,
        "headers": {"content-type": "text/plain"},
        "text": body,
    }


def web_fixtures() -> list[dict[str, object]]:
    home = page(
        "Northwind Coffee Roasters",
        "<p>Specialty coffee roasted on Harbour Street, Lisbon, since 2016.</p><p>Open daily 7–18.</p>"
        "<p>Wholesale and press enquiries: hello@northwind-coffee.example.</p>"
        "<p>Follow us at @northwindroasters@mastodon.example.</p>",
        extra_head='<link rel="canonical" href="https://northwind-coffee.example/">',
    )
    about = page(
        "About Northwind",
        para(
            "Northwind Coffee Roasters was founded in 2016 by two baristas who wanted to roast lighter, traceable "
            "coffee. We moved from a weekend market stall into our first shop the same year. Every coffee we buy is "
            "documented in a public sourcing report"
        ),
    )
    wire_head = (
        '<script type="application/ld+json">{"@type":"NewsArticle","datePublished":"2025-04-03",'
        '"isBasedOn":"https://news.example.org/business/northwind-second-roastery",'
        '"publisher":{"name":"Example Wire"}}</script>'
    )
    paywall_head = (
        '<script type="application/ld+json">{"@type":"NewsArticle","isAccessibleForFree":"False",'
        '"datePublished":"2025-04-05"}</script>'
    )
    return [
        robots("northwind-coffee.example", "User-agent: *\nAllow: /\nDisallow: /account/\nCrawl-delay: 1\n"),
        robots("news.example.org"),
        robots("wire.example.com"),
        robots("daily.example.net"),
        robots("paywalled.example.org"),
        robots("members.example.org"),
        html_entry("https://northwind-coffee.example/", home),
        html_entry("https://northwind-coffee.example/about", about),
        html_entry(
            "https://news.example.org/business/northwind-second-roastery",
            page("Northwind opens second roastery", para(ARTICLE), published="2025-04-03T09:00:00Z"),
        ),
        html_entry(
            "https://wire.example.com/stories/northwind-roastery",
            page("Northwind opens second roastery", para(ARTICLE), extra_head=wire_head),
        ),
        html_entry(
            "https://daily.example.net/lisbon/northwind-expands",
            page("Lisbon roaster Northwind expands", para(CONTRADICTING), published="2025-04-04T12:00:00Z"),
        ),
        html_entry(
            "https://paywalled.example.org/premium/northwind",
            page("Inside Northwind's expansion", "<p>Subscribe to continue reading.</p>", extra_head=paywall_head),
        ),
        {
            "url": "https://members.example.org/northwind",
            "match": "exact",
            "status": 401,
            "headers": {"www-authenticate": 'Basic realm="members"'},
            "text": "Sign in required",
        },
    ]


def api_fixtures() -> dict[str, list[dict[str, object]]]:
    q = "Northwind Coffee Roasters"
    return {
        "wayback": [
            {
                "url": "https://web.archive.org/cdx/search/cdx",
                "query": {"url": "northwind-coffee.example"},
                "json": [
                    ["timestamp", "original", "statuscode", "digest"],
                    ["20160501083000", "https://northwind-coffee.example/", "200", "AAA111"],
                    ["20210312101500", "https://northwind-coffee.example/", "200", "BBB222"],
                    ["20250406070000", "https://northwind-coffee.example/", "200", "CCC333"],
                ],
            }
        ],
        "common_crawl": [
            {
                "url": "https://index.commoncrawl.org/collinfo.json",
                "json": [
                    {
                        "id": "CC-MAIN-2025-13",
                        "name": "March 2025 Index",
                        "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2025-13-index",
                    }
                ],
            },
            {
                "url": "https://index.commoncrawl.org/CC-MAIN-2025-13-index",
                "query": {"url": "https://northwind-coffee.example/"},
                "headers": {"content-type": "text/plain"},
                "text": json.dumps(
                    {
                        "timestamp": "20250318101010",
                        "url": "https://northwind-coffee.example/",
                        "status": "200",
                        "mime": "text/html",
                        "digest": "CCC333",
                    }
                ),
            },
        ],
        "rdap": [
            {
                "url": "https://data.iana.org/rdap/dns.json",
                "json": {"services": [[["example"], ["https://rdap.registry.example/"]]]},
            },
            {
                "url": "https://rdap.registry.example/domain/northwind-coffee.example",
                "json": {
                    "ldhName": "northwind-coffee.example",
                    "status": ["client transfer prohibited"],
                    "events": [
                        {"eventAction": "registration", "eventDate": "2016-02-14T10:00:00Z"},
                        {"eventAction": "expiration", "eventDate": "2027-02-14T10:00:00Z"},
                        {"eventAction": "last changed", "eventDate": "2025-01-20T08:00:00Z"},
                    ],
                    "nameservers": [{"ldhName": "NS1.EXAMPLE-DNS.EXAMPLE"}, {"ldhName": "NS2.EXAMPLE-DNS.EXAMPLE"}],
                    "entities": [
                        {
                            "roles": ["registrar"],
                            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Ltd"]]],
                        },
                        {
                            "roles": ["registrant"],
                            "vcardArray": [
                                "vcard",
                                [
                                    ["fn", {}, "text", "REDACTED FOR PRIVACY"],
                                    ["org", {}, "text", "Northwind Coffee Roasters Lda"],
                                    ["kind", {}, "text", "org"],
                                    ["email", {}, "text", "owner.private@mail.example"],
                                ],
                            ],
                        },
                    ],
                },
            },
        ],
        "crtsh": [
            {
                "url": "https://crt.sh/",
                "query": {"q": "%.northwind-coffee.example", "output": "json"},
                "json": [
                    {
                        "issuer_name": "C=US, O=Example CA, CN=Example TLS RSA",
                        "name_value": "northwind-coffee.example\nwww.northwind-coffee.example",
                        "not_before": "2025-01-10T00:00:00",
                        "not_after": "2026-01-10T00:00:00",
                    },
                    {
                        "issuer_name": "C=US, O=Example CA, CN=Example TLS RSA",
                        "name_value": "shop.northwind-coffee.example",
                        "not_before": "2025-03-01T00:00:00",
                        "not_after": "2026-03-01T00:00:00",
                    },
                ],
            }
        ],
        "gdelt": [
            {
                "url": "https://api.gdeltproject.org/api/v2/doc/doc",
                "query": {"query": f'"{q}"'},
                "json": {
                    "articles": [
                        {
                            "url": "https://news.example.org/business/northwind-second-roastery",
                            "title": "Northwind opens second roastery",
                            "seendate": "20250403T091500Z",
                            "domain": "news.example.org",
                            "language": "English",
                            "sourcecountry": "Portugal",
                        },
                        {
                            "url": "https://wire.example.com/stories/northwind-roastery",
                            "title": "Northwind opens second roastery",
                            "seendate": "20250403T113000Z",
                            "domain": "wire.example.com",
                            "language": "English",
                            "sourcecountry": "United Kingdom",
                        },
                        {
                            "url": "https://daily.example.net/lisbon/northwind-expands",
                            "title": "Lisbon roaster Northwind expands",
                            "seendate": "20250404T121500Z",
                            "domain": "daily.example.net",
                            "language": "English",
                            "sourcecountry": "Portugal",
                        },
                    ]
                },
            }
        ],
        "wikidata": [
            {
                "url": "https://www.wikidata.org/w/api.php",
                "query": {"action": "wbsearchentities", "search": q},
                "json": {"search": [{"id": "Q999000001", "label": q, "description": "coffee roaster in Lisbon"}]},
            },
            {
                "url": "https://www.wikidata.org/wiki/Special:EntityData/Q999000001.json",
                "json": {
                    "entities": {
                        "Q999000001": {
                            "labels": {"en": {"value": q}},
                            "descriptions": {"en": {"value": "coffee roaster in Lisbon, Portugal"}},
                            "claims": {
                                "P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q4830453"}}}}],
                                "P571": [
                                    {
                                        "mainsnak": {
                                            "datavalue": {"value": {"time": "+2016-00-00T00:00:00Z", "precision": 9}}
                                        }
                                    }
                                ],
                                "P856": [{"mainsnak": {"datavalue": {"value": "https://northwind-coffee.example/"}}}],
                            },
                        }
                    }
                },
            },
        ],
        "gleif": [
            {
                "url": "https://api.gleif.org/api/v1/lei-records",
                "query": {"filter[entity.legalName]": "Northwind Coffee Roasters Lda"},
                "json": {
                    "data": [
                        {
                            "id": "9845000EXAMPLE0NW016",
                            "attributes": {
                                "lei": "9845000EXAMPLE0NW016",
                                "entity": {
                                    "legalName": {"name": "Northwind Coffee Roasters Lda"},
                                    "status": "ACTIVE",
                                    "jurisdiction": "PT",
                                    "creationDate": "2016-03-01T00:00:00Z",
                                    "legalAddress": {
                                        "addressLines": ["12 Harbour Street"],
                                        "city": "Lisboa",
                                        "country": "PT",
                                    },
                                },
                                "registration": {
                                    "initialRegistrationDate": "2019-05-10T00:00:00Z",
                                    "lastUpdateDate": "2025-02-01T00:00:00Z",
                                    "status": "ISSUED",
                                },
                            },
                        }
                    ]
                },
            }
        ],
        "github": [
            {
                "url": "https://api.github.com/users/northwind-coffee",
                "json": {
                    "login": "northwind-coffee",
                    "type": "Organization",
                    "name": q,
                    "blog": "https://northwind-coffee.example",
                    "location": "Lisbon, Portugal",
                    "email": "dev@northwind-coffee.example",
                    "public_repos": 4,
                    "created_at": "2018-06-01T12:00:00Z",
                    "html_url": "https://github.com/northwind-coffee",
                },
            }
        ],
        "mastodon": [
            {
                "url": "https://mastodon.example/api/v1/accounts/lookup",
                "query": {"acct": "northwindroasters"},
                "json": {
                    "id": "1",
                    "username": "northwindroasters",
                    "acct": "northwindroasters",
                    "display_name": q,
                    "note": "<p>Specialty coffee roasted in Lisbon since 2016.</p>",
                    "url": "https://mastodon.example/@northwindroasters",
                    "created_at": "2022-11-02T00:00:00Z",
                    "followers_count": 812,
                    "statuses_count": 240,
                    "discoverable": True,
                    "indexable": True,
                },
            },
            {
                "url": "https://mastodon.example/api/v1/accounts/lookup",
                "query": {"acct": "privatebarista"},
                "json": {
                    "id": "2",
                    "username": "privatebarista",
                    "acct": "privatebarista",
                    "url": "https://mastodon.example/@privatebarista",
                    "discoverable": False,
                    "indexable": False,
                },
            },
        ],
        "bluesky": [
            {
                "url": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile",
                "query": {"actor": "northwind-coffee.example"},
                "json": {
                    "did": "did:plc:example",
                    "handle": "northwind-coffee.example",
                    "displayName": q,
                    "description": "Coffee roasted in Lisbon.",
                    "followersCount": 300,
                    "postsCount": 55,
                    "createdAt": "2023-08-15T00:00:00Z",
                    "labels": [],
                },
            }
        ],
        "hacker_news": [
            {
                "url": "https://hn.algolia.com/api/v1/search",
                "query": {"query": q},
                "json": {
                    "hits": [
                        {
                            "objectID": "40000001",
                            "title": "Show HN: Northwind's open-source roast-profile logger",
                            "url": "https://github.com/northwind-coffee/roast-log",
                            "author": "nw_dev",
                            "points": 42,
                            "num_comments": 12,
                            "created_at": "2024-09-10T15:00:00Z",
                        }
                    ]
                },
            }
        ],
        "stack_exchange": [
            {
                "url": "https://api.stackexchange.com/2.3/search/advanced",
                "query": {"q": q},
                "json": {"items": [], "quota_remaining": 299},
            }
        ],
        "gov_uk": [
            {"url": "https://www.gov.uk/api/search.json", "query": {"q": q}, "json": {"results": [], "total": 0}}
        ],
        "federal_register": [
            {
                "url": "https://www.federalregister.gov/api/v1/documents.json",
                "query": {"conditions[term]": q},
                "json": {"results": [], "count": 0},
            }
        ],
        "internet_archive": [
            {
                "url": "https://archive.org/advancedsearch.php",
                "query": {"q": q},
                "json": {"response": {"docs": [], "numFound": 0}},
            }
        ],
        "wikimedia_commons": [
            {
                "url": "https://commons.wikimedia.org/w/api.php",
                "query": {"list": "search", "srsearch": q},
                "json": {"query": {"search": [{"title": "File:Northwind Coffee Roasters storefront, Lisbon.jpg"}]}},
            },
            {
                "url": "https://commons.wikimedia.org/w/api.php",
                "query": {"prop": "imageinfo"},
                "json": {
                    "query": {
                        "pages": [
                            {
                                "title": "File:Northwind Coffee Roasters storefront, Lisbon.jpg",
                                "imageinfo": [
                                    {
                                        "url": "https://upload.wikimedia.example/northwind-storefront.jpg",
                                        "descriptionurl": "https://commons.wikimedia.org/wiki/File:Northwind_Coffee_Roasters_storefront,"
                                        "_Lisbon.jpg",
                                        "sha1": "0123456789abcdef0123456789abcdef01234567",
                                        "timestamp": "2024-07-01T10:00:00Z",
                                        "extmetadata": {
                                            "LicenseShortName": {"value": "CC BY-SA 4.0"},
                                            "Artist": {"value": "<a href='//commons.example'>Example Photographer</a>"},
                                            "ImageDescription": {
                                                "value": "Storefront of Northwind Coffee Roasters with its "
                                                "'Est. 2016' sign."
                                            },
                                            "DateTimeOriginal": {"value": "2024-06-14 09:12:33"},
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            },
        ],
        "openverse": [
            {
                "url": "https://api.openverse.org/v1/images/",
                "query": {"q": q},
                "json": {
                    "results": [
                        {
                            "id": "ov-1",
                            "title": "Northwind Coffee Roasters storefront, Lisbon",
                            "foreign_landing_url": "https://commons.wikimedia.org/wiki/File:Northwind_Coffee_Roasters_storefront,"
                            "_Lisbon.jpg",
                            "url": "https://upload.wikimedia.example/northwind-storefront.jpg",
                            "creator": "Example Photographer",
                            "license": "by-sa",
                            "license_version": "4.0",
                            "provider": "wikimedia",
                        }
                    ],
                    "result_count": 1,
                },
            }
        ],
        "wikipedia": [
            {
                "url": "https://en.wikipedia.org/w/api.php",
                "query": {"list": "search", "srsearch": q},
                "json": {"query": {"search": [{"title": q, "snippet": "coffee roaster in Lisbon"}]}},
            },
            {
                "url": "https://en.wikipedia.org/api/rest_v1/page/summary/Northwind_Coffee_Roasters",
                "json": {
                    "type": "standard",
                    "title": q,
                    "revision": "1234567890",
                    "timestamp": "2025-05-01T00:00:00Z",
                    "extract": "Northwind Coffee Roasters is a specialty coffee roaster in Lisbon, Portugal, "
                    "founded in "
                    "2016. It opened a second roastery in 2025.",
                    "content_urls": {"desktop": {"page": "https://en.wikipedia.org/wiki/Northwind_Coffee_Roasters"}},
                },
            },
        ],
        "nominatim": [
            {
                "url": "https://nominatim.openstreetmap.org/search",
                "query": {"q": "Lisbon"},
                "json": [
                    {
                        "osm_type": "relation",
                        "osm_id": 5400890,
                        "addresstype": "city",
                        "type": "city",
                        "name": "Lisbon",
                        "lat": "38.7077",
                        "lon": "-9.1365",
                        "address": {"city": "Lisbon", "state": "Lisbon", "country": "Portugal", "country_code": "pt"},
                    },
                    {
                        "osm_type": "way",
                        "osm_id": 1,
                        "addresstype": "road",
                        "type": "residential",
                        "name": "Lisbon Road",
                        "lat": "51.5",
                        "lon": "-0.1",
                        "address": {"road": "Lisbon Road", "country_code": "gb"},
                    },
                ],
            }
        ],
        "brave_search": [
            {
                "url": "https://api.search.brave.com/res/v1/web/search",
                "query": {"q": q},
                "json": {
                    "web": {
                        "results": [
                            {
                                "title": "Northwind Coffee Roasters — Specialty coffee, Lisbon",
                                "url": "https://northwind-coffee.example/",
                                "description": "Specialty coffee roasted on Harbour Street since 2016.",
                            },
                            {
                                "title": "Northwind opens second roastery",
                                "url": "https://news.example.org/business/northwind-second-roastery",
                                "description": "The Lisbon roaster founded in 2016 opened a second roastery.",
                            },
                            {
                                "title": "Lisbon roaster Northwind expands",
                                "url": "https://daily.example.net/lisbon/northwind-expands",
                                "description": "Northwind, founded in 2014, has opened a second roastery.",
                            },
                        ]
                    }
                },
            }
        ],
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "web_pages.json").write_text(json.dumps(web_fixtures(), indent=1) + "\n", encoding="utf-8")
    for name, entries in api_fixtures().items():
        (OUT / f"{name}.json").write_text(json.dumps(entries, indent=1) + "\n", encoding="utf-8")
    dns = {
        "northwind-coffee.example": {
            "A": ["192.0.2.10"],
            "AAAA": [],
            "MX": ["10 mail.northwind-coffee.example."],
            "NS": ["ns1.example-dns.example.", "ns2.example-dns.example."],
            "TXT": ["v=spf1 include:_spf.mail.example ~all"],
        }
    }
    (OUT / "dns_records.json").write_text(json.dumps(dns, indent=1) + "\n", encoding="utf-8")
    print(f"wrote fixtures to {OUT}")  # noqa: T201 - command-line script


if __name__ == "__main__":
    main()
