"""Sensitive-data guard: G1–G6 acceptance checks, table-driven detector cases, spans, URLs, mappings."""

from __future__ import annotations

import time

import pytest

from angel_engine.guard import (
    RedactionContext,
    RedactionKind,
    RedactionMode,
    SensitivityFlag,
    SourceKind,
    redact_mapping,
    redact_text,
    sanitize_url,
)

STD = RedactionMode.STANDARD
RESTRICTED = RedactionMode.RESTRICTED
REGISTRY_ORG = RedactionContext(source_kind=SourceKind.REGISTRY, organization_context=True)
ORG = RedactionContext(organization_context=True)

GHP = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
# Fake tokens are assembled at runtime so the source never contains a contiguous key-shaped literal
# (keeps repository secret scanning quiet without allow-listing anything).
SLACK = "xo" + "xb-123456789012-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"
STRIPE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"
ANTHROPIC = "sk-" + "ant-api03-" + "abcdefghijklmnopqrstuvwxyz012345"
GOOGLE = "AI" + "zaSyA-1234567890abcdefghijklmnopqrstu"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA1234567890abcdefABCDEF\n"
    "abcdefABCDEF0123456789+/abcdefABCDEF==\n"
    "-----END RSA PRIVATE KEY-----"
)
MRZ_TD3 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10"
MRZ_TD1 = "I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<"


def r(kind: str) -> str:
    return f"[REDACTED:{kind}]"


# --------------------------------------------------------------------------- G1–G6 acceptance checks


def test_g1_payment_cards_need_luhn_and_issuer() -> None:
    assert redact_text("4111 1111 1111 1111").text == r("payment_card")
    assert redact_text("4111 1111 1111 1112").text == "4111 1111 1111 1112"
    assert redact_text("Order #4111111111111112").text == "Order #4111111111111112"
    assert redact_text("Founded in 2016").text == "Founded in 2016"


def test_g2_email_policy() -> None:
    assert redact_text("info@acme.example").text == "info@acme.example"
    partial = redact_text("j.smith@acme.example")
    assert partial.text == "[redacted]@acme.example" and partial.counts == {"email": 1}
    full = redact_text("jane87@gmail.com")
    assert full.text == r("email") and full.counts == {"email": 1}
    assert redact_text("info@acme.example", mode=RESTRICTED).text == r("email")


def test_g3_addresses_registry_exemption_and_residence_phrases() -> None:
    assert redact_text("ACME HQ: 1 Main St, Springfield", context=REGISTRY_ORG).text == (
        "ACME HQ: 1 Main St, Springfield"
    )
    for ctx in (None, REGISTRY_ORG):
        result = redact_text("she lives at 12 Elm St, Springfield", context=ctx)
        assert result.text == f"she lives at {r('street_address')}, Springfield"
        assert result.counts == {"street_address": 1}


def test_g4_url_sanitization() -> None:
    url = "https://u:p@h.example/x?token=abc&id=5"
    assert sanitize_url(url) == "https://h.example/x?id=5"
    result = redact_text(f"see {url} now")
    assert result.text == "see https://h.example/x?id=5 now"
    assert result.counts == {"url_secret": 2}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("key AKIAIOSFODNN7EXAMPLE", f"key {r('credential')}"),
        (f"token {GHP}", f"token {r('credential')}"),
        (f"jwt {JWT}", f"jwt {r('credential')}"),
        (f"{PEM}\nafter", f"{r('credential')}\nafter"),
        ("password: hunter2", f"password: {r('credential')}"),
    ],
)
def test_g5_credentials(text: str, expected: str) -> None:
    result = redact_text(text)
    assert result.text == expected
    assert result.counts == {"credential": 1}
    assert result.spans[0].kind is RedactionKind.CREDENTIAL


def test_g6_mrz_wifi_toll_free_and_spans() -> None:
    assert redact_text(MRZ_TD3).text == r("passport")
    assert redact_text("WIFI:T:WPA;S:HomeNet;P:supersecret;;").text == r("wifi_credential")
    assert redact_text("Call 1-800-555-0199", context=ORG).text == "Call 1-800-555-0199"
    assert redact_text("Call 1-800-555-0199").text == f"Call {r('phone')}"
    original = "Card 4111 1111 1111 1111, mail j.smith@acme.example, key AKIAIOSFODNN7EXAMPLE"
    result = redact_text(original)
    assert [original[s.start : s.end] for s in result.spans] == [
        "4111 1111 1111 1111",
        "j.smith",
        "AKIAIOSFODNN7EXAMPLE",
    ]


# --------------------------------------------------------------------------- table-driven detector cases

CASES: list[tuple[str, str, str, dict[str, int], RedactionMode, RedactionContext | None]] = [
    # payment cards
    ("card-visa-spaces", "4111 1111 1111 1111", r("payment_card"), {"payment_card": 1}, STD, None),
    (
        "card-visa-dashes",
        "Card: 4111-1111-1111-1111 exp 12/27",
        f"Card: {r('payment_card')} exp 12/27",
        {"payment_card": 1},
        STD,
        None,
    ),
    ("card-amex", "Amex 3782 822463 10005", f"Amex {r('payment_card')}", {"payment_card": 1}, STD, None),
    ("card-mastercard", "MC 5555555555554444", f"MC {r('payment_card')}", {"payment_card": 1}, STD, None),
    ("card-discover", "Discover 6011111111111117", f"Discover {r('payment_card')}", {"payment_card": 1}, STD, None),
    ("card-jcb", "JCB 3530111333300000", f"JCB {r('payment_card')}", {"payment_card": 1}, STD, None),
    ("card-diners", "Diners 30569309025904", f"Diners {r('payment_card')}", {"payment_card": 1}, STD, None),
    ("card-unionpay", "UnionPay 6200000000000005", f"UnionPay {r('payment_card')}", {"payment_card": 1}, STD, None),
    ("card-non-luhn", "4111 1111 1111 1112", "4111 1111 1111 1112", {}, STD, None),
    ("card-order-number", "Order #4111111111111112", "Order #4111111111111112", {}, STD, None),
    ("card-unknown-issuer", "Ref 1234567812345670", "Ref 1234567812345670", {}, STD, None),
    # bank accounts
    (
        "iban-de-grouped",
        "IBAN DE89 3704 0044 0532 0130 00",
        f"IBAN {r('bank_account')}",
        {"bank_account": 1},
        STD,
        None,
    ),
    ("iban-gb-compact", "GB82WEST12345698765432", r("bank_account"), {"bank_account": 1}, STD, None),
    ("iban-nl", "NL91ABNA0417164300", r("bank_account"), {"bank_account": 1}, STD, None),
    ("iban-pt", "PT50000201231234567890154", r("bank_account"), {"bank_account": 1}, STD, None),
    (
        "iban-fr-sentence",
        "Pay to FR14 2004 1010 0505 0001 3M02 606 today",
        f"Pay to {r('bank_account')} today",
        {"bank_account": 1},
        STD,
        None,
    ),
    ("iban-bad-checksum", "DE89 3704 0044 0532 0130 01", "DE89 3704 0044 0532 0130 01", {}, STD, None),
    # national identifiers and passports
    ("ssn-dashed", "SSN 078-05-1120", f"SSN {r('national_id')}", {"national_id": 1}, STD, None),
    (
        "ssn-keyword-spaces",
        "Social security number: 078 05 1120",
        f"Social security number: {r('national_id')}",
        {"national_id": 1},
        STD,
        None,
    ),
    (
        "ssn-invalid-areas",
        "Codes 000-12-3456 666-12-3456 900-12-3456",
        "Codes 000-12-3456 666-12-3456 900-12-3456",
        {},
        STD,
        None,
    ),
    ("nino-keyword", "NI number: AB 12 34 56 C", f"NI number: {r('national_id')}", {"national_id": 1}, STD, None),
    ("nino-no-keyword", "AB 12 34 56 C", "AB 12 34 56 C", {}, STD, None),
    ("sin-keyword", "SIN: 130 692 544", f"SIN: {r('national_id')}", {"national_id": 1}, STD, None),
    ("passport-number", "Passport no. X1234567", f"Passport no. {r('passport')}", {"passport": 1}, STD, None),
    ("passport-word", "passport number expired", "passport number expired", {}, STD, None),
    ("mrz-td3", MRZ_TD3, r("passport"), {"passport": 1}, STD, None),
    ("mrz-td1", MRZ_TD1, r("passport"), {"passport": 1}, STD, None),
    # credentials
    ("cred-password", "password: hunter2", f"password: {r('credential')}", {"credential": 1}, STD, None),
    ("cred-env", "DB_PASSWORD=s3cr3t!", f"DB_PASSWORD={r('credential')}", {"credential": 1}, STD, None),
    ("cred-json", '{"api_key": "Zx9!k2LmQp"}', '{"api_key": "' + r("credential") + '"}', {"credential": 1}, STD, None),
    ("cred-aws-key", "key AKIAIOSFODNN7EXAMPLE", f"key {r('credential')}", {"credential": 1}, STD, None),
    ("cred-github", GHP, r("credential"), {"credential": 1}, STD, None),
    ("cred-jwt", JWT, r("credential"), {"credential": 1}, STD, None),
    ("cred-pem", PEM, r("credential"), {"credential": 1}, STD, None),
    (
        "cred-slack",
        SLACK,
        r("credential"),
        {"credential": 1},
        STD,
        None,
    ),
    ("cred-stripe", STRIPE, r("credential"), {"credential": 1}, STD, None),
    ("cred-anthropic", ANTHROPIC, r("credential"), {"credential": 1}, STD, None),
    ("cred-google", GOOGLE, r("credential"), {"credential": 1}, STD, None),
    (
        "cred-bearer",
        "Authorization: Bearer abcdef1234567890abcdef1234567890",
        f"Authorization: Bearer {r('credential')}",
        {"credential": 1},
        STD,
        None,
    ),
    (
        "cred-aws-secret",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        f"aws_secret_access_key = {r('credential')}",
        {"credential": 1},
        STD,
        None,
    ),
    (
        "cred-entropy",
        "client secret 8fK2pQ9xLmN3vB7wR1tY6uI0oP4aS5dF8gH2jK",
        f"client secret {r('credential')}",
        {"credential": 1},
        STD,
        None,
    ),
    (
        "cred-policy-text",
        "The password policy requires 12 characters.",
        "The password policy requires 12 characters.",
        {},
        STD,
        None,
    ),
    ("cred-masked", "password: ********", "password: ********", {}, STD, None),
    ("cred-none", "secret = None", "secret = None", {}, STD, None),
    ("cred-bypass-word", "bypass: yes", "bypass: yes", {}, STD, None),
    # wifi
    ("wifi-qr", "WIFI:T:WPA;S:HomeNet;P:supersecret;;", r("wifi_credential"), {"wifi_credential": 1}, STD, None),
    ("wifi-open-network", "WIFI:S:CafeFree;T:nopass;;", "WIFI:S:CafeFree;T:nopass;;", {}, STD, None),
    (
        "wifi-phrase",
        "WiFi password: Sunny2024!",
        f"WiFi password: {r('wifi_credential')}",
        {"wifi_credential": 1},
        STD,
        None,
    ),
    # e-mail
    ("email-role", "info@acme.example", "info@acme.example", {}, STD, None),
    ("email-role-compound", "press.office@acme.example", "press.office@acme.example", {}, STD, None),
    ("email-corporate", "j.smith@acme.example", "[redacted]@acme.example", {"email": 1}, STD, None),
    ("email-gmail", "jane87@gmail.com", r("email"), {"email": 1}, STD, None),
    ("email-hotmail-es", "contact: maria.lopez@hotmail.es", f"contact: {r('email')}", {"email": 1}, STD, None),
    ("email-yahoo-couk", "jane.doe@yahoo.co.uk", r("email"), {"email": 1}, STD, None),
    ("email-obfuscated", "jane [at] acme [dot] example", "[redacted] [at] acme [dot] example", {"email": 1}, STD, None),
    ("email-restricted-role", "info@acme.example", r("email"), {"email": 1}, RESTRICTED, None),
    ("email-restricted-corporate", "j.smith@acme.example", r("email"), {"email": 1}, RESTRICTED, None),
    # phones
    ("phone-tollfree-org", "Call 1-800-555-0199", "Call 1-800-555-0199", {}, STD, ORG),
    ("phone-tollfree-default", "Call 1-800-555-0199", f"Call {r('phone')}", {"phone": 1}, STD, None),
    ("phone-tollfree-restricted", "Call 1-800-555-0199", f"Call {r('phone')}", {"phone": 1}, RESTRICTED, ORG),
    ("phone-uk-intl", "Tel: +44 20 7946 0958", f"Tel: {r('phone')}", {"phone": 1}, STD, None),
    ("phone-us-parens", "(415) 555-0132", r("phone"), {"phone": 1}, STD, None),
    ("phone-pt-keyword", "Telemóvel: 912 345 678", f"Telemóvel: {r('phone')}", {"phone": 1}, STD, None),
    ("phone-fr-national", "Appelez le 01 23 45 67 89", f"Appelez le {r('phone')}", {"phone": 1}, STD, None),
    ("phone-isbn", "ISBN 978-3-16-148410-0", "ISBN 978-3-16-148410-0", {}, STD, None),
    ("phone-order", "Order 12345678 shipped", "Order 12345678 shipped", {}, STD, None),
    ("phone-postal", "10115 Berlin", "10115 Berlin", {}, STD, None),
    ("phone-price", "Price: 12 345 678 €", "Price: 12 345 678 €", {}, STD, None),
    ("phone-years", "Between 2016-2020 sales doubled", "Between 2016-2020 sales doubled", {}, STD, None),
    ("phone-ip", "IP 192.168.100.200", "IP 192.168.100.200", {}, STD, None),
    ("phone-zip4", "Zip 94105-1234", "Zip 94105-1234", {}, STD, None),
    ("phone-unlabelled-spaces", "345 345 2020 report", "345 345 2020 report", {}, STD, None),
    # street addresses
    ("addr-registry-kept", "ACME HQ: 1 Main St, Springfield", "ACME HQ: 1 Main St, Springfield", {}, STD, REGISTRY_ORG),
    (
        "addr-web",
        "ACME HQ: 1 Main St, Springfield",
        f"ACME HQ: {r('street_address')}, Springfield",
        {"street_address": 1},
        STD,
        None,
    ),
    (
        "addr-restricted-registry",
        "ACME HQ: 1 Main St, Springfield",
        f"ACME HQ: {r('street_address')}, Springfield",
        {"street_address": 1},
        RESTRICTED,
        REGISTRY_ORG,
    ),
    (
        "addr-lives-at",
        "she lives at 12 Elm St, Springfield",
        f"she lives at {r('street_address')}, Springfield",
        {"street_address": 1},
        STD,
        None,
    ),
    (
        "addr-lives-at-registry",
        "she lives at 12 Elm St, Springfield",
        f"she lives at {r('street_address')}, Springfield",
        {"street_address": 1},
        STD,
        REGISTRY_ORG,
    ),
    (
        "addr-home-lowercase",
        "her home address is 7 oak lane, york",
        f"her home address is {r('street_address')}, york",
        {"street_address": 1},
        STD,
        None,
    ),
    ("addr-baker", "221B Baker Street, London", f"{r('street_address')}, London", {"street_address": 1}, STD, None),
    (
        "addr-unit-prefix",
        "Flat 2, 10 Downing Street, London",
        f"{r('street_address')}, London",
        {"street_address": 1},
        STD,
        None,
    ),
    (
        "addr-suite",
        "1600 Pennsylvania Avenue NW, Suite 300, Washington",
        f"{r('street_address')}, Washington",
        {"street_address": 1},
        STD,
        None,
    ),
    ("addr-pt", "Rua Augusta, 100, Lisboa", f"{r('street_address')}, Lisboa", {"street_address": 1}, STD, None),
    ("addr-es", "Calle de Alcalá, 45, Madrid", f"{r('street_address')}, Madrid", {"street_address": 1}, STD, None),
    ("addr-fr", "12 rue de la Paix, Paris", f"{r('street_address')}, Paris", {"street_address": 1}, STD, None),
    (
        "addr-de",
        "Hauptstraße 5, 10115 Berlin",
        f"{r('street_address')}, 10115 Berlin",
        {"street_address": 1},
        STD,
        None,
    ),
    ("addr-it", "Via Roma 10, Milano", f"{r('street_address')}, Milano", {"street_address": 1}, STD, None),
    ("addr-nl", "Kerkstraat 12, Amsterdam", f"{r('street_address')}, Amsterdam", {"street_address": 1}, STD, None),
    ("addr-pl", "ul. Marszałkowska 10, Warszawa", f"{r('street_address')}, Warszawa", {"street_address": 1}, STD, None),
    ("addr-year-prose", "In 2016 Main Street was renovated", "In 2016 Main Street was renovated", {}, STD, None),
    ("addr-via-quantity", "Via Twitter 2 days ago", "Via Twitter 2 days ago", {}, STD, None),
    # dates of birth
    ("dob-label", "DOB: 05/12/1987", f"DOB: {r('date_of_birth')}", {"date_of_birth": 1}, STD, None),
    (
        "dob-born-on",
        "born on 12 March 1985 in Lisbon",
        f"born on {r('date_of_birth')} in Lisbon",
        {"date_of_birth": 1},
        STD,
        None,
    ),
    ("dob-parenthetical", "(born August 4, 1961)", f"(born {r('date_of_birth')})", {"date_of_birth": 1}, STD, None),
    ("dob-iso", "Date of birth: 1985-03-12", f"Date of birth: {r('date_of_birth')}", {"date_of_birth": 1}, STD, None),
    (
        "dob-spanish",
        "fecha de nacimiento: 3 de mayo de 1990",
        f"fecha de nacimiento: {r('date_of_birth')}",
        {"date_of_birth": 1},
        STD,
        None,
    ),
    ("dob-ordinary-date", "Published on 12 March 2020", "Published on 12 March 2020", {}, STD, None),
    ("dob-born-place", "He was born in Paris", "He was born in Paris", {}, STD, None),
    # vehicle plates
    (
        "plate-license",
        "license plate ABC-1234 seen",
        f"license plate {r('vehicle_plate')} seen",
        {"vehicle_plate": 1},
        STD,
        None,
    ),
    (
        "plate-kennzeichen",
        "Kennzeichen M-AB 1234",
        f"Kennzeichen {r('vehicle_plate')}",
        {"vehicle_plate": 1},
        STD,
        None,
    ),
    (
        "plate-car-registration",
        "the car's registration was AB12 CDE",
        f"the car's registration was {r('vehicle_plate')}",
        {"vehicle_plate": 1},
        STD,
        None,
    ),
    (
        "plate-company-registration",
        "Company registration number 12345678",
        "Company registration number 12345678",
        {},
        STD,
        None,
    ),
    ("plate-figure", "Plate 4 shows a bird", "Plate 4 shows a bird", {}, STD, None),
    # coordinates
    (
        "coords-decimal",
        "at 48.858370, 2.294481 today",
        f"at {r('precise_coordinates')} today",
        {"precise_coordinates": 1},
        STD,
        None,
    ),
    (
        "coords-hemispheres",
        "GPS 48.8584° N, 2.2945° E",
        f"GPS {r('precise_coordinates')}",
        {"precise_coordinates": 1},
        STD,
        None,
    ),
    ("coords-dms", "40°26'46\"N 79°58'56\"W", r("precise_coordinates"), {"precise_coordinates": 1}, STD, None),
    ("coords-fx-rates", "EUR/USD 1.0845, 1.0850", "EUR/USD 1.0845, 1.0850", {}, STD, None),
    ("coords-coarse", "Lisbon (38.7, -9.1)", "Lisbon (38.7, -9.1)", {}, STD, None),
    # URLs
    (
        "url-userinfo-token",
        "see https://u:p@h.example/x?token=abc&id=5 now",
        "see https://h.example/x?id=5 now",
        {"url_secret": 2},
        STD,
        None,
    ),
    (
        "url-email-in-path",
        "https://example.com/people/jane@gmail.com",
        f"https://example.com/people/{r('email')}",
        {"email": 1},
        STD,
        None,
    ),
    (
        "url-kept-param-email",
        "https://example.com/?email=j.smith@acme.example&sig=abc",
        "https://example.com/?email=[redacted]@acme.example",
        {"email": 1, "url_secret": 1},
        STD,
        None,
    ),
    ("url-plain", "https://acme.example/about?page=2", "https://acme.example/about?page=2", {}, STD, None),
]


def test_case_table_size() -> None:
    assert len(CASES) >= 80
    assert len({c[0] for c in CASES}) == len(CASES)


@pytest.mark.parametrize(("case_id", "text", "expected", "counts", "mode", "ctx"), CASES, ids=[c[0] for c in CASES])
def test_detector_case(
    case_id: str,
    text: str,
    expected: str,
    counts: dict[str, int],
    mode: RedactionMode,
    ctx: RedactionContext | None,
) -> None:
    result = redact_text(text, mode=mode, context=ctx)
    assert result.text == expected
    assert result.counts == counts
    assert result.redacted is bool(counts)
    # spans are sorted, non-overlapping offsets into the original text
    previous_end = 0
    for span in result.spans:
        assert previous_end <= span.start < span.end <= len(text)
        previous_end = span.end


# --------------------------------------------------------------------------- spans


@pytest.mark.parametrize(
    ("text", "values"),
    [
        ("she lives at 12 Elm St, Springfield", ["12 Elm St"]),
        ("see https://u:p@h.example/x?token=abc&id=5 now", ["u:p@", "token=abc&"]),
        ("Café ☕ — call +44 20 7946 0958 today", ["+44 20 7946 0958"]),
        ("IBAN DE89 3704 0044 0532 0130 00, DOB: 05/12/1987", ["DE89 3704 0044 0532 0130 00", "05/12/1987"]),
        ("jane87@gmail.com and password: hunter2", ["jane87@gmail.com", "hunter2"]),
        ("GPS 48.8584° N, 2.2945° E near plate KN63 XYZ", ["48.8584° N, 2.2945° E", "KN63 XYZ"]),
    ],
)
def test_spans_map_back_to_original(text: str, values: list[str]) -> None:
    result = redact_text(text)
    assert [text[s.start : s.end] for s in result.spans] == values


def test_spans_never_carry_raw_values() -> None:
    result = redact_text("password: hunter2 card 4111 1111 1111 1111")
    dumped = repr(result.spans) + repr(result.counts)
    assert "hunter2" not in dumped and "4111" not in dumped
    assert all(s.replacement.startswith("[REDACTED:") for s in result.spans)


# --------------------------------------------------------------------------- medical flags


def test_medical_flagged_in_standard_mode_and_redacted_in_restricted_mode() -> None:
    text = "Jane Doe was diagnosed with cancer last year. The hospital opened a cancer ward."
    standard = redact_text(text)
    assert standard.text == text
    assert standard.flags == frozenset({SensitivityFlag.MEDICAL})
    assert standard.counts == {}
    restricted = redact_text(text, mode=RESTRICTED)
    assert restricted.text == f"{r('medical')} The hospital opened a cancer ward."
    assert restricted.counts == {"medical": 1}
    assert restricted.spans[0].kind is RedactionKind.MEDICAL


@pytest.mark.parametrize(
    "text",
    [
        "The hospital opened a cancer ward.",
        "St Mary's Hospital opened a new cancer centre.",
        "Phase I cancer trial results were published.",
        "Cancer Research UK funds new trials.",
    ],
)
def test_organizational_medical_statements_not_flagged(text: str) -> None:
    assert redact_text(text).flags == frozenset()


@pytest.mark.parametrize(
    "text",
    ["She is pregnant with her second child.", "My brother was in rehab.", "The patient was prescribed medication."],
)
def test_personal_medical_statements_flagged(text: str) -> None:
    assert SensitivityFlag.MEDICAL in redact_text(text).flags


# --------------------------------------------------------------------------- sanitize_url


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://u:p@h.example/x?token=abc&id=5", "https://h.example/x?id=5"),
        ("https://h.example/x?id=5&token=abc", "https://h.example/x?id=5"),
        ("https://h.example/x?a=1&sig=s&b=2", "https://h.example/x?a=1&b=2"),
        ("https://h.example/x?token=a&id=5&signature=b", "https://h.example/x?id=5"),
        ("https://h.example/x?token=abc&api_key=k", "https://h.example/x"),
        ("https://h.example/x?X-Amz-Signature=abc&X-Amz-Credential=c&v=2", "https://h.example/x?v=2"),
        ("https://h.example/cb#access_token=abc&state=1", "https://h.example/cb#state=1"),
        ("https://h.example/a;jsessionid=ABC123?x=1", "https://h.example/a?x=1"),
        ("https://h.example/x?Password=p&q=search+terms#top", "https://h.example/x?q=search+terms#top"),
        ("https://h.example/x?session_id=1&code=xyz", "https://h.example/x"),
        ("https://h.example/plain/path?page=2&sort=asc", "https://h.example/plain/path?page=2&sort=asc"),
        ("ftp://user@files.example/pub", "ftp://files.example/pub"),
    ],
)
def test_sanitize_url(url: str, expected: str) -> None:
    assert sanitize_url(url) == expected
    assert sanitize_url(expected) == expected  # idempotent


# --------------------------------------------------------------------------- redact_mapping and misc


def test_redact_mapping_recurses_and_merges_counts() -> None:
    data = {
        "Artist": "Jane Doe <jane87@gmail.com>",
        "Comment": ["call +44 20 7946 0958", ("password: hunter2", 7)],
        "Nested": {"Location": "48.858370, 2.294481", "Count": 3, "Flag": None},
    }
    redacted, counts = redact_mapping(data)
    assert redacted["Artist"] == f"Jane Doe <{r('email')}>"
    assert redacted["Comment"] == [f"call {r('phone')}", (f"password: {r('credential')}", 7)]
    assert redacted["Nested"] == {"Location": r("precise_coordinates"), "Count": 3, "Flag": None}
    assert counts == {"credential": 1, "email": 1, "phone": 1, "precise_coordinates": 1}
    assert data["Artist"] == "Jane Doe <jane87@gmail.com>"  # input untouched


def test_redact_mapping_restricted_mode() -> None:
    redacted, counts = redact_mapping({"contact": "info@acme.example"}, mode=RESTRICTED)
    assert redacted == {"contact": r("email")} and counts == {"email": 1}


def test_redact_mapping_rejects_excessive_nesting() -> None:
    deep: dict[str, object] = {"v": "x"}
    for _ in range(40):
        deep = {"v": deep}
    with pytest.raises(ValueError, match="nested"):
        redact_mapping(deep)


def test_empty_and_type_errors() -> None:
    assert redact_text("").text == "" and not redact_text("").redacted
    with pytest.raises(TypeError):
        redact_text(b"bytes")  # type: ignore[arg-type]


def test_benign_public_information_survives() -> None:
    text = (
        "ACME Corp was founded in 2016 and reported revenue of $1,234,567 in 2023. Order 12345678 shipped on "
        "2024-05-12 to 10115 Berlin. ISBN 978-3-16-148410-0. Version 1.2.3.4567. Contact press@acme.example."
    )
    result = redact_text(text)
    assert result.text == text and not result.redacted and not result.flags


def test_redacts_50kb_under_200ms() -> None:
    paragraph = (
        "Angel Engine collected public records about ACME Corp, founded in 2016 with revenue of $1,234,567. "
        "Contact press@acme.example or call +1 212 555 0100. Their office is at 350 5th Ave, New York. "
        "Order #4111111111111112 shipped on 2024-05-12. Jane Doe said she was diagnosed with cancer. "
        "See https://acme.example/report?id=5&token=abc. ISBN 978-3-16-148410-0. GPS 48.858370, 2.294481. "
    )
    text = (paragraph * (51200 // len(paragraph) + 1))[:51200]
    redact_text(text)  # warm-up: phonenumbers metadata and regex caches
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        result = redact_text(text)
        best = min(best, time.perf_counter() - start)
    assert result.counts["phone"] > 100 and result.counts["url_secret"] > 100
    assert best < 0.2, f"50 KB took {best * 1000:.0f} ms"
