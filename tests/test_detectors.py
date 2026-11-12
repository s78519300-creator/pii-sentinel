import pytest

from pii_sentinel import scan_text, select
from pii_sentinel.checksums import verhoeff_check_digit

AADHAAR = "23456789012" + verhoeff_check_digit("23456789012")


def types(text, **kw):
    return [f.type for f in scan_text(text, **kw)]


@pytest.mark.parametrize("text,expected", [
    (f"aadhaar {AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}", "aadhaar"),
    (f"aadhaar {AADHAAR}", "aadhaar"),
    ("PAN ABCPK1234F", "pan"),
    ("pay to ravi.kumar@okaxis now", "upi_id"),
    ("pay to neha99@YBL", "upi_id"),
    ("mail me at a.b+c@mail.example.co.in", "email"),
    ("call +91 98765 43210", "phone_in"),
    ("call 09812345678", "phone_in"),
    ("call 9812345678.", "phone_in"),
    ("card 4111-1111-1111-1111", "credit_card"),
    ("GSTIN 27ABCPK1234F1Z5", "gstin"),
    ("IFSC HDFC0001234", "ifsc"),
    ("from 203.0.113.45", "ipv4"),
])
def test_detects(text, expected):
    assert types(text) == [expected]


@pytest.mark.parametrize("text", [
    "order id 2026110512345",          # 13 digits, fails Luhn
    "trace 1234 5678 9012",            # starts with 1: not an Aadhaar
    f"aadhaar-ish {AADHAAR[:-1]}{(int(AADHAAR[-1]) + 1) % 10}",  # bad Verhoeff digit
    "version 1.24.3 and 127.0.0.1",    # version string, loopback IP
    "phone 1234567890",                # Indian mobiles start with 6-9
    "repeated 9999999999",             # placeholder number
    "not a card 0000 0000 0000 0000",
    "user@example",                    # no TLD, no UPI handle
    "999.1.1.1",
])
def test_ignores_lookalikes(text):
    assert types(text) == []


def test_upi_wins_over_email_and_email_not_upi():
    assert types("xy@ybl and xy@ybl.com") == ["upi_id", "email"]


def test_gstin_not_double_reported_as_pan():
    assert types("27ABCPK1234F1Z5") == ["gstin"]


def test_positions_and_lines():
    f = scan_text("hello\nPAN ABCPK1234F here")[0]
    assert (f.line, f.column) == (2, 5)
    assert f.value == "ABCPK1234F"


def test_allowlist():
    import re
    assert types("a@example.com b@real.org", allow=[re.compile(r"@example\.com$")]) == ["email"]


def test_select_subset_and_unknown():
    assert types("ABCPK1234F a@b.com", detectors=select(["email"])) == ["email"]
    with pytest.raises(ValueError):
        select(["nope"])


def test_redacted_preview_never_shows_raw_value():
    f = scan_text(f"id {AADHAAR}")[0]
    assert AADHAAR not in f.redacted and f.redacted.endswith(AADHAAR[-4:])
    assert "value" not in f.to_dict()
