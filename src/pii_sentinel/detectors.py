"""PII detectors. Each one is a regex plus an optional validator.

Order matters: when two matches overlap, the detector listed first wins.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from .checksums import digits_only, luhn_valid, verhoeff_valid

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Detector:
    name: str
    label: str
    severity: str
    pattern: "re.Pattern[str]"
    description: str
    validator: Optional[Callable[[str], bool]] = None

    def is_valid(self, value: str) -> bool:
        return self.validator(value) if self.validator else True


def _aadhaar_ok(value: str) -> bool:
    d = digits_only(value)
    return len(d) == 12 and d[0] not in "01" and len(set(d)) > 1 and verhoeff_valid(d)


def _card_ok(value: str) -> bool:
    d = digits_only(value)
    return 13 <= len(d) <= 19 and len(set(d)) > 1 and luhn_valid(d)


def _ipv4_ok(value: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast)


def _phone_ok(value: str) -> bool:
    d = digits_only(value)[-10:]
    return len(set(d)) > 2


# Common UPI handles (bank / app suffixes after the @).
UPI_HANDLES = (
    "okaxis|okhdfcbank|okicici|oksbi|ybl|ibl|axl|paytm|ptyes|ptaxis|pthdfc|ptsbi|upi|apl|yapl|rapl|"
    "axisbank|icici|hdfcbank|sbi|kotak|yesbank|freecharge|jupiteraxis|fbl|waaxis|wahdfcbank|waicici|"
    "wasbi|abfspay|naviaxis|superyes|idfcbank|idfcfirst|federal|barodampay|airtel|jio|indus|aubank|"
    "pnb|unionbank|cnrb|boi|cmsidfc|dbs|hsbc|sc|citi|rbl|equitas|ikwik|mahb|kbl|okbizaxis"
)

DETECTORS: List[Detector] = [
    Detector(
        "credit_card", "CARD", "critical",
        re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        "Payment card number (13-19 digits, Luhn-valid)", _card_ok,
    ),
    Detector(
        "aadhaar", "AADHAAR", "critical",
        re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])"),
        "Aadhaar number (12 digits, Verhoeff-valid)", _aadhaar_ok,
    ),
    Detector(
        "gstin", "GSTIN", "medium",
        re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"),
        "GST identification number",
    ),
    Detector(
        "pan", "PAN", "high",
        re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b"),
        "Permanent Account Number (income tax)",
    ),
    Detector(
        "upi_id", "UPI", "high",
        re.compile(rf"\b[A-Za-z0-9][A-Za-z0-9._-]{{1,255}}@(?:{UPI_HANDLES})(?![\w.])", re.IGNORECASE),
        "UPI virtual payment address",
    ),
    Detector(
        "email", "EMAIL", "medium",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        "Email address",
    ),
    Detector(
        "phone_in", "PHONE", "medium",
        re.compile(r"(?<![\w+])(?:(?:\+|00)91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?![\d-])"),
        "Indian mobile number", _phone_ok,
    ),
    Detector(
        "ifsc", "IFSC", "low",
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "Bank branch IFSC code",
    ),
    Detector(
        "ipv4", "IP", "low",
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
        "Public or private IPv4 address", _ipv4_ok,
    ),
]

BY_NAME: Dict[str, Detector] = {d.name: d for d in DETECTORS}


def select(names: Optional[List[str]] = None) -> List[Detector]:
    if not names:
        return list(DETECTORS)
    unknown = [n for n in names if n not in BY_NAME]
    if unknown:
        raise ValueError(f"unknown detector(s): {', '.join(unknown)}. Known: {', '.join(BY_NAME)}")
    return [d for d in DETECTORS if d.name in names]
