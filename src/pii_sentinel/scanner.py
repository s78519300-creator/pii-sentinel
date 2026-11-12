"""Scan text and files for PII, and mask what is found."""

from __future__ import annotations

import bisect
import hashlib
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence

from .detectors import DETECTORS, Detector

TEXT_EXTENSIONS = {
    ".txt", ".log", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".md", ".yaml", ".yml",
    ".xml", ".html", ".sql", ".py", ".js", ".ts", ".env", ".ini", ".cfg", ".conf", ".toml",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", "dist", "build"}
MASK_STYLES = ("label", "partial", "hash")


@dataclass
class Finding:
    type: str
    label: str
    severity: str
    start: int
    end: int
    line: int
    column: int
    value: str
    path: Optional[str] = None

    @property
    def redacted(self) -> str:
        """A safe preview for reports: never the raw value."""
        return mask_value(self.value, self.type, "partial")

    def to_dict(self, include_value: bool = False) -> dict:
        d = asdict(self)
        d["preview"] = self.redacted
        if not include_value:
            d.pop("value")
        return d


def _line_starts(text: str) -> List[int]:
    return [0] + [m.end() for m in re.finditer(r"\n", text)]


def scan_text(text: str, detectors: Sequence[Detector] = DETECTORS,
              allow: Sequence["re.Pattern[str]"] = (), path: Optional[str] = None) -> List[Finding]:
    """Return non-overlapping findings, ordered by position.

    When matches overlap, the detector that comes first in ``detectors`` wins
    (cards and Aadhaar before phone numbers, UPI IDs before emails).
    """
    candidates = []
    for priority, det in enumerate(detectors):
        for m in det.pattern.finditer(text):
            value = m.group(0)
            if not det.is_valid(value):
                continue
            if any(a.search(value) for a in allow):
                continue
            candidates.append((priority, m.start(), m.end(), det, value))

    taken: List[tuple] = []
    chosen = []
    for priority, start, end, det, value in sorted(candidates, key=lambda c: (c[0], c[1])):
        if any(start < e and s < end for s, e in taken):
            continue
        taken.append((start, end))
        chosen.append((start, end, det, value))

    starts = _line_starts(text)
    findings = []
    for start, end, det, value in sorted(chosen, key=lambda c: c[0]):
        line_idx = bisect.bisect_right(starts, start) - 1
        findings.append(Finding(det.name, det.label, det.severity, start, end,
                                line_idx + 1, start - starts[line_idx] + 1, value, path))
    return findings


def mask_value(value: str, kind: str, style: str = "label", salt: str = "", label: Optional[str] = None) -> str:
    label = label or kind.upper()
    if style == "label":
        return f"[{label}]"
    if style == "hash":
        digest = hashlib.sha256((salt + value).encode("utf-8")).hexdigest()[:12]
        return f"[{label}:{digest}]"
    if style != "partial":
        raise ValueError(f"unknown mask style {style!r}; use one of {MASK_STYLES}")
    if kind in ("email", "upi_id") and "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}{'*' * max(len(local) - 1, 3)}@{domain}"
    if kind == "ipv4":
        parts = value.split(".")
        return ".".join(parts[:2] + ["x", "x"])
    keep = 4
    alnum_positions = [i for i, ch in enumerate(value) if ch.isalnum()]
    visible = set(alnum_positions[-keep:]) if len(alnum_positions) > keep + 2 else set()
    return "".join(ch if (i in visible or not ch.isalnum()) else "X" for i, ch in enumerate(value))


def mask_text(text: str, findings: Sequence[Finding], style: str = "label", salt: str = "") -> str:
    out, pos = [], 0
    for f in sorted(findings, key=lambda f: f.start):
        out.append(text[pos:f.start])
        out.append(mask_value(f.value, f.type, style, salt, f.label))
        pos = f.end
    out.append(text[pos:])
    return "".join(out)


def is_binary(path: Path) -> bool:
    with path.open("rb") as fh:
        return b"\x00" in fh.read(4096)


def iter_files(paths: Iterable[str], all_files: bool = False) -> Iterator[Path]:
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            yield p
        elif p.is_dir():
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for name in sorted(files):
                    fp = Path(root) / name
                    if all_files or fp.suffix.lower() in TEXT_EXTENSIONS or not fp.suffix:
                        yield fp
        else:
            raise FileNotFoundError(raw)


def scan_paths(paths: Iterable[str], detectors: Sequence[Detector] = DETECTORS,
               allow: Sequence["re.Pattern[str]"] = (), all_files: bool = False):
    """Yield ``(path, text, findings)`` for every readable text file."""
    for fp in iter_files(paths, all_files):
        try:
            if is_binary(fp):
                continue
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        yield fp, text, scan_text(text, detectors, allow, str(fp))
