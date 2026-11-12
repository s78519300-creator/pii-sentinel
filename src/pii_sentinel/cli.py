"""Command line interface: ``pii-sentinel scan`` and ``pii-sentinel mask``."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .detectors import BY_NAME, SEVERITIES, SEVERITY_RANK, select
from .report import render_json, render_sarif, render_text
from .scanner import MASK_STYLES, mask_text, scan_paths


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="+", help="files or directories")
    p.add_argument("--types", help=f"comma-separated detectors to run (default all): {', '.join(BY_NAME)}")
    p.add_argument("--allow", action="append", default=[], metavar="REGEX",
                   help="ignore values matching this regex, e.g. '@example\\.com$' (repeatable)")
    p.add_argument("--all-files", action="store_true", help="scan every non-binary file, not just known text types")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pii-sentinel",
                                description="Find and mask personal data, including Aadhaar, PAN, UPI and Indian phone numbers.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="report PII without changing files")
    _common(s)
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--output", "-o", help="write the report to a file")
    s.add_argument("--fail-on", choices=list(SEVERITIES) + ["never"], default="high",
                   help="exit 1 if any finding is at or above this severity (default high)")
    s.add_argument("--include-values", action="store_true",
                   help="put raw values in JSON output (off by default so reports are safe to share)")

    m = sub.add_parser("mask", help="write masked copies of files")
    _common(m)
    m.add_argument("--style", choices=MASK_STYLES, default="label",
                   help="label: [AADHAAR]; partial: XXXX XXXX 1234; hash: [AADHAAR:3f9c...] (stable pseudonym)")
    m.add_argument("--salt", default="", help="secret salt for --style hash")
    dest = m.add_mutually_exclusive_group(required=True)
    dest.add_argument("--out", help="directory for masked copies (mirrors input layout)")
    dest.add_argument("--in-place", action="store_true", help="overwrite the input files")

    sub.add_parser("detectors", help="list detectors and their severities")
    return p


def _relative(fp: Path, roots: List[str]) -> Path:
    for r in roots:
        rp = Path(r)
        if rp.is_dir():
            try:
                return fp.relative_to(rp)
            except ValueError:
                continue
    return Path(fp.name)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "detectors":
        for d in BY_NAME.values():
            print(f"{d.name:<12}{d.severity:<10}{d.description}")
        return 0

    try:
        detectors = select([t.strip() for t in args.types.split(",")] if args.types else None)
        allow = [re.compile(a) for a in args.allow]
        results = list(scan_paths(args.paths, detectors, allow, args.all_files))
    except (FileNotFoundError, ValueError, re.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = [f for _, _, fs in results for f in fs]

    if args.command == "scan":
        if args.format == "json":
            out = render_json(findings, len(results), args.include_values)
        elif args.format == "sarif":
            out = render_sarif(findings)
        else:
            out = render_text(findings, len(results))
        if args.output:
            Path(args.output).write_text(out, encoding="utf-8")
            print(f"{len(findings)} finding(s); report written to {args.output}", file=sys.stderr)
        else:
            sys.stdout.write(out)
        if args.fail_on != "never":
            threshold = SEVERITY_RANK[args.fail_on]
            if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
                return 1
        return 0

    # mask
    changed = 0
    for fp, text, fs in results:
        target = fp if args.in_place else Path(args.out) / _relative(fp, args.paths)
        if args.in_place and not fs:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(mask_text(text, fs, args.style, args.salt), encoding="utf-8")
        changed += bool(fs)
    where = "in place" if args.in_place else f"to {args.out}"
    print(f"Masked {len(findings)} value(s) in {changed} file(s), written {where}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
