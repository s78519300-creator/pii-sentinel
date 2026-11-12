"""Reports: text, JSON and SARIF 2.1.0 (for GitHub code scanning)."""

from __future__ import annotations

import json
from collections import Counter
from typing import Dict, List, Sequence

from . import __version__
from .detectors import BY_NAME, SEVERITY_RANK
from .scanner import Finding

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def summarize(findings: Sequence[Finding]) -> Dict[str, Dict[str, int]]:
    return {
        "by_type": dict(Counter(f.type for f in findings).most_common()),
        "by_severity": {s: n for s, n in sorted(Counter(f.severity for f in findings).items(),
                                                key=lambda kv: -SEVERITY_RANK[kv[0]])},
    }


def render_text(findings: Sequence[Finding], files_scanned: int) -> str:
    files = {f.path for f in findings}
    lines = [f"pii-sentinel: {len(findings)} finding(s) in {len(files)} of {files_scanned} file(s) scanned"]
    if findings:
        s = summarize(findings)
        lines.append("  by type: " + ", ".join(f"{k} {v}" for k, v in s["by_type"].items()))
        lines.append("  by severity: " + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items()))
        lines.append("")
        for f in sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.path or "", f.start)):
            lines.append(f"  {f.severity.upper():<9}{f.type:<12}{f.path}:{f.line}:{f.column}  {f.redacted}")
    return "\n".join(lines) + "\n"


def render_json(findings: Sequence[Finding], files_scanned: int, include_values: bool = False) -> str:
    return json.dumps({
        "tool": "pii-sentinel",
        "version": __version__,
        "files_scanned": files_scanned,
        "total": len(findings),
        "summary": summarize(findings),
        "findings": [f.to_dict(include_values) for f in findings],
    }, indent=2, ensure_ascii=False) + "\n"


def render_sarif(findings: Sequence[Finding]) -> str:
    used = sorted({f.type for f in findings})
    rules: List[dict] = []
    for name in used:
        det = BY_NAME[name]
        rules.append({
            "id": name,
            "name": det.label,
            "shortDescription": {"text": det.description},
            "defaultConfiguration": {"level": _SARIF_LEVEL[det.severity]},
            "properties": {"severity": det.severity, "tags": ["privacy", "pii"]},
        })
    results = [{
        "ruleId": f.type,
        "level": _SARIF_LEVEL[f.severity],
        "message": {"text": f"{BY_NAME[f.type].description} found: {f.redacted}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": (f.path or "").replace("\\", "/")},
            "region": {"startLine": f.line, "startColumn": f.column,
                       "endColumn": f.column + (f.end - f.start)},
        }}],
    } for f in findings]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "pii-sentinel", "version": __version__,
                                "informationUri": "https://github.com/s78519300-creator/pii-sentinel",
                                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2) + "\n"
