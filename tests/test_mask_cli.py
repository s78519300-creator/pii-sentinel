import json
import shutil
from pathlib import Path

from pii_sentinel import mask_text, mask_value, scan_text
from pii_sentinel.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "data"


def test_mask_styles():
    assert mask_value("ABCPK1234F", "pan", "label", label="PAN") == "[PAN]"
    assert mask_value("4111 1111 1111 1111", "credit_card", "partial") == "XXXX XXXX XXXX 1111"
    assert mask_value("ravi@okaxis", "upi_id", "partial") == "r***@okaxis"
    h1 = mask_value("ABCPK1234F", "pan", "hash", "salt", "PAN")
    assert h1 == mask_value("ABCPK1234F", "pan", "hash", "salt", "PAN")
    assert h1 != mask_value("ABCPK1234F", "pan", "hash", "other", "PAN")


def test_mask_text_keeps_surroundings():
    text = "PAN ABCPK1234F, mail a@b.com."
    assert mask_text(text, scan_text(text)) == "PAN [PAN], mail [EMAIL]."


def test_scan_cli_exit_codes(capsys):
    assert main(["scan", str(EXAMPLES)]) == 1
    out = capsys.readouterr().out
    assert "12 finding(s)" in out
    assert "ABCPK1234F" not in out  # raw values never printed
    assert main(["scan", str(EXAMPLES), "--fail-on", "never"]) == 0
    assert main(["scan", str(EXAMPLES / "app.log"), "--fail-on", "critical"]) == 0


def test_scan_cli_json_and_sarif(tmp_path):
    j, s = tmp_path / "r.json", tmp_path / "r.sarif"
    main(["scan", str(EXAMPLES), "--format", "json", "-o", str(j), "--fail-on", "never"])
    main(["scan", str(EXAMPLES), "--format", "sarif", "-o", str(s), "--fail-on", "never"])
    data = json.loads(j.read_text(encoding="utf-8"))
    assert data["total"] == 12 and "value" not in data["findings"][0]
    sarif = json.loads(s.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 12


def test_mask_cli_out_dir(tmp_path):
    out = tmp_path / "masked"
    assert main(["mask", str(EXAMPLES), "--out", str(out), "--allow", r"@example\.com$"]) == 0
    masked = (out / "support_tickets.csv").read_text(encoding="utf-8")
    assert "[AADHAAR]" in masked and "[UPI]" in masked and "priya.s@example.com" in masked
    assert main(["scan", str(out), "--fail-on", "low", "--allow", r"@example\.com$"]) == 0


def test_mask_cli_in_place(tmp_path):
    shutil.copy(EXAMPLES / "app.log", tmp_path / "app.log")
    main(["mask", str(tmp_path), "--in-place", "--style", "partial"])
    assert "neha99@ybl" not in (tmp_path / "app.log").read_text(encoding="utf-8")


def test_detectors_command(capsys):
    assert main(["detectors"]) == 0
    assert "aadhaar" in capsys.readouterr().out


def test_bad_path():
    assert main(["scan", "does-not-exist"]) == 2
