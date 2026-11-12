# pii-sentinel

Find and mask personal data in logs, CSV exports, support tickets and LLM training data, including the Indian identifiers that generic scanners miss: **Aadhaar, PAN, UPI IDs, GSTIN, IFSC and Indian mobile numbers**.

Checksums keep false positives down. Aadhaar numbers must pass the Verhoeff check and card numbers must pass Luhn, so order IDs, trace IDs and version strings are left alone. Reports never print raw values, so they are safe to paste into a ticket or a CI log.

Pure Python standard library. Text, JSON and SARIF output, so findings show up in GitHub code scanning.

## Quick start

```bash
git clone https://github.com/s78519300-creator/pii-sentinel
cd pii-sentinel
pip install -e ".[dev]"

pii-sentinel scan examples/data
```

```text
pii-sentinel: 12 finding(s) in 2 of 2 file(s) scanned
  by type: ipv4 2, upi_id 2, phone_in 2, pan 1, aadhaar 1, credit_card 1, email 1, gstin 1, ifsc 1
  by severity: critical 2, high 3, medium 4, low 3

  CRITICAL aadhaar     examples/data/support_tickets.csv:3:56  XXXX XXXX 0124
  CRITICAL credit_card examples/data/support_tickets.csv:4:25  XXXX XXXX XXXX 1111
  HIGH     upi_id      examples/data/app.log:2:63  n*****@ybl
  HIGH     upi_id      examples/data/support_tickets.csv:2:51  r*********@okaxis
  HIGH     pan         examples/data/support_tickets.csv:3:36  XXXXXX234F
  MEDIUM   phone_in    examples/data/support_tickets.csv:2:79  +XX XXXXX X3210
  MEDIUM   phone_in    examples/data/support_tickets.csv:4:72  XXXXXXX5678
  MEDIUM   email       examples/data/support_tickets.csv:5:57  p******@example.com
  MEDIUM   gstin       examples/data/support_tickets.csv:6:38  XXXXXXXXXXXF1Z5
  LOW      ipv4        examples/data/app.log:1:52  203.0.x.x
  LOW      ipv4        examples/data/app.log:4:52  10.0.x.x
  LOW      ifsc        examples/data/support_tickets.csv:6:65  XXXXXXX1234
```

The same files also hold a 13-digit order number, a `1234 5678 9012` trace ID and a `1.24.3` version string. None of them is reported. All sample values are fake.

## Mask

```bash
# [AADHAAR], [PAN], [UPI] ... written to a mirror directory
pii-sentinel mask examples/data --out masked/

# keep the last 4 characters: XXXX XXXX 0124, r*********@okaxis
pii-sentinel mask examples/data --out masked/ --style partial

# stable pseudonyms, so joins and dedup still work: [UPI:bf72a4d7b430]
pii-sentinel mask logs/ --in-place --style hash --salt "$PII_SALT"
```

Before:

```text
T-1001,2026-11-02,"Refund not received. My UPI is ravi.kumar@okaxis and phone +91 98765 43210"
```

After `--style partial`:

```text
T-1001,2026-11-02,"Refund not received. My UPI is r*********@okaxis and phone +XX XXXXX X3210"
```

## Detectors

| Detector | Severity | What it matches | False-positive guard |
| --- | --- | --- | --- |
| `credit_card` | critical | 13 to 19 digit card numbers | Luhn checksum, no all-same digits |
| `aadhaar` | critical | 12 digits, spaced or not | Verhoeff checksum, cannot start with 0 or 1 |
| `pan` | high | `ABCPK1234F` | 4th letter must be a valid holder type |
| `upi_id` | high | `name@okaxis`, `name@ybl` and 50+ other handles | known handle list, not followed by a domain |
| `gstin` | medium | `27ABCPK1234F1Z5` | full GSTIN structure; the PAN inside it is not double-reported |
| `email` | medium | standard addresses | needs a real TLD |
| `phone_in` | medium | `+91 98765 43210`, `09812345678`, `9812345678` | must start with 6 to 9, no placeholder runs |
| `ifsc` | low | `HDFC0001234` | 5th character must be 0 |
| `ipv4` | low | `203.0.113.45` | valid octets; loopback and link-local skipped |

Run `pii-sentinel detectors` to list them, and `--types aadhaar,pan` to run only some.

## Use it in CI

```bash
pii-sentinel scan data/ --format sarif -o pii.sarif --fail-on high --allow '@example\.com$'
```

- `--fail-on` sets the lowest severity that fails the build: `low`, `medium`, `high` (default), `critical` or `never`.
- `--allow REGEX` skips known-safe values such as test emails. It can be repeated.
- Exit codes: `0` passed, `1` findings at or above `--fail-on`, `2` bad input.

Upload `pii.sarif` with `github/codeql-action/upload-sarif` and each finding appears as an annotation on the pull request.

## Use it from Python

```python
from pii_sentinel import mask_text, scan_text

text = "KYC failed for PAN ABCPK1234F, UPI ravi.kumar@okaxis"
findings = scan_text(text)
print([(f.type, f.redacted) for f in findings])
print(mask_text(text, findings))  # KYC failed for PAN [PAN], UPI [UPI]
```

## Limits

- Pattern-based. It does not find names, street addresses or free-text health details; pair it with an NER model for those.
- Phone detection covers Indian mobile numbers, not landlines or other countries.
- PAN, GSTIN and IFSC have no public checksum, so a code-like string with the same shape will match.

## License

MIT
