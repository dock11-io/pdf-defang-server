# Quick Start

## Install

```bash
pip install pdf-defang
```

That's it. The only dependency is [pikepdf](https://github.com/pikepdf/pikepdf).

## Five-minute tour

### Sanitize a file

```python
from pdf_defang import sanitize

sanitize("uploaded.pdf")
# 'uploaded.pdf' is now safe to serve back to other users
```

### Get a detailed report

```python
from pdf_defang import sanitize

report = sanitize("uploaded.pdf", return_report=True)

print(report.javascript_in_names)        # 2
print(report.open_action_removed)        # True
print(report.annotation_action_types)    # ['Launch']
print(report.dangerous_uris_removed)     # 1
print(report.dangerous_uri_schemes_removed)  # ['javascript']

# Or as a dict for JSON logging
import json
print(json.dumps(report.as_dict(), indent=2))
```

### Inspect without modifying

```python
from pdf_defang import scan

report = scan("suspicious.pdf")
if report.risk_level == "high":
    quarantine(report)
```

### Async (for FastAPI, aiohttp, etc.)

```python
from pdf_defang import sanitize_async, scan_async

async def upload_handler(path):
    scan_result = await scan_async(path)
    if scan_result.risk_level == "high":
        report = await sanitize_async(path, return_report=True)
        log.warning("Stripped active content: %s", report.as_dict())
```

### In memory (S3, streaming, Lambda)

```python
from pdf_defang import SanitizeError, sanitize_bytes

raw_pdf: bytes = ...   # from S3, HTTP, anywhere
try:
    cleaned: bytes = sanitize_bytes(raw_pdf)
except SanitizeError:
    ...  # unparseable or encrypted: nothing was stripped, so reject it
# No disk involved. Ship `cleaned` back to S3 / browser.
```

### CLI

```bash
# Clean one file
pdf-defang clean report.pdf

# Clean many
pdf-defang clean *.pdf

# Inspect without changes
pdf-defang scan suspicious.pdf

# JSON output for your logging stack
pdf-defang scan suspicious.pdf --json | jq .risk_level
```

## Encrypted PDFs

Pass the password. Encryption is **preserved** on save.

```python
sanitize("encrypted.pdf", password="hunter2")
# Still encrypted with the same password, but JavaScript is gone.
```

## Two levels: strict vs balanced

By default, every form of active content is removed. If you need
legitimate form interactivity to keep working (Submit buttons, calculate
triggers, embedded portfolios) and you trust the source, opt into
`level="balanced"`:

```python
from pdf_defang import sanitize

# Public uploads from random users (safest default):
sanitize("untrusted.pdf")                     # level="strict" implied

# Internal expense form that needs Calculate / Submit buttons:
sanitize("expense_report.pdf", level="balanced")
```

Both levels strip the same attack vectors (`/Launch`, `/GoToR`, document
JavaScript, dangerous URI schemes, etc.). `balanced` only differs in
keeping `/SubmitForm`/`/ResetForm`/form JavaScript actions, annotation
`/AA` and `/JS` triggers, the AcroForm `/CO` calculation order, and
embedded files. See [Protections](protections.md) for the full matrix.

## Next steps

- [Use cases](use-cases.md) - Flask / FastAPI / batch / forensics patterns
- [API reference](api.md) - Full function and dataclass docs
- [Protections](protections.md) - What exactly gets stripped
- [Comparison vs Dangerzone](compare/dangerzone.md) - When to use which
