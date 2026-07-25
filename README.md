# pdf-defang

> Strip JavaScript, OpenAction, Launch actions and other active content from PDFs.
> Lightweight Python library on top of [pikepdf](https://github.com/pikepdf/pikepdf).
> MIT licensed.

[![PyPI](https://img.shields.io/pypi/v/pdf-defang.svg)](https://pypi.org/project/pdf-defang/)
[![Python](https://img.shields.io/pypi/pyversions/pdf-defang.svg)](https://pypi.org/project/pdf-defang/)
[![Downloads](https://static.pepy.tech/badge/pdf-defang/month)](https://pepy.tech/project/pdf-defang)
[![CI](https://github.com/kovetz-PDF/pdf-defang/actions/workflows/ci.yml/badge.svg)](https://github.com/kovetz-PDF/pdf-defang/actions/workflows/ci.yml)
[![Docs](https://github.com/kovetz-PDF/pdf-defang/actions/workflows/docs.yml/badge.svg)](https://kovetz-pdf.github.io/pdf-defang/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![mypy](https://img.shields.io/badge/mypy-strict-blue.svg)](https://mypy.readthedocs.io/)
[![Ruff](https://img.shields.io/badge/ruff-clean-success.svg)](https://github.com/astral-sh/ruff)

**📚 [Full documentation](https://kovetz-pdf.github.io/pdf-defang/)** | **📦 [PyPI](https://pypi.org/project/pdf-defang/)** | **🛠️ Built by [kovetz.co.il](https://kovetz.co.il)**

---

## Why?

PDFs can carry executable content: JavaScript that runs when the file opens,
auto-actions that fire on every page navigation, "Launch" actions that try to
open other programs, embedded files that drop malware. If you process
user-uploaded PDFs in your app, you should strip this content before serving
them back.

The Python ecosystem has parsers (`pikepdf`, `pypdf`, `PyMuPDF`) and a heavy
container-based tool ([Dangerzone](https://dangerzone.rocks/)), but no clean
drop-in library that says "give me this PDF without active content." This is
that library.

## Install

```bash
pip install pdf-defang
```

Requires Python 3.9+ and pikepdf 8+.

## Quick start

### Python API

```python
from pdf_defang import sanitize, scan

# Clean a file in place
sanitize("uploaded.pdf")

# Get a detailed report of what was removed
report = sanitize("uploaded.pdf", return_report=True)
print(report.javascript_in_names)        # 2
print(report.open_action_removed)        # True
print(report.annotation_action_types)    # ['Launch']
print(report.dangerous_uris_removed)     # 1
print(report.as_dict())                  # JSON-serialisable

# Inspect a file WITHOUT modifying it
report = scan("suspicious.pdf")
print(report.risk_level)                 # 'high' / 'medium' / 'low' / 'none'
print(report.has_javascript)             # True
```

### Async API (FastAPI / aiohttp / asyncio)

```python
from pdf_defang import sanitize_async, scan_async

async def handle_upload(path):
    report = await sanitize_async(path, return_report=True)
    return report.as_dict()
```

### In-memory API (S3, Lambda, no disk)

```python
from pdf_defang import SanitizeError, sanitize_bytes

raw_pdf: bytes = ...   # from S3, HTTP, anywhere
try:
    cleaned: bytes = sanitize_bytes(raw_pdf)
except SanitizeError as exc:
    # Unparseable or encrypted - nothing was stripped, so there is no
    # clean file to serve. Reject it.
    ...
# No disk involved
```

### Encrypted PDFs (encryption preserved on output)

```python
sanitize("encrypted.pdf", password="hunter2")
# Still encrypted with the same password, JavaScript removed.
```

### Two levels: strict (default) vs balanced

```python
# Public uploads: kill everything active (safest)
sanitize("untrusted.pdf")                            # level="strict"

# Trusted internal forms that need Submit / Calculate buttons:
sanitize("expense_form.pdf", level="balanced")
```

Both levels strip pure attack vectors (`/Launch`, `/GoToR`, document
JavaScript, dangerous URI schemes, etc.). `balanced` additionally
preserves `/SubmitForm` / `/ResetForm` / form JS actions, annotation
`/AA` and `/JS` triggers, the AcroForm `/CO` calculation order, and
embedded files (used by PDF portfolios). Default is `strict`.

### Command line

```bash
# Clean a single file (strict by default)
pdf-defang clean uploaded.pdf

# Clean many at once
pdf-defang clean *.pdf

# Keep form interactivity working
pdf-defang clean --level balanced internal_form.pdf

# Inspect without changes
pdf-defang scan suspicious.pdf

# Get JSON output for piping into your logging stack
pdf-defang scan suspicious.pdf --json | jq .risk_level
pdf-defang clean *.pdf --json > sanitization-log.json
```

Exit codes follow shell conventions:

| Code | `clean` | `scan` |
|------|---------|--------|
| 0    | All files were already clean | No active content found |
| 1    | At least one file had something stripped | Active content detected |
| 2    | At least one file could not be opened | File could not be scanned |

## Use cases

### Web app that accepts PDF uploads

```python
from pdf_defang import sanitize

def handle_upload(uploaded_file_path: str) -> str:
    report = sanitize(uploaded_file_path, return_report=True)
    if report.error:
        raise ValueError(f"Could not process PDF: {report.error}")
    # Log what was removed for your audit trail
    logger.info("Sanitized %s: %s", uploaded_file_path, report.as_dict())
    return uploaded_file_path  # safe to serve back to other users now
```

### Suspicious file investigation

```python
from pdf_defang import scan

report = scan("phishing_attachment.pdf")
if report.risk_level == "high":
    quarantine(report)
elif report.risk_level == "medium":
    notify_security_team(report)
```

### Compliance pipeline (PDF/A clean output)

```bash
find /var/incoming -name '*.pdf' | xargs pdf-defang clean --json >> audit.jsonl
```

## What gets removed

| Item | Where | What it does |
|---|---|---|
| `/JavaScript` in `/Names` | Document root | Document-level JavaScript that runs on open |
| `/EmbeddedFiles` | Document root | Files hidden inside the PDF (potential malware) |
| `/OpenAction` | Document root | Action automatically executed when PDF opens |
| `/AA` | Document root | "Additional Actions" - auto-execute on navigation |
| `/XFA` | `/AcroForm` | Legacy XML forms - well-known attack surface |
| `/CO` | `/AcroForm` | Form field Calculation Order |
| `/AA` | Each page | Page-level auto-execute actions |
| Dangerous `/A` | Each annotation | JavaScript, Launch, ImportData, SubmitForm, ResetForm, Rendition, GoToR, GoToE, Movie, Sound actions |
| `/AA` | Each annotation | Per-annotation auto-actions |
| `/JS` | Each annotation | JavaScript attached directly to an annotation |
| Unsafe `/URI` | Each annotation | URI actions with dangerous schemes (`javascript:`, `file:`, `data:`, `vbscript:`, UNC paths). Standard hyperlinks (`http`, `https`, `mailto`, `tel`, `ftp`, etc.) are preserved. |

## What is preserved

Sanitization is **non-destructive to visible content**:

- All text, images and layout
- Standard form fields (filled values stay intact)
- Bookmarks, table of contents, page labels
- Document metadata (Author, Title, Subject, Keywords)
- Standard link annotations to `mailto:` / `http(s):` URLs
- Document structure, page count, page order

## Why not Dangerzone / iText / commercial SDKs?

| Tool | Why this might not fit you |
|---|---|
| [Dangerzone](https://dangerzone.rocks/) | Excellent for sensitive analyst workflows, but runs a full Docker container per file. Minutes per PDF, not milliseconds. |
| [iText](https://itextpdf.com/) / [Apryse](https://apryse.com/) | Powerful, but commercial licenses start at thousands of USD/year. |
| [pikepdf](https://github.com/pikepdf/pikepdf) directly | Brilliant library, but it's a parser, not a sanitizer. You'd write the same `_strip_document_level()` code we wrote here. That's exactly what we extracted. |

`pdf-defang` is for the case where you want a small, free, drop-in function
to ship in your existing Python app. No subprocesses, no Docker, no per-seat
license.

## Performance

Measured on a Windows 11 laptop, Python 3.13, on the fixture PDFs:

| Operation | Median time |
|---|---|
| `scan_bytes()` on a clean PDF (in memory) | ~0.3 ms |
| `sanitize_bytes()` on a malicious PDF (in memory) | ~0.6 ms |
| `sanitize()` on a clean PDF (with disk I/O) | ~8 ms |
| `sanitize()` kitchen-sink PDF (with disk I/O) | ~8 ms |

These are 50-100 times faster than container-based tools like Dangerzone
(which take seconds-to-minutes per file).

To benchmark on your hardware:

```bash
python -m pytest tests/test_performance.py -v -s
```

## Caveats

- Sanitization modifies the input file **in place**. If you need the original
  preserved for audit, copy it first.
- Encrypted PDFs require the `password=` argument. Wrong-password attempts
  return an error report (not an exception).
- Malformed PDFs may not open at all - we surface the underlying pikepdf error
  in the report. The original file is not touched on failure.
- This is **defense in depth**, not a replacement for layered controls. Don't
  rely on a sanitizer alone for high-risk attachment workflows: also validate
  uploaders, sandbox processing, and scan with AV.

## Origin story

This library was originally written for [kovetz.co.il](https://kovetz.co.il)
(Hebrew PDF tools, [www.kovetz.co.il](https://www.kovetz.co.il)) in May 2026,
during an APT scanning campaign by an Iranian-attributed threat actor sweeping
endpoints for upload vectors. We needed to make sure that any PDF leaving our
service was free of executable payloads, even if an attacker successfully
uploaded a poisoned file.

We initially wrote 67 lines of pikepdf code, tested it on the kovetz.co.il
fleet (thousands of files/day), then realised there's no clean equivalent in
the OSS Python ecosystem. So we extracted it here for everyone else who needs
the same thing.

## Contributing

Issues and PRs welcome at [github.com/kovetz-PDF/pdf-defang](https://github.com/kovetz-PDF/pdf-defang).

If you've found a PDF in the wild that contains active content we don't
strip, please open an issue with the file (or a minimal reproducer) attached.

### Development setup

```bash
git clone https://github.com/kovetz-PDF/pdf-defang.git
cd pdf-defang
python -m pip install -e ".[test]"
python -m pytest
```

The `tests/conftest.py` will auto-generate the test fixture PDFs on first run.

## License

[MIT](LICENSE) - free for any use, including commercial.

---

Built and maintained by [kovetz.co.il](https://kovetz.co.il).
Contact: [contact@kovetz.co.il](mailto:contact@kovetz.co.il)
