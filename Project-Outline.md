## Aim of this project

`pdf-defang-server` exists to answer one narrow question: _how do you call
`pdf-defang` over the network rather than importing it directly into a Python
process?_ It is deliberately not trying to be a general-purpose PDF
processing service, a malware scanner, or a complete document pipeline.

Specifically, the aim is:

- **Expose `pdf-defang` as an internal HTTP microservice** — something a
  Cloudflare Worker/Workflow, n8n flow, or any other orchestrator can call
  over the network, without that caller needing a Python runtime or the
  `pikepdf`/`pdf-defang` dependencies itself.
- **Add the operational concerns the library doesn't have an opinion on**:
  concurrency limiting, timeouts, file size limits, and — the one that
  actually mattered in testing — refusing to silently serve back unsanitised
  content on a parse failure (see Finding #1 below).
- **Stay legible as a teaching example.** This was built partly so the
  underlying mechanics (FastAPI route → uvicorn server → Docker container →
  Compose service → reverse proxy) are visible and separable, not so it's the
  most feature-complete sanitiser service possible. Where there was a choice
  between "one clever combined endpoint" and "several small, separately
  testable pieces," the latter was chosen on purpose.
- **Be one stage in a larger pipeline, not the whole pipeline.** It assumes
  ClamAV (or equivalent) runs separately against the _original_ upload before
  this service ever sees it — see "Pipeline ordering" below. This service has
  no malware-detection ambition of its own.

What this project explicitly does **not** try to do: detect malware by
signature, validate PDF/A compliance, OCR, convert formats, or replace
upload-time validation (auth, content-type checks, antivirus) elsewhere in
the pipeline. Scope creep into any of those would be a different project.

---

## Structural considerations

Decisions made about how the code is organised, and why, separate from the
`pdf-defang`-specific findings further down.

### Why one file (`app/main.py`) rather than split modules

At this size (under 200 lines), splitting into `routes.py` / `schemas.py` /
`services.py` would add navigation overhead without a matching benefit. The
natural split point, if this grows, is **routes vs. the sanitisation-calling
logic** (`_run_with_limits`, the `report.error` check) — that logic is the
part worth unit-testing in isolation from HTTP concerns, and the part most
likely to be reused if a second endpoint shape is added later (e.g. a queue
consumer instead of an HTTP route, per the queue-vs-synchronous discussion
earlier). Splitting before that need is concrete would be guessing at
structure rather than responding to it.

### Why configuration is environment variables, not a config file

This service runs inside Docker Compose, where environment variables are the
idiomatic way to vary behaviour per-deployment (dev vs. prod concurrency
limits, for instance) without rebuilding the image or mounting extra files.
A config file would need its own mounting/path-resolution logic for no
benefit at this scope. The trade-off: env vars don't give you nested
structure if config ever gets complex — if that happens, it's a signal to
revisit, not a reason to over-engineer now.

### Why the concurrency limit lives in the app, not just at the container level

It would be possible to rely solely on `cpus`/`mem_limit` in Compose plus
uvicorn's worker count to bound load. The explicit `asyncio.Semaphore` in
`app/main.py` is a second, independent layer: it gives a clean `503` to the
caller when at capacity (so the orchestrator's retry/backoff logic — see the
Cloudflare Workflow discussion — has something sensible to react to) rather
than the request queuing silently at the TCP level or the container getting
OOM-killed under burst load with no application-level signal at all. Belt
and braces, not redundancy: container limits protect the host, the semaphore
protects the request's caller.

### Why `/sanitise` and `/sanitise/report` are separate endpoints rather than one with a query flag

Both call the same underlying function; the split exists because the two
callers have genuinely different needs. A pipeline writing an audit trail
(per compliance habits, logging what was stripped before
forwarding the file) wants the report without paying the cost of moving the
file body over the wire twice. A caller that just wants a clean file back
doesn't want JSON parsing on the other end. Folding both into one endpoint
behind a `?include_report=true` flag was considered and rejected — it would
work, but two clearly-named endpoints are easier to read in a Workflow step
definition than a query parameter buried in a URL.

### Pipeline ordering (ClamAV + pdf-defang), restated structurally

Already covered conversationally, restated here because it's a structural
decision about where this service sits, not just a sequencing tip:

```
Upload → ClamAV (scans the ORIGINAL file) → pdf-defang-server (sanitises) → store/serve
```

This service should never be the _first_ thing an untrusted upload reaches in
a production pipeline. It assumes something upstream (ClamAV, or at minimum
basic upload validation) has already had a chance to see the file
unmodified. Building it as a standalone container with no opinion on what
comes before it (rather than, say, bundling ClamAV into the same image) keeps
that ordering decision visible at the orchestration layer where it belongs,
instead of hidden inside this service's internals.

---

## 1. Silent failure on malformed/unparseable PDFs (the important one)

**Severity: High** — this is the one worth understanding properly, because it's
exactly the kind of bug that looks fine in a demo and fails quietly in
production.

### What was assumed

That `sanitize_bytes()` would raise an exception (or at minimum return some
clear failure signal) if handed a file it couldn't parse as a PDF.

### What actually happens

```python
from pdf_defang import sanitize_bytes

result = sanitize_bytes(b"this is not a pdf", return_report=False)
print(result == b"this is not a pdf")  # True
```

`sanitize_bytes()` does **not** raise. On a parse failure it logs a warning
internally and returns the **original, unmodified bytes**, unchanged. The
failure is only visible if you explicitly ask for the report:

```python
cleaned, report = sanitize_bytes(data, return_report=True)
print(report.error)
# 'PdfError: stream <...>: unable to find trailer dictionary while recovering damaged file'
print(report.modified)
# False
```

### Why this matters

A naive wrapper —

```python
@app.post("/sanitise")
async def sanitise(file: UploadFile):
    data = await file.read()
    cleaned = sanitize_bytes(data)          # return_report defaults to False
    return Response(content=cleaned, media_type="application/pdf")
```

— will return a `200 OK` with the **original, unsanitised** file body for any
input it can't parse. If that input happened to be a malicious PDF crafted in
a way that also confuses the parser, you've served back exactly the file you
built this service to clean, with no error, no log signal visible to the
caller, and a success status code.

### The fix applied in this repo

Every endpoint that calls `sanitize_bytes()` or `scan_bytes()` always passes
`return_report=True` internally and explicitly checks `report.error` before
trusting the result, regardless of what the public-facing function signature
makes convenient. See `app/main.py`, and the regression tests:

- `test_garbage_input_never_returned_as_unsanitised_200`
- `test_scan_garbage_input_does_not_report_as_safe`

---

## 2. `scan_bytes()` reports a misleading "safe" risk level on parse failure

**Severity: Medium** — a variant of #1, specific to the `/scan` (read-only
inspection) path.

```python
from pdf_defang import scan_bytes

report = scan_bytes(b"not a pdf at all")
print(report.risk_level)  # 'none'
print(report.error)       # 'PdfError: ... unable to find trailer dictionary ...'
```

`risk_level: 'none'` reads as "this file was inspected and found to be safe."
That is not what happened — the file could not be parsed at all. A triage
workflow that branches on `risk_level` (e.g. "auto-approve if none/low, flag
if medium/high") would auto-approve a file that was never actually inspected.

**Fix applied**: `/scan` checks `report.error` and returns a `422` rather than
forwarding a `risk_level` that doesn't mean what it appears to mean.

---

## 3. `return_report=True` changes the return _shape_, not just its contents

**Severity: Low (correctness bug if missed, not a security issue)**

```python
# return_report=False -> bytes
cleaned = sanitize_bytes(data)

# return_report=True -> tuple[bytes, SanitizeReport]
cleaned, report = sanitize_bytes(data, return_report=True)
```

This is documented behaviour, not a bug in `pdf-defang` — but it's easy to
miss on a quick read of the README's code samples, which show the two modes
in separate snippets rather than side-by-side. An early draft of the
`/sanitise/report` endpoint in this project treated the return value as just
the report object and would have raised an `AttributeError` on every call.
Caught by running the actual function against a real PDF before writing the
endpoint around it, rather than coding from the README description alone.

---

## 4. README version/changelog details worth knowing if you upgrade

These aren't bugs, just things confirmed directly rather than assumed:

- `sanitize_bytes(data, *, return_report=False, password=None, level='strict')`
  — `level` and `password` are keyword-only.
- Verified pinned version: `pdf-defang==0.1.2`, depends on
  `pikepdf<10.0,>=8.0` (resolved to `pikepdf==9.11.0` at time of writing).
- This is a genuinely young project: single `v0.1.0` GitHub release, 1 star,
  0 forks at time of writing. The code itself behaved correctly in every test
  run here, but "behaved correctly in the cases we tested" and "mature,
  widely-audited dependency" are different claims. Re-check this before
  relying on it for anything beyond what's tested in this repo.

---

## 5. Lint findings (correctness, not security)

Running `ruff check .` against the first draft flagged real issues, fixed in
the current version:

| Rule    | Issue                                                                                                                      | Fix                                                                                                                              |
| ------- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `B904`  | `raise HTTPException(...)` inside an `except` block without `from exc`/`from None`                                         | Added explicit exception chaining so tracebacks show the real cause                                                              |
| `UP041` | `asyncio.TimeoutError` is an alias; the builtin `TimeoutError` is preferred                                                | Switched to builtin                                                                                                              |
| `B008`  | Flags `File(...)` as a "mutable default argument" — a false positive for FastAPI's documented dependency-injection pattern | Suppressed for this file specifically via `pyproject.toml`, with a comment explaining why, rather than silencing it project-wide |

None of these were security-relevant, but `B904` in particular is worth
internalising: without `from exc`, your logs lose the original traceback when
an unexpected exception gets wrapped into an `HTTPException`, which makes
debugging a production incident slower than it needs to be.

---

## How these were found

Every claim above was verified by actually running the code against real
inputs (crafted PDFs built with `pikepdf` directly, plus deliberately garbage
bytes) inside a sandbox with network access to PyPI — not inferred from the
`pdf-defang` README alone. The README is accurate about _what_ the library
does; it just doesn't document every edge case in its error-handling
behaviour, which is normal for a `v0.1.0` library and exactly why testing
against real inputs before shipping matters more than reading documentation
carefully.
