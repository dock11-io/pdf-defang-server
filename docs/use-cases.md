# Use Cases

Working examples for common scenarios. Each links to the full runnable
script in [`examples/`](https://github.com/kovetz-PDF/pdf-defang/tree/main/examples).

## Flask: sanitize uploaded PDFs

```python
from flask import Flask, send_file, request
from pdf_defang import SanitizeError, sanitize_bytes
import io

app = Flask(__name__)

@app.route("/sanitize", methods=["POST"])
def clean():
    raw = request.files["file"].read()
    try:
        cleaned = sanitize_bytes(raw)
    except SanitizeError as exc:
        return {"error": str(exc)}, 400
    return send_file(io.BytesIO(cleaned), mimetype="application/pdf")
```

Full script: [`examples/flask_upload.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/examples/flask_upload.py)

## FastAPI: async non-blocking

```python
from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pdf_defang import SanitizeError, sanitize_bytes
import io

app = FastAPI()

@app.post("/sanitize")
async def clean(file: UploadFile):
    raw = await file.read()
    try:
        cleaned = sanitize_bytes(raw)
    except SanitizeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return StreamingResponse(io.BytesIO(cleaned), media_type="application/pdf")
```

Full script: [`examples/fastapi_async.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/examples/fastapi_async.py)

## Batch processing with audit log

```python
from pathlib import Path
import json
from pdf_defang import sanitize

with open("audit.jsonl", "w") as log:
    for pdf in Path("incoming/").rglob("*.pdf"):
        report = sanitize(pdf, return_report=True)
        log.write(json.dumps({"file": str(pdf), **report.as_dict()}) + "\n")
```

Full script: [`examples/batch_processor.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/examples/batch_processor.py)

## Read-only forensic scan

```python
from pdf_defang import scan

report = scan("suspicious.pdf")
if report.risk_level == "high":
    print("DO NOT OPEN:", report.annotation_action_types)
```

Full script: [`examples/audit_only.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/examples/audit_only.py)

## S3 / cloud streaming (no disk)

```python
import boto3
from pdf_defang import SanitizeError, sanitize_bytes

s3 = boto3.client("s3")

def process(bucket: str, key: str):
    raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    try:
        cleaned = sanitize_bytes(raw)
    except SanitizeError:
        s3.copy_object(Bucket=bucket, Key=f"quarantine/{key}", ...)
    else:
        s3.put_object(Bucket=bucket, Key=f"clean/{key}", Body=cleaned)
```

Full script: [`examples/s3_streaming.py`](https://github.com/kovetz-PDF/pdf-defang/blob/main/examples/s3_streaming.py)

## Internal form that needs to keep working

For trusted-source PDFs where forms must still calculate and submit
(e.g. expense reports, tax forms, signed contracts), opt into
`balanced` mode:

```python
from pdf_defang import sanitize

# Strips /Launch, /GoToR, document JS, dangerous URIs - but keeps
# /SubmitForm, /ResetForm, form JavaScript, calculate triggers, and
# embedded files.
sanitize("expense_form.pdf", level="balanced")
```

Use `strict` (the default) for anything coming from outside your
organisation. Use `balanced` only when you trust the producer and a
non-functional form is worse than a residual JS execution surface.

## Compliance / audit pipeline

For HIPAA/GDPR/regulatory workflows where every modification needs an
audit record:

```python
import logging
from pdf_defang import sanitize

audit_log = logging.getLogger("compliance.pdf_audit")

def compliance_clean(path: str, user_id: str) -> dict:
    report = sanitize(path, return_report=True)
    audit_log.info(
        "user=%s file=%s modifications=%s",
        user_id, path, report.as_dict(),
    )
    return report.as_dict()
```

The `SanitizeReport.as_dict()` output is JSON-serialisable, so it flows
into any structured logging or audit store (Splunk, Elastic, Datadog,
CloudWatch, etc.).
