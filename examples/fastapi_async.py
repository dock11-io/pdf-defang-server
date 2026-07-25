"""
FastAPI endpoint using sanitize_async for non-blocking PDF processing.

Run with:
    pip install pdf-defang fastapi uvicorn python-multipart
    uvicorn examples.fastapi_async:app --reload

Test:
    curl -F 'file=@some.pdf' http://localhost:8000/sanitize -o cleaned.pdf
"""
from __future__ import annotations

import io
import logging

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from pdf_defang import SanitizeError, sanitize_bytes, scan_bytes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fastapi_pdf_defang")

app = FastAPI(title="pdf-defang demo")


@app.post("/sanitize")
async def sanitize_endpoint(file: UploadFile = File(...)) -> StreamingResponse:
    """
    Accept a PDF upload, sanitize it, return the cleaned bytes.

    Returns 400 with JSON error if the upload is invalid or sanitization
    fails (e.g., encrypted PDF without password, malformed PDF).
    """
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Must upload a .pdf file")

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")

    # Default level="strict" for a public endpoint. Pass level="balanced"
    # if the source is trusted and you need form interactivity preserved.
    try:
        cleaned, report = sanitize_bytes(raw, return_report=True)
    except SanitizeError as exc:
        # Nothing was stripped, so there is no clean file to stream back.
        logger.warning("Sanitization failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    logger.info(
        "Sanitized %s (%d -> %d bytes): %s",
        file.filename, report.file_size_before, report.file_size_after,
        report.as_dict(),
    )

    return StreamingResponse(
        io.BytesIO(cleaned),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="sanitized_{file.filename}"',
            "X-Defang-Modifications": str(report.javascript_in_names + report.dangerous_uris_removed),
        },
    )


@app.post("/scan")
async def scan_endpoint(file: UploadFile = File(...)) -> dict[str, object]:
    """
    Inspect a PDF and return findings as JSON. Does not modify the input.

    Useful for upload-validation UX: 'Your PDF contains JavaScript - are
    you sure you want to upload it?'
    """
    if not file.filename or not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Must upload a .pdf file")

    raw = await file.read()
    report = scan_bytes(raw)
    return {"filename": file.filename, **report.as_dict()}
