"""
Flask endpoint that accepts a PDF upload, sanitizes it, and returns the
cleaned bytes back to the user.

Run with:
    pip install pdf-defang flask
    python examples/flask_upload.py
    # Then upload at http://localhost:5000

The endpoint at POST /sanitize accepts multipart/form-data with a "file"
field and returns the sanitized PDF.
"""
from __future__ import annotations

import io
import logging
from flask import Flask, jsonify, request, send_file

from pdf_defang import SanitizeError, sanitize_bytes

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)


@app.route("/")
def index():
    return """
    <h2>pdf-defang demo</h2>
    <form method="post" action="/sanitize" enctype="multipart/form-data">
      <input type="file" name="file" accept="application/pdf" required>
      <button type="submit">Sanitize</button>
    </form>
    """


@app.route("/sanitize", methods=["POST"])
def sanitize_endpoint():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded"}), 400

    upload = request.files["file"]
    if not upload.filename or not upload.filename.lower().endswith(".pdf"):
        return jsonify({"error": "must upload a .pdf file"}), 400

    raw = upload.read()
    if not raw:
        return jsonify({"error": "empty file"}), 400

    # Public uploads default to level="strict". For an internal endpoint
    # serving trusted PDFs that need form interactivity, use:
    #     sanitize_bytes(raw, return_report=True, level="balanced")
    try:
        cleaned, report = sanitize_bytes(raw, return_report=True)
    except SanitizeError as exc:
        # Nothing was stripped, so there is no clean file to return.
        # Never fall back to exc.original here.
        app.logger.warning("Sanitization failed: %s", exc)
        return jsonify({"error": str(exc)}), 400

    # Log what was removed for audit
    app.logger.info(
        "Sanitized %s (%d -> %d bytes): %s",
        upload.filename,
        report.file_size_before,
        report.file_size_after,
        report.as_dict(),
    )

    # Return the cleaned PDF as a download
    return send_file(
        io.BytesIO(cleaned),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"sanitized_{upload.filename}",
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
