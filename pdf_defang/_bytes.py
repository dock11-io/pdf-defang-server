"""
Bytes-in / bytes-out API for in-memory PDF processing.

Useful when:
- You receive a PDF from an upload stream and want to process it before
  ever touching disk
- You're reading PDFs from S3, Redis, or another byte-source
- You want to integrate with FastAPI/Flask file handlers without temp files

Example::

    from pdf_defang import SanitizeError, sanitize_bytes, scan_bytes

    # From an upload
    raw = await uploaded_file.read()
    try:
        clean = sanitize_bytes(raw)
    except SanitizeError as exc:
        # Unparseable or encrypted - nothing was stripped, so there is no
        # clean file. Reject it; do NOT serve exc.original to the user.
        return reject(str(exc))
    # 'clean' is now a sanitized PDF as bytes - serve back to user

    # Inspect first
    report = scan_bytes(raw)
    if report.risk_level == "high":
        clean = sanitize_bytes(raw)
"""
from __future__ import annotations

import io
import logging
import warnings
from typing import Literal, overload

import pikepdf

from ._core import (
    Level,
    SanitizeError,
    SanitizeReport,
    _preserve_encryption,
    _strip_document_level,
    _strip_pages,
    _validate_level,
)
from ._scan import ScanReport, _calculate_risk, _scan_document_level, _scan_pages

logger = logging.getLogger(__name__)


def _handle_failure(
    data: bytes,
    report: SanitizeReport,
    *,
    raise_on_error: bool,
    return_report: bool,
) -> bytes | tuple[bytes, SanitizeReport]:
    """
    Common exit path when sanitization failed.

    Either raises (the default, so the failure cannot be mistaken for a
    clean file) or returns the untouched input with a loud warning.
    """
    message = report.error or "sanitization failed"
    if raise_on_error:
        raise SanitizeError(message, report=report, original=data)
    warnings.warn(
        f"pdf-defang: sanitization failed ({message}); returning the ORIGINAL, "
        "UNSANITIZED bytes because raise_on_error=False. Do not serve these "
        "bytes to a user without checking SanitizeReport.error.",
        RuntimeWarning,
        stacklevel=3,
    )
    return (data, report) if return_report else data


@overload
def sanitize_bytes(
    data: bytes,
    *,
    return_report: Literal[False] = False,
    password: str | None = None,
    level: Level = "strict",
    raise_on_error: bool = True,
) -> bytes: ...


@overload
def sanitize_bytes(
    data: bytes,
    *,
    return_report: Literal[True],
    password: str | None = None,
    level: Level = "strict",
    raise_on_error: bool = True,
) -> tuple[bytes, SanitizeReport]: ...


def sanitize_bytes(
    data: bytes,
    *,
    return_report: bool = False,
    password: str | None = None,
    level: Level = "strict",
    raise_on_error: bool = True,
) -> bytes | tuple[bytes, SanitizeReport]:
    """
    Sanitize a PDF given as bytes; return the cleaned bytes.

    Args:
        data: The PDF file content as bytes.
        return_report: If True, return ``(cleaned_bytes, SanitizeReport)``.
            If False, return just the cleaned bytes.
        password: For encrypted PDFs.
        level: ``"strict"`` (default) or ``"balanced"``. See
            :func:`pdf_defang.sanitize` for the full semantics.
        raise_on_error: If True (default), a PDF that cannot be parsed or
            decrypted raises :class:`SanitizeError` instead of returning
            the untouched input. Set to False only if you handle the
            failure yourself - see the warning below.

    Returns:
        ``bytes`` if ``return_report`` is False - the sanitized PDF bytes.

        ``(bytes, SanitizeReport)`` if ``return_report`` is True.

    Raises:
        SanitizeError: If the PDF could not be parsed, or is encrypted and
            the password is missing or wrong. Nothing was stripped in that
            case. ``exc.report`` holds the details and ``exc.original``
            holds the input bytes.
        ValueError: If ``level`` is not ``"strict"`` or ``"balanced"``.

    Warning:
        With ``raise_on_error=False`` this returns the **original,
        unsanitized bytes** on failure - a value indistinguishable from a
        clean result. A caller that passes them straight back to a user
        serves exactly the file it meant to clean. Always check
        ``SanitizeReport.error`` in that mode.

    Note:
        Unlike :func:`pdf_defang.sanitize`, this does NOT modify any file
        on disk. Input bytes are read-only, output bytes are a fresh
        in-memory buffer.
    """
    _validate_level(level)
    report = SanitizeReport(level=level)
    report.file_size_before = len(data)

    try:
        with pikepdf.open(io.BytesIO(data), password=password or "") as pdf:
            encryption = _preserve_encryption(pdf, password)
            _strip_document_level(pdf, report, level)
            _strip_pages(pdf, report, level)
            out = io.BytesIO()
            if encryption is not None:
                pdf.save(out, encryption=encryption)
            else:
                pdf.save(out)
            cleaned = out.getvalue()
        report.modified = True
        report.file_size_after = len(cleaned)
    except pikepdf.PasswordError:
        report.error = "encrypted: password required or wrong"
        logger.warning("PDF sanitize_bytes needs password")
        return _handle_failure(
            data, report, raise_on_error=raise_on_error, return_report=return_report,
        )
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"
        logger.warning("PDF sanitize_bytes failed: %s", e)
        return _handle_failure(
            data, report, raise_on_error=raise_on_error, return_report=return_report,
        )

    return (cleaned, report) if return_report else cleaned


def scan_bytes(data: bytes, *, password: str | None = None) -> ScanReport:
    """
    Inspect a PDF given as bytes; return findings without modification.

    Args:
        data: The PDF file content as bytes.
        password: For encrypted PDFs.

    Returns:
        :class:`ScanReport` with detected findings and risk level.
    """
    report = ScanReport()
    report.file_size = len(data)

    try:
        with pikepdf.open(io.BytesIO(data), password=password or "") as pdf:
            report.page_count = len(pdf.pages)
            _scan_document_level(pdf, report)
            _scan_pages(pdf, report)
    except pikepdf.PasswordError:
        report.is_encrypted = True
        report.error = "encrypted: password required or wrong"
        return report
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"
        logger.warning("PDF scan_bytes failed: %s", e)
        return report

    report.risk_level = _calculate_risk(report)
    return report
