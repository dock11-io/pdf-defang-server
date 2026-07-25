"""
pdf-defang
==========

Strip JavaScript, OpenAction, Launch actions and other active content
from PDFs. Lightweight Python library on top of pikepdf.

Quick start::

    from pdf_defang import sanitize, scan

    # Clean a file in place
    sanitize("uploaded.pdf")

    # Inspect without modifying
    report = scan("suspicious.pdf")
    print(report.risk_level)  # 'high' / 'medium' / 'low' / 'none'

See https://github.com/kovetz-PDF/pdf-defang for full docs.
"""
from ._async import sanitize_async, scan_async
from ._bytes import sanitize_bytes, scan_bytes
from ._core import Level, SanitizeError, SanitizeReport, sanitize
from ._scan import ScanReport, scan

__version__ = "0.2.0"
__all__ = [
    "sanitize",
    "scan",
    "sanitize_async",
    "scan_async",
    "sanitize_bytes",
    "scan_bytes",
    "SanitizeError",
    "SanitizeReport",
    "ScanReport",
    "Level",
    "__version__",
]
