"""Tests for the bytes-in/bytes-out API."""
from __future__ import annotations

import pikepdf
import pytest

from pdf_defang import (
    SanitizeError,
    SanitizeReport,
    ScanReport,
    sanitize_bytes,
    scan_bytes,
)


class TestSanitizeBytes:
    def test_returns_bytes(self, fixture_pdf):
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        result = sanitize_bytes(raw)
        assert isinstance(result, bytes)
        assert result.startswith(b"%PDF")

    def test_does_not_modify_input(self, fixture_pdf):
        """Verify the input bytes object is not mutated."""
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        original_raw = bytes(raw)  # immutable copy

        sanitize_bytes(raw)
        assert raw == original_raw

    def test_does_not_touch_disk(self, fixture_pdf):
        """Sanitize_bytes should NOT modify the source file."""
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        original_file_bytes = path.read_bytes()

        sanitize_bytes(raw)

        # Source file unchanged
        assert path.read_bytes() == original_file_bytes

    def test_removes_js_from_bytes(self, fixture_pdf):
        path = fixture_pdf("with_js.pdf")
        raw = path.read_bytes()
        cleaned, report = sanitize_bytes(raw, return_report=True)

        assert report.javascript_in_names >= 1

        # Open the cleaned bytes and verify JS is gone
        import io
        with pikepdf.open(io.BytesIO(cleaned)) as pdf:
            if "/Names" in pdf.Root:
                assert "/JavaScript" not in pdf.Root.Names

    def test_invalid_pdf_raises(self):
        """A file we cannot parse must never come back looking like a result."""
        garbage = b"not a pdf"
        with pytest.raises(SanitizeError) as excinfo:
            sanitize_bytes(garbage)

        exc = excinfo.value
        assert exc.report.error is not None
        assert exc.report.modified is False
        assert exc.original == garbage

    def test_invalid_pdf_raises_with_report_requested(self):
        """return_report=True does not downgrade the failure to a return value."""
        with pytest.raises(SanitizeError):
            sanitize_bytes(b"not a pdf", return_report=True)

    def test_invalid_pdf_passthrough_when_opted_out(self):
        """raise_on_error=False keeps the old behaviour - but warns loudly."""
        garbage = b"not a pdf"
        with pytest.warns(RuntimeWarning, match="UNSANITIZED"):
            cleaned, report = sanitize_bytes(
                garbage, return_report=True, raise_on_error=False,
            )
        assert cleaned == garbage
        assert report.error is not None

    def test_invalid_pdf_passthrough_without_report(self):
        garbage = b"not a pdf"
        with pytest.warns(RuntimeWarning):
            cleaned = sanitize_bytes(garbage, raise_on_error=False)
        assert cleaned == garbage

    def test_valid_pdf_does_not_warn_or_raise(self, fixture_pdf, recwarn):
        """The happy path stays silent - no warning noise on every clean file."""
        raw = fixture_pdf("with_js.pdf").read_bytes()
        cleaned = sanitize_bytes(raw)
        assert cleaned != raw
        assert not [w for w in recwarn if issubclass(w.category, RuntimeWarning)]

    def test_returns_report_tuple_when_requested(self, fixture_pdf):
        path = fixture_pdf("with_everything.pdf")
        raw = path.read_bytes()
        result = sanitize_bytes(raw, return_report=True)

        assert isinstance(result, tuple)
        assert len(result) == 2
        cleaned, report = result
        assert isinstance(cleaned, bytes)
        assert isinstance(report, SanitizeReport)
        assert report.javascript_in_names >= 1

    def test_encrypted_with_password(self, fixture_pdf):
        path = fixture_pdf("encrypted_with_js.pdf")
        raw = path.read_bytes()
        cleaned, report = sanitize_bytes(
            raw, return_report=True, password="secret123",
        )
        assert report.error is None
        assert report.javascript_in_names >= 1

    def test_encrypted_wrong_password_raises(self, fixture_pdf):
        path = fixture_pdf("encrypted_with_js.pdf")
        raw = path.read_bytes()
        with pytest.raises(SanitizeError) as excinfo:
            sanitize_bytes(raw, return_report=True, password="wrong")

        assert "password" in str(excinfo.value)
        assert excinfo.value.original == raw

    def test_encrypted_wrong_password_passthrough_when_opted_out(self, fixture_pdf):
        path = fixture_pdf("encrypted_with_js.pdf")
        raw = path.read_bytes()
        with pytest.warns(RuntimeWarning):
            cleaned, report = sanitize_bytes(
                raw, return_report=True, password="wrong", raise_on_error=False,
            )
        assert report.error is not None
        # Should return original input unchanged on error
        assert cleaned == raw


class TestScanBytes:
    def test_returns_report(self, fixture_pdf):
        raw = fixture_pdf("clean.pdf").read_bytes()
        report = scan_bytes(raw)
        assert isinstance(report, ScanReport)
        assert report.risk_level == "none"

    def test_detects_high_risk(self, fixture_pdf):
        raw = fixture_pdf("with_everything.pdf").read_bytes()
        report = scan_bytes(raw)
        assert report.risk_level == "high"
        assert report.has_javascript

    def test_encrypted_no_password(self, fixture_pdf):
        raw = fixture_pdf("encrypted_with_js.pdf").read_bytes()
        report = scan_bytes(raw)
        assert report.is_encrypted is True

    def test_encrypted_with_password(self, fixture_pdf):
        raw = fixture_pdf("encrypted_with_js.pdf").read_bytes()
        report = scan_bytes(raw, password="secret123")
        assert report.is_encrypted is False
        assert report.has_javascript

    def test_invalid_pdf_returns_error(self):
        report = scan_bytes(b"not a pdf")
        assert report.error is not None
