"""
Core sanitization logic. Removes embedded JavaScript, automatic actions,
launch actions, embedded files, XFA forms and other active content from
a PDF in place.
"""
from __future__ import annotations

import logging
import os
import warnings
from dataclasses import dataclass, field
from typing import Any, Literal, cast, overload

import pikepdf

logger = logging.getLogger(__name__)

# Two sanitization levels. ``strict`` is the safest default and is what
# kovetz.co.il runs in production. ``balanced`` keeps form interactivity
# and PDF portfolios working - use it only when you trust the source and
# need legitimate form/embedded-file behaviour to survive.
Level = Literal["strict", "balanced"]

# Action types we always treat as dangerous in ``strict`` mode (the full set).
_DANGEROUS_ACTION_TYPES: frozenset[str] = frozenset({
    "/JavaScript",    # in-document scripting
    "/Launch",        # open external executable
    "/ImportData",    # read external data into form fields
    "/SubmitForm",    # send form values to a URL
    "/ResetForm",     # clear form (used in social-engineering chains)
    "/Rendition",     # play media (legacy attack surface)
    "/GoToR",         # open another PDF file - can point to file:// or http://
    "/GoToE",         # open an embedded file - we strip /EmbeddedFiles too
    "/Movie",         # deprecated movie playback - kept dangerous for old readers
    "/Sound",         # deprecated sound playback - same
})

# Action types still considered dangerous in ``balanced`` mode. Form-related
# actions (``/JavaScript``, ``/SubmitForm``, ``/ResetForm``) are excluded so
# legitimate forms keep working; pure attack vectors are still stripped.
_DANGEROUS_ACTION_TYPES_BALANCED: frozenset[str] = frozenset({
    "/Launch",
    "/ImportData",
    "/Rendition",
    "/GoToR",
    "/GoToE",
    "/Movie",
    "/Sound",
})

# URI schemes we consider safe in annotation URI actions. URIs starting with
# anything outside this set (javascript:, file:, data:, etc.) are stripped.
# URIs with NO scheme (relative paths) are kept - they're usually legitimate
# in-document references.
_SAFE_URI_SCHEMES: frozenset[str] = frozenset({
    "http",
    "https",
    "mailto",
    "tel",
    "ftp",
    "sftp",
    "news",
    "nntp",
    "irc",
    "ircs",
    "magnet",
})


@dataclass
class SanitizeReport:
    """
    Detailed report of what was removed during sanitization.

    Returned when ``sanitize(..., return_report=True)`` is called. Useful for
    audit logs, compliance trails, and Sentry/OpenTelemetry breadcrumbs.
    """
    modified: bool = False
    level: Level = "strict"
    javascript_in_names: int = 0
    embedded_files: int = 0
    open_action_removed: bool = False
    document_aa_removed: bool = False
    xfa_form_removed: bool = False
    calculation_order_removed: bool = False
    pages_with_aa: int = 0
    annotations_with_actions: int = 0
    annotation_action_types: list[str] = field(default_factory=list)
    annotations_with_js: int = 0
    dangerous_uris_removed: int = 0
    dangerous_uri_schemes_removed: list[str] = field(default_factory=list)
    file_size_before: int = 0
    file_size_after: int = 0
    error: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Return the report as a plain dictionary (JSON-serialisable)."""
        return {
            "modified": self.modified,
            "level": self.level,
            "javascript_in_names": self.javascript_in_names,
            "embedded_files": self.embedded_files,
            "open_action_removed": self.open_action_removed,
            "document_aa_removed": self.document_aa_removed,
            "xfa_form_removed": self.xfa_form_removed,
            "calculation_order_removed": self.calculation_order_removed,
            "pages_with_aa": self.pages_with_aa,
            "annotations_with_actions": self.annotations_with_actions,
            "annotation_action_types": list(self.annotation_action_types),
            "annotations_with_js": self.annotations_with_js,
            "dangerous_uris_removed": self.dangerous_uris_removed,
            "dangerous_uri_schemes_removed": list(self.dangerous_uri_schemes_removed),
            "file_size_before": self.file_size_before,
            "file_size_after": self.file_size_after,
            "error": self.error,
        }


class SanitizeError(Exception):
    """
    Raised when a PDF could not be sanitized.

    The two causes are a PDF that cannot be parsed at all (truncated,
    corrupt, or not a PDF) and an encrypted PDF opened without the right
    password. In both cases nothing was stripped, so there is no cleaned
    output to return.

    This exists because the bytes API has no other way to signal failure:
    its success value and its failure value are both ``bytes``, so a caller
    that does not inspect a report cannot tell them apart and would serve
    the untouched input back to a user. Raising makes the failure
    impossible to ignore by accident.

    Attributes:
        report: The :class:`SanitizeReport` for the failed run. ``error``
            holds the underlying message; every count is zero.
        original: The input bytes, unmodified. Available so a caller that
            deliberately wants to fall back to the original (quarantine it,
            forward it to a different scanner) can still reach it.
    """

    def __init__(
        self,
        message: str,
        *,
        report: SanitizeReport,
        original: bytes | None = None,
    ) -> None:
        super().__init__(message)
        self.report = report
        self.original = original


@overload
def sanitize(
    pdf_path: str | os.PathLike[str],
    *,
    return_report: Literal[False] = False,
    password: str | None = None,
    level: Level = "strict",
) -> bool: ...


@overload
def sanitize(
    pdf_path: str | os.PathLike[str],
    *,
    return_report: Literal[True],
    password: str | None = None,
    level: Level = "strict",
) -> SanitizeReport: ...


def sanitize(
    pdf_path: str | os.PathLike[str],
    *,
    return_report: bool = False,
    password: str | None = None,
    level: Level = "strict",
) -> bool | SanitizeReport:
    """
    Strip active content from ``pdf_path`` in place.

    Args:
        pdf_path: Path to the PDF file to sanitize. Modified in place.
        return_report: If True, return a :class:`SanitizeReport` with details
            of what was removed. If False (default), return a simple
            boolean indicating whether the file was modified.
        password: If the PDF is encrypted, supply the password.
        level: Sanitization aggressiveness.

            * ``"strict"`` (default) - strip every form of active content,
              including form JavaScript, ``/SubmitForm``/``/ResetForm``
              actions, embedded files, and the AcroForm calculation order.
              The safest default for accepting PDFs from untrusted users.

            * ``"balanced"`` - preserve form interactivity and PDF
              portfolios. Form-related JavaScript, submit/reset buttons,
              annotation calculation triggers, and embedded files are kept;
              pure attack vectors (``/Launch``, ``/GoToR``, document
              JavaScript, dangerous URI schemes, etc.) are still stripped.

    Returns:
        ``bool`` when ``return_report`` is False - True if the file was
        modified, False on failure. Failure is non-fatal: the caller's
        original file is left in a usable state.

        :class:`SanitizeReport` when ``return_report`` is True.

    Raises:
        ValueError: If ``level`` is not ``"strict"`` or ``"balanced"``.

    Note:
        This function operates in place. If you need the original file
        preserved, copy it first.
    """
    _validate_level(level)
    report = SanitizeReport(level=level)
    try:
        report.file_size_before = os.path.getsize(pdf_path)
    except OSError:
        pass

    pdf_path_str = os.fspath(pdf_path)
    try:
        with pikepdf.open(pdf_path_str, allow_overwriting_input=True, password=password or "") as pdf:
            # Preserve encryption on save: if the input is encrypted, write the
            # output with the same encryption parameters. Without this, calling
            # sanitize() on an encrypted PDF would silently decrypt it.
            encryption = _preserve_encryption(pdf, password)
            _strip_document_level(pdf, report, level)
            _strip_pages(pdf, report, level)
            if encryption is not None:
                pdf.save(pdf_path_str, encryption=encryption)
            else:
                pdf.save(pdf_path_str)
        report.modified = True
        try:
            report.file_size_after = os.path.getsize(pdf_path)
        except OSError:
            pass
    except pikepdf.PasswordError:
        report.error = "encrypted: password required or wrong"
        logger.warning("PDF sanitization needs password for %s", _basename(pdf_path))
        return report if return_report else False
    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"
        logger.warning("PDF sanitization failed for %s: %s", _basename(pdf_path), e)
        warnings.warn(
            f"pdf-defang: sanitization failed for {_basename(pdf_path)}: {e}",
            RuntimeWarning,
            stacklevel=2,
        )
        return report if return_report else False

    return report if return_report else True


def _validate_level(level: str) -> None:
    if level not in ("strict", "balanced"):
        raise ValueError(
            f"level must be 'strict' or 'balanced', got {level!r}",
        )


def _dangerous_action_types(level: Level) -> frozenset[str]:
    """Return the set of annotation action types stripped under ``level``."""
    if level == "balanced":
        return _DANGEROUS_ACTION_TYPES_BALANCED
    return _DANGEROUS_ACTION_TYPES


def _strip_document_level(pdf: Any, report: SanitizeReport, level: Level) -> None:
    """Remove dangerous keys that live on the document Root."""
    root = pdf.Root

    if "/Names" in root:
        names = root.Names
        if "/JavaScript" in names:
            report.javascript_in_names = _count_named_tree_entries(names.JavaScript)
            del names["/JavaScript"]
        # Embedded files are kept in balanced mode - they're how PDF portfolios
        # ship attachments. In strict mode they're stripped because they're a
        # common malware delivery vehicle.
        if "/EmbeddedFiles" in names and level == "strict":
            report.embedded_files = _count_named_tree_entries(names.EmbeddedFiles)
            del names["/EmbeddedFiles"]

    if "/OpenAction" in root:
        del root["/OpenAction"]
        report.open_action_removed = True

    if "/AA" in root:
        del root["/AA"]
        report.document_aa_removed = True

    if "/AcroForm" in root:
        acro = root.AcroForm
        if "/XFA" in acro:
            del acro["/XFA"]
            report.xfa_form_removed = True
        # /CO drives form calculation order. Stripped in strict because it
        # can chain JavaScript triggers; kept in balanced because legitimate
        # forms depend on it.
        if "/CO" in acro and level == "strict":
            del acro["/CO"]
            report.calculation_order_removed = True


def _strip_pages(pdf: Any, report: SanitizeReport, level: Level) -> None:
    """Iterate pages, remove page-level AA and annotation-level active content."""
    dangerous_types = _dangerous_action_types(level)
    for page in pdf.pages:
        if "/AA" in page:
            del page["/AA"]
            report.pages_with_aa += 1

        if "/Annots" not in page:
            continue

        try:
            annots = list(page.Annots)
        except Exception:
            continue

        for annot in annots:
            _strip_annotation(annot, report, level, dangerous_types)


def _strip_annotation(
    annot: Any,
    report: SanitizeReport,
    level: Level,
    dangerous_types: frozenset[str],
) -> None:
    """Remove dangerous actions from a single annotation."""
    try:
        if "/A" in annot:
            action = annot.A
            stype = action.get("/S")
            stype_str = str(stype) if stype is not None else ""
            if stype_str in dangerous_types:
                report.annotations_with_actions += 1
                report.annotation_action_types.append(stype_str.lstrip("/"))
                del annot["/A"]
            elif stype_str == "/URI":
                # URI is normally safe (it's just a hyperlink), but the URL
                # itself can be a javascript:, file:, data:, or UNC path.
                uri_value = action.get("/URI")
                if uri_value is not None and not _is_safe_uri(str(uri_value)):
                    scheme = _extract_scheme(str(uri_value))
                    report.dangerous_uris_removed += 1
                    if scheme and scheme not in report.dangerous_uri_schemes_removed:
                        report.dangerous_uri_schemes_removed.append(scheme)
                    del annot["/A"]
        # Annotation /AA and /JS carry form calculation/format/validate triggers.
        # In strict mode we strip them; in balanced we keep them so the form
        # behaves as the author intended.
        if level == "strict":
            if "/AA" in annot:
                del annot["/AA"]
                report.annotations_with_actions += 1
            if "/JS" in annot:
                del annot["/JS"]
                report.annotations_with_js += 1
    except Exception:
        # Malformed annotation - skip rather than abort the whole file
        return


def _extract_scheme(uri: str) -> str:
    """Extract the URI scheme (lowercase). Returns '' for relative URIs."""
    if not uri:
        return ""
    uri = uri.strip()
    if uri.startswith("\\\\") or uri.startswith("//"):
        return "unc"  # UNC paths (Windows network shares) - always dangerous
    if ":" not in uri:
        return ""
    scheme = uri.split(":", 1)[0].lower().strip()
    # Sanity: real schemes are letters/digits/+/-/.
    if not scheme or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789+-." for c in scheme):
        return ""
    return scheme


def _is_safe_uri(uri: str) -> bool:
    """
    Return True if the URI is safe to keep (legitimate hyperlink).

    Safe = empty, relative (no scheme), or in the safe-scheme whitelist.
    Unsafe = javascript:, file:, data:, vbscript:, UNC paths (\\\\server),
    and any other scheme we don't explicitly trust.
    """
    if not uri or not uri.strip():
        return True
    scheme = _extract_scheme(uri)
    if not scheme:
        return True  # relative URI - usually a fragment or in-document link
    return scheme in _SAFE_URI_SCHEMES


def _count_named_tree_entries(tree: Any) -> int:
    """
    Best-effort count of entries in a PDF Name Tree. Returns 0 if the
    structure is unrecognised - we don't want a count to abort sanitization.
    """
    try:
        if "/Names" in tree:
            return len(tree["/Names"]) // 2  # name tree is [name, value, name, value, ...]
        if "/Kids" in tree:
            total = 0
            for kid in tree["/Kids"]:
                total += _count_named_tree_entries(kid)
            return total
    except Exception:
        return 0
    return 0


def _basename(path: str | os.PathLike[str]) -> str:
    try:
        return os.path.basename(str(path))
    except Exception:
        return "<pdf>"


def _preserve_encryption(pdf: Any, password: str | None) -> Any:
    """
    If the input PDF was encrypted, return a pikepdf.Encryption object that
    preserves the same encryption parameters on save. Returns None if the
    input was unencrypted (no encryption needed on save).

    Uses the same password for both owner and user passwords - we don't
    know the original owner password (might differ from the user password
    we received), but using the user password for both is safe and ensures
    the document remains password-protected.
    """
    if not pdf.is_encrypted:
        return None
    if not password:
        # Encrypted PDF was opened with empty password (rare - owner-pass-only)
        # In this case we can't re-encrypt with a known password, so we save unencrypted.
        return None
    # Match the original PDF's encryption strength when we can.
    # R=6 = AES-256 (PDF 2.0). R=4 = AES-128. R=2/3 = RC4 (avoid - upgrade to 4).
    # Type ignored because pikepdf accepts ints at runtime, but the stub
    # uses a Literal.
    try:
        enc_info = getattr(pdf, "encryption", None)
        revision_raw = getattr(enc_info, "R", 4) if enc_info else 4
        revision: int = max(4, int(revision_raw)) if isinstance(revision_raw, int) else 4
        if revision == 5:
            # R=5 was a transitional revision, not in PDF 2.0 spec - prefer R=6
            revision = 6
        if revision > 6:
            revision = 6
        return pikepdf.Encryption(
            owner=password,
            user=password,
            R=cast("Literal[2, 3, 4, 5, 6]", revision),
        )
    except Exception:
        return pikepdf.Encryption(owner=password, user=password, R=4)
