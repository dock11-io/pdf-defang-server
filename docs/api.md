# API Reference

Full reference for `pdf_defang` public symbols. All are importable from
the top level::

    from pdf_defang import (
        sanitize, scan,
        sanitize_async, scan_async,
        sanitize_bytes, scan_bytes,
        SanitizeReport, ScanReport, SanitizeError, Level,
    )

## Sanitization levels

`sanitize()`, `sanitize_async()` and `sanitize_bytes()` all accept a
`level` keyword. Two values are supported:

| `level` | Form interactivity | Embedded files | Use when |
|---|---|---|---|
| `"strict"` *(default)* | stripped | stripped | Accepting PDFs from untrusted users. The safest default. |
| `"balanced"` | preserved | preserved | You trust the source and need legitimate form/portfolio behaviour to survive. |

Both levels strip the same set of pure attack vectors: document
JavaScript, `/OpenAction`, document `/AA`, XFA forms, page `/AA`, and
dangerous URI schemes (`javascript:`, `file:`, `data:`, UNC paths,
etc.), plus the annotation action types `/Launch`, `/ImportData`,
`/GoToR`, `/GoToE`, `/Movie`, `/Sound`, `/Rendition`.

`balanced` additionally **keeps**: `/SubmitForm` and `/ResetForm`
annotation actions, `/JavaScript` annotation actions (for form
calculations), annotation `/AA` (calculate / format / validate / blur /
focus triggers), annotation `/JS` keys, the AcroForm `/CO` calculation
order, and `/EmbeddedFiles` (used by PDF portfolios).

Passing any other string raises `ValueError`. See
[Protections](protections.md) for the full removal table.

## Sync API

### `sanitize(pdf_path, *, return_report=False, password=None, level="strict")`

Strip active content from a PDF in place.

**Arguments:**

- `pdf_path` (`str` or `os.PathLike`): Path to the PDF file. Modified in place.
- `return_report` (`bool`): If `True`, return a `SanitizeReport`. If
  `False` (default), return a simple boolean.
- `password` (`str`, optional): Password for encrypted PDFs.
- `level` (`"strict"` or `"balanced"`): Sanitization aggressiveness.
  Default `"strict"`. See [Sanitization levels](#sanitization-levels).

**Returns:**

- `bool` when `return_report=False`. `True` if modified, `False` on
  failure.
- `SanitizeReport` when `return_report=True`.

**Raises:** `ValueError` if `level` is not `"strict"` or `"balanced"`.

**Encryption preservation:** If the input PDF is encrypted and you supply
the correct password, the output PDF stays encrypted (same password,
modern AES). If you don't supply a password and the PDF is encrypted,
sanitization fails cleanly without modifying the file.

### `scan(pdf_path, *, password=None)`

Inspect a PDF and return what dangerous content it contains. Does **not**
modify the file.

**Arguments:**

- `pdf_path`: Path to the PDF.
- `password`: Password for encrypted PDFs.

**Returns:** `ScanReport`. Always returns - errors are reflected in
`report.error`, not raised.

## Async API

### `sanitize_async(...)`, `scan_async(...)`

Same arguments and return types as the sync versions, but they `await`
under the hood (offloaded to a thread pool, non-blocking in asyncio).

Use these in FastAPI, aiohttp, Starlette, or any other asyncio-based
framework.

## Bytes API

### `sanitize_bytes(data, *, return_report=False, password=None, level="strict", raise_on_error=True)`

Sanitize a PDF given as `bytes`. Returns cleaned bytes.

**Arguments:**

- `data` (`bytes`): The PDF file content.
- `return_report` (`bool`): If `True`, returns `(bytes, SanitizeReport)`.
- `password`: For encrypted PDFs.
- `level` (`"strict"` or `"balanced"`): Same semantics as
  `sanitize()`. Default `"strict"`.
- `raise_on_error` (`bool`, default `True`): Raise `SanitizeError` when the
  PDF cannot be parsed or decrypted, instead of returning the untouched
  input. See the warning below before turning this off.

**Returns:**

- `bytes` (cleaned PDF) when `return_report=False`.
- `tuple[bytes, SanitizeReport]` when `return_report=True`.

**Raises:**

- `SanitizeError` if the PDF could not be parsed, or is encrypted and the
  password is missing or wrong. Nothing was stripped. `exc.report` holds the
  details; `exc.original` holds the input bytes.
- `ValueError` if `level` is not `"strict"` or `"balanced"`.

!!! danger "`raise_on_error=False` fails open"
    In that mode a failure returns the **original, unsanitized bytes** - a
    value indistinguishable from a clean result. Code that passes the return
    value straight back to a user serves exactly the file it meant to clean.
    Always check `SanitizeReport.error` if you opt out. A `RuntimeWarning` is
    emitted on every such failure.

```python
from pdf_defang import SanitizeError, sanitize_bytes

try:
    cleaned = sanitize_bytes(raw)
except SanitizeError as exc:
    # Nothing was stripped - reject, quarantine, or route elsewhere.
    # Do NOT serve exc.original to the user.
    return reject(str(exc))
```

### `scan_bytes(data, *, password=None)`

Inspect a PDF given as `bytes`. Returns `ScanReport`.

## Data classes

### `SanitizeReport`

Returned by `sanitize(..., return_report=True)` and `sanitize_bytes(...)`.

Fields:

| Field | Type | Meaning |
|---|---|---|
| `modified` | `bool` | Whether the file was successfully processed |
| `level` | `"strict"` or `"balanced"` | Level that was applied |
| `javascript_in_names` | `int` | JS entries removed from `/Names → /JavaScript` |
| `embedded_files` | `int` | Embedded files removed |
| `open_action_removed` | `bool` | Whether `/OpenAction` was present and removed |
| `document_aa_removed` | `bool` | Whether document-level `/AA` was removed |
| `xfa_form_removed` | `bool` | Whether XFA form was removed |
| `calculation_order_removed` | `bool` | Whether `/CO` was removed |
| `pages_with_aa` | `int` | Pages where `/AA` was removed |
| `annotations_with_actions` | `int` | Dangerous annotation actions removed |
| `annotation_action_types` | `list[str]` | Types found (e.g., `['Launch', 'JavaScript']`) |
| `annotations_with_js` | `int` | Annotations with `/JS` removed |
| `dangerous_uris_removed` | `int` | URI actions with dangerous schemes removed |
| `dangerous_uri_schemes_removed` | `list[str]` | Schemes found (e.g., `['javascript', 'file']`) |
| `file_size_before` | `int` | Bytes before |
| `file_size_after` | `int` | Bytes after |
| `error` | `str` or `None` | Error message if sanitization failed |

Helper: `report.as_dict()` returns a JSON-serialisable plain dict.

### `SanitizeError`

Raised by `sanitize_bytes()` when the PDF could not be parsed or decrypted.
Subclass of `Exception`.

| Attribute | Type | Meaning |
|---|---|---|
| `report` | `SanitizeReport` | The failed run's report; `error` holds the underlying message |
| `original` | `bytes` or `None` | The input bytes, unmodified |

`original` exists so a caller that deliberately wants the untouched file
(quarantine it, hand it to another scanner) can still reach it - not so it
can be served to a user.

### `ScanReport`

Returned by `scan()` and `scan_bytes()`.

Fields:

| Field | Type | Meaning |
|---|---|---|
| `has_javascript` | `bool` | Document JavaScript detected |
| `has_open_action` | `bool` | `/OpenAction` detected |
| `has_document_aa` | `bool` | Document `/AA` detected |
| `has_xfa_form` | `bool` | XFA form detected |
| `has_embedded_files` | `bool` | Embedded files detected |
| `javascript_in_names` | `int` | Count of JS entries |
| `embedded_files_count` | `int` | Count of embedded files |
| `pages_with_aa` | `int` | Pages with `/AA` |
| `annotations_with_actions` | `int` | Dangerous annotation count |
| `annotation_action_types` | `list[str]` | Types found |
| `annotations_with_js` | `int` | Annotations with /JS |
| `dangerous_uris` | `int` | URI actions with dangerous schemes |
| `dangerous_uri_schemes` | `list[str]` | Schemes found |
| `page_count` | `int` | Total pages in PDF |
| `is_encrypted` | `bool` | True if PDF is encrypted and no password given |
| `risk_level` | `Literal["none", "low", "medium", "high"]` | Bucketed risk |
| `file_size` | `int` | Total bytes |
| `error` | `str` or `None` | Error if scanning failed |

Helper: `report.as_dict()` returns a plain dict.

#### Risk level rules

- **`high`**: Document JavaScript, OpenAction, document `/AA`, XFA form,
  Launch/ImportData/GoToR annotation action, or dangerous URI
  (`javascript:`, `file:`, UNC, etc.).
- **`medium`**: Annotation actions other than the high-risk ones,
  embedded files, page-level `/AA`.
- **`low`**: Annotation with `/JS` but no execution trigger.
- **`none`**: Nothing dangerous detected.
