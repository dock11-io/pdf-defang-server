# pdf-defang

> Strip JavaScript, OpenAction, Launch actions and other active content from PDFs.
> Lightweight Python library on top of [pikepdf](https://github.com/pikepdf/pikepdf).
> MIT licensed.

## Why?

PDFs can carry executable content: JavaScript that runs when the file
opens, auto-actions that fire on every page navigation, "Launch" actions
that try to open other programs, embedded files that drop malware. If you
process user-uploaded PDFs in your app, you should strip this content
before serving them back.

The Python ecosystem has parsers (`pikepdf`, `pypdf`, `PyMuPDF`) and a
heavy container-based tool ([Dangerzone](https://dangerzone.rocks/)), but
no clean drop-in library that says "give me this PDF without active
content."

This is that library.

## What this protects against — and what it does not

**In scope:** content the PDF asks a viewer to *execute* — document and
annotation JavaScript, `/OpenAction` and `/AA` auto-actions, `/Launch` and the
other dangerous action types, embedded files, XFA, and `javascript:` / `file:`
/ `data:` URI actions. An actively exploited class, removed for a few
milliseconds per file.

**Out of scope:** memory-corruption bugs in the viewer's *parser* — the heap
overflows and use-after-frees that surface in PDFium and Acrobat several times
a year. They fire on malformed structure with no active content involved, and
no structural sanitizer touches them.

!!! warning "If hostile documents are your actual threat model, use Dangerzone"
    Untrusted senders, journalism, incident response — you want
    render-to-pixels reconstruction inside a disposable sandbox:
    [Dangerzone](https://dangerzone.rocks/). A library installed into your own
    process inevitably parses the hostile file *in* your process. The isolation
    is the protection, and a library cannot ship isolation.

    `pdf-defang` is a cheap, high-value layer for a normal web app that accepts
    PDF uploads and serves them back — one layer, not a guarantee.

## Install

```bash
pip install pdf-defang
```

Requires Python 3.9+ and pikepdf 8+.

## Three ways to use it

=== "Python API"

    ```python
    from pdf_defang import sanitize, scan

    # Clean a file in place
    sanitize("uploaded.pdf")

    # Inspect without modifying
    report = scan("suspicious.pdf")
    print(report.risk_level)  # 'high' / 'medium' / 'low' / 'none'
    ```

=== "Async API"

    ```python
    from pdf_defang import sanitize_async

    async def handle_upload(path):
        report = await sanitize_async(path, return_report=True)
        return report.as_dict()
    ```

=== "Bytes API"

    ```python
    from pdf_defang import SanitizeError, sanitize_bytes

    raw = await uploaded_file.read()
    try:
        cleaned = sanitize_bytes(raw)
    except SanitizeError:
        ...  # nothing was stripped - reject, don't serve the original
    # 'cleaned' is the sanitized PDF as bytes - no disk involved
    ```

=== "Command line"

    ```bash
    pdf-defang clean uploaded.pdf
    pdf-defang scan suspicious.pdf --json
    pdf-defang clean *.pdf  # batch
    ```

## Two levels: strict (default) vs balanced

```python
sanitize("untrusted.pdf")                       # level="strict" - safest
sanitize("internal_form.pdf", level="balanced") # keep form interactivity
```

Both levels strip the same attack vectors (JavaScript at document level,
`/Launch`, `/GoToR`, dangerous URI schemes, etc.). `balanced` keeps
form-related actions (`/SubmitForm`, `/ResetForm`, form JS, calculate
triggers) and embedded files alive when you trust the source. See
[Protections](protections.md) for the full matrix.

## What gets removed

A complete reference is on the [Protections page](protections.md). The
short list (everything below is stripped in both levels unless noted):

- Document-level **JavaScript**
- **OpenAction** and document **/AA** auto-execute actions
- **Launch**, **GoToR**, **GoToE**, **ImportData**, **Rendition**,
  **Movie**, **Sound** annotation actions
- Page-level **/AA**
- **XFA forms** (legacy attack surface)
- Dangerous **URI** schemes (`javascript:`, `file:`, `data:`, UNC paths)
- Strict-only: annotation **JavaScript / SubmitForm / ResetForm**,
  annotation `/AA` and `/JS`, AcroForm `/CO`, embedded files

What stays:

- All visible text, images, layout
- Standard form fields and their values
- Safe hyperlinks (`http`, `https`, `mailto`, `tel`, `ftp`)
- Bookmarks, table of contents, metadata, encryption

## Built by

[kovetz.co.il](https://kovetz.co.il) - Hebrew/English PDF tools.
Contact: [contact@kovetz.co.il](mailto:contact@kovetz.co.il).
