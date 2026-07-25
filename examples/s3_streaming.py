"""
Sanitize PDFs streamed from S3 (or any byte source) without writing to
local disk.

Uses sanitize_bytes() to keep everything in memory. Useful for:
- Serverless (Lambda) where /tmp is limited
- High-throughput pipelines that can't afford disk I/O
- Compliance environments that forbid local PDF storage

Run with:
    pip install pdf-defang boto3
    python examples/s3_streaming.py s3://my-bucket/incoming/ s3://my-bucket/cleaned/

This is illustrative pseudocode for the S3 part - swap in your own
storage client.
"""
from __future__ import annotations

import argparse
import logging
import sys
from typing import Iterator, Tuple

from pdf_defang import SanitizeError, sanitize_bytes


logger = logging.getLogger("s3_streaming")


# ── Mock S3 client for illustration ──────────────────────────────────────────
# Replace this with boto3.client("s3") in real usage.


class FakeS3:
    """Stand-in for boto3.client('s3'). Replace with the real client."""

    def __init__(self) -> None:
        self._storage: dict[str, bytes] = {}

    def list_objects(self, prefix: str) -> Iterator[str]:
        for key in sorted(self._storage):
            if key.startswith(prefix):
                yield key

    def get_object(self, key: str) -> bytes:
        return self._storage[key]

    def put_object(self, key: str, data: bytes) -> None:
        self._storage[key] = data


# ── Pipeline ─────────────────────────────────────────────────────────────────


def process_bucket(
    s3_client,
    source_prefix: str,
    dest_prefix: str,
    quarantine_prefix: str,
    level: str = "strict",
) -> Tuple[int, int, int]:
    """
    Walk source_prefix, sanitize each PDF, write to dest_prefix.
    Files that fail to sanitize go to quarantine_prefix instead.

    ``level`` is forwarded to ``sanitize_bytes``. Default ``"strict"`` is
    correct for untrusted ingest; switch to ``"balanced"`` only for
    pipelines processing trusted internal documents that need form
    interactivity preserved.

    Returns (success, modified, failed) counts.
    """
    success = 0
    modified = 0
    failed = 0

    for key in s3_client.list_objects(source_prefix):
        if not key.lower().endswith(".pdf"):
            continue

        logger.info("Processing %s", key)
        raw = s3_client.get_object(key)

        try:
            cleaned, report = sanitize_bytes(raw, return_report=True, level=level)
        except SanitizeError as exc:
            # Nothing was stripped. The original goes to quarantine, never
            # to the destination prefix.
            failed += 1
            quarantine_key = key.replace(source_prefix, quarantine_prefix, 1)
            s3_client.put_object(quarantine_key, raw)
            logger.warning("  -> quarantined: %s", exc)
            continue

        dest_key = key.replace(source_prefix, dest_prefix, 1)
        s3_client.put_object(dest_key, cleaned)
        success += 1

        # Did we actually remove anything?
        if (
            report.javascript_in_names
            or report.open_action_removed
            or report.annotations_with_actions
            or report.dangerous_uris_removed
        ):
            modified += 1
            logger.info(
                "  -> cleaned (size %d -> %d, JS=%d, URIs=%d)",
                report.file_size_before, report.file_size_after,
                report.javascript_in_names, report.dangerous_uris_removed,
            )

    return success, modified, failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Source prefix (e.g., incoming/)")
    parser.add_argument("dest", help="Destination prefix (e.g., cleaned/)")
    parser.add_argument(
        "--quarantine", default="quarantine/",
        help="Prefix for files that failed to sanitize (default: quarantine/)",
    )
    parser.add_argument(
        "--level", "-l", choices=("strict", "balanced"), default="strict",
        help="Sanitization level. 'strict' (default) for untrusted ingest; "
             "'balanced' to keep form interactivity on trusted sources.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # In real usage:
    # import boto3
    # s3 = boto3.client("s3")
    s3 = FakeS3()
    # ... populate with test data for demo

    success, modified, failed = process_bucket(
        s3, args.source, args.dest, args.quarantine, level=args.level,
    )

    print(f"\nDone: {success} processed ({modified} had content removed), {failed} quarantined.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
