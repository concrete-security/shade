#!/usr/bin/env python3
"""Update one image reference in src/shade/versions.py.

This script intentionally updates exactly one service key line:
  "service-key": "ghcr.io/...@sha256:..."
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update a Shade image digest in versions.py")
    parser.add_argument("--service-key", required=True, help="Service key in VERSIONS map")
    parser.add_argument("--image-ref", required=True, help="Full image ref with digest")
    parser.add_argument(
        "--versions-file",
        default="src/shade/versions.py",
        help="Path to versions.py",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    image_ref = args.image_ref.strip()
    if "@sha256:" not in image_ref:
        raise SystemExit(f"image ref must be digest-pinned: {image_ref}")

    versions_path = Path(args.versions_file)
    content = versions_path.read_text(encoding="utf-8")

    pattern = re.compile(
        rf'(^\s*"{re.escape(args.service_key)}":\s*")([^"]+)(",\s*$)',
        re.MULTILINE,
    )

    total_matches = len(pattern.findall(content))
    if total_matches != 1:
        raise SystemExit(
            f"expected exactly one '{args.service_key}' image entry, found {total_matches}"
        )

    updated, replaced = pattern.subn(
        lambda m: f'{m.group(1)}{image_ref}{m.group(3)}',
        content,
        count=1,
    )

    if replaced != 1:
        raise SystemExit(f"failed to update '{args.service_key}' image entry")

    if updated == content:
        print("No changes needed.")
        return 0

    versions_path.write_text(updated, encoding="utf-8")
    print(f"Updated {args.service_key} image ref to {image_ref}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
