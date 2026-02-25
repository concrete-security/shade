#!/usr/bin/env python3
"""Update one image reference in src/shade/versions.py and docker-compose.yml.

This script updates exactly one service key line in versions.py and the
matching image line in docker-compose.yml.  It accepts any pinned image
reference (tag-based or digest-based).
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import oras.client


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Update a Shade image ref in versions.py and docker-compose.yml"
    )
    parser.add_argument("--service-key", required=True, help="Service key in VERSIONS map")
    parser.add_argument("--image-ref", required=True, help="Full image ref (tag or digest)")
    parser.add_argument(
        "--versions-file",
        default="src/shade/versions.py",
        help="Path to versions.py",
    )
    parser.add_argument(
        "--compose-file",
        default="docker-compose.yml",
        help="Path to docker-compose.yml",
    )
    parser.add_argument(
        "--skip-compose",
        action="store_true",
        help="Skip updating docker-compose.yml",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip verifying that the image exists in the registry",
    )
    return parser.parse_args()


def verify_image_exists(image_ref: str) -> None:
    """Verify that the image exists in the registry using oras Python SDK."""
    client = oras.client.OrasClient()
    try:
        client.remote.get_manifest(image_ref)
    except Exception as exc:
        raise SystemExit(f"image not found in registry: {image_ref}\n{exc}") from exc
    print(f"verify: image exists in registry: {image_ref}")


def update_versions_file(versions_path: Path, service_key: str, image_ref: str) -> bool:
    """Update the image ref in versions.py. Returns True if file was changed."""
    content = versions_path.read_text(encoding="utf-8")

    pattern = re.compile(
        rf'(^\s*"{re.escape(service_key)}":\s*")([^"]+)(",\s*$)',
        re.MULTILINE,
    )

    total_matches = len(pattern.findall(content))
    if total_matches != 1:
        raise SystemExit(
            f"expected exactly one '{service_key}' image entry, found {total_matches}"
        )

    updated, replaced = pattern.subn(
        lambda m: f'{m.group(1)}{image_ref}{m.group(3)}',
        content,
        count=1,
    )

    if replaced != 1:
        raise SystemExit(f"failed to update '{service_key}' image entry")

    if updated == content:
        print(f"versions.py: no changes needed for {service_key}.")
        return False

    versions_path.write_text(updated, encoding="utf-8")
    print(f"versions.py: updated {service_key} image ref to {image_ref}")
    return True


def update_compose_file(compose_path: Path, service_key: str, image_ref: str) -> bool:
    """Update the image ref in docker-compose.yml. Returns True if file was changed."""
    if not compose_path.exists():
        print(f"compose: {compose_path} not found, skipping.")
        return False

    content = compose_path.read_text(encoding="utf-8")

    # Extract the image name (without tag or digest)
    image_name = image_ref.split("@")[0].split(":")[0]

    # Match image lines with either tag or digest format
    pattern = re.compile(
        rf"(^\s*image:\s*){re.escape(image_name)}(?::[^\s@]+|@sha256:[0-9a-f]{{64}})\s*$",
        re.MULTILINE,
    )

    total_matches = len(pattern.findall(content))
    if total_matches == 0:
        print(f"compose: no image entry for {service_key} in {compose_path}, skipping.")
        return False

    updated, replaced = pattern.subn(
        lambda m: f"{m.group(1)}{image_ref}",
        content,
    )

    if replaced == 0 or updated == content:
        print(f"compose: no changes needed for {service_key}.")
        return False

    compose_path.write_text(updated, encoding="utf-8")
    print(f"compose: updated {replaced} image ref(s) for {service_key} in {compose_path}")
    return True


def main() -> int:
    args = parse_args()
    image_ref = args.image_ref.strip()
    if ":" not in image_ref and "@" not in image_ref:
        raise SystemExit(f"image ref must include a tag or digest: {image_ref}")

    if not args.no_verify:
        verify_image_exists(image_ref)

    update_versions_file(Path(args.versions_file), args.service_key, image_ref)

    if not args.skip_compose:
        update_compose_file(Path(args.compose_file), args.service_key, image_ref)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
