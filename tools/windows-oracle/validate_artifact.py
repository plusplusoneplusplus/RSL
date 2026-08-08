#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-configuration", default="Release")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    root = args.directory.resolve()
    manifest_path = root / "artifact-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    if manifest.get("artifactSchemaVersion") != 1:
        fail("unsupported artifact schema")
    if manifest["generator"]["identity"] != "rsl-windows-production-oracle":
        fail("unexpected generator identity")

    provenance = manifest["provenance"]
    if args.expected_revision and provenance["sourceRevision"] != args.expected_revision:
        fail("source revision does not match the workflow checkout")
    if provenance["configuration"] != args.expected_configuration:
        fail("unexpected generator configuration")
    if provenance["architecture"] != "x86_64":
        fail("authoritative artifact was not generated on x86_64")
    if provenance["sourceDirty"] and not args.allow_dirty:
        fail("authoritative artifact came from a dirty worktree")

    declared = {}
    for item in manifest["files"]:
        relative = item["path"]
        if relative in declared:
            fail(f"duplicate file entry: {relative}")
        path = root / relative
        if not path.is_file():
            fail(f"missing file: {relative}")
        if path.stat().st_size != item["size"]:
            fail(f"size mismatch: {relative}")
        if sha256(path) != item["sha256"]:
            fail(f"SHA-256 mismatch: {relative}")
        declared[relative] = path

    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual != set(declared):
        fail(
            f"artifact file set mismatch: missing={sorted(set(declared) - actual)}, "
            f"extra={sorted(actual - set(declared))}"
        )

    wire_manifest = json.loads(
        declared[manifest["corpora"]["wireManifest"]].read_text(encoding="utf-8")
    )
    storage_manifest = json.loads(
        declared[manifest["corpora"]["storageManifest"]].read_text(encoding="utf-8")
    )
    for name, inner in (("wire", wire_manifest), ("storage", storage_manifest)):
        if inner.get("schemaVersion") != 1:
            fail(f"{name} manifest schema mismatch")
        generator = inner.get("generator", {})
        if generator.get("identity") != manifest["generator"]["identity"]:
            fail(f"{name} manifest generator mismatch")
        if generator.get("sourceRevision") != provenance["sourceRevision"]:
            fail(f"{name} manifest source revision mismatch")
        if generator.get("sourceDirty") != provenance["sourceDirty"]:
            fail(f"{name} manifest dirty flag mismatch")
        if generator.get("architecture") != provenance["architecture"]:
            fail(f"{name} manifest architecture mismatch")
        if generator.get("configuration") != provenance["configuration"]:
            fail(f"{name} manifest configuration mismatch")

    storage_names = {item["file"] for item in storage_manifest["files"]}
    required_large = {"600.codex", "601.codex", "602.codex"}
    if not required_large.issubset(storage_names):
        fail("full storage corpus is missing block-boundary checkpoints")

    print(
        f"validated schema 1 artifact from {provenance['sourceRevision']} "
        f"with {len(declared)} hashed files"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"artifact validation failed: {error}", file=sys.stderr)
        sys.exit(1)
