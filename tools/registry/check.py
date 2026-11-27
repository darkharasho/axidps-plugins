#!/usr/bin/env python3
"""Checks one downloaded package zip against its registry entry and version, as the overlay's
install would. Run with `python3 -I`; the zip is data and is never unpacked to disk.

    python3 -I tools/registry/check.py <package.zip> <plugins/<id>.json> <version>

Prints a JSON object {problems, manifest, tree, sha256, deeper} and exits 0 when there are no
problems, 1 when there are, 2 on wrong usage."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402


def run(zip_path, entry, version):
    manifest, tree, sha, problems = lib.check_package(zip_path, entry, version)
    return {
        "problems": problems,
        "manifest": manifest,
        "tree": tree,
        "sha256": sha,
        "deeper": lib.deeper(manifest["permissions"]) if manifest else [],
    }


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    zip_path, entry_path, version = argv
    with open(entry_path, "rb") as f:
        entry = json.load(f)
    result = run(zip_path, entry, version)
    print(json.dumps(result, indent=1, sort_keys=True))
    return 1 if result["problems"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
