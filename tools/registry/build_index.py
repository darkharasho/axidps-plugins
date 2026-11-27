#!/usr/bin/env python3
"""Builds the store index from a registry checkout and its mirrored package zips, and signs it
with the index key from the INDEX_KEY environment variable (a PKCS#8 PEM; CI only).

    INDEX_KEY=... python3 -I tools/registry/build_index.py --root . --packages <dir> \\
        --out <dir> [--previous <old index.json>] [--generated 2026-11-26T12:00:00Z]

<dir> holds one `<id>@<version>.zip` per mirrored version. Writes <out>/index.json and
<out>/index.json.sig. With --previous, an index that differs only in `generated` keeps the old
time, so its bytes (and signature) don't change. Approvals, passes and revoked.json are copied
only if they verify against keys/approvers.txt; the client checks them again itself."""

import argparse
import datetime
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402


def semver_key(v):
    m = lib._SEMVER.fullmatch(v)
    pre = m.group(4)
    ids = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split(".")) if pre else ()
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, ids)


def _load(path):
    with open(path, "rb") as f:
        return json.load(f)


def _listing(entry, packages, warnings):
    pid = entry["id"]
    versions, newest = [], None
    for v in sorted(entry["versions"], key=lambda v: semver_key(v["version"])):
        ver = v["version"]
        zip_path = os.path.join(packages, lib.mirror_tag(pid, ver) + ".zip")
        if not os.path.isfile(zip_path):
            warnings.append(f"{pid} {ver} skipped: not mirrored yet")
            continue
        manifest, tree, sha, problems = lib.check_package(zip_path, entry, ver)
        if problems:
            warnings.append(f"{pid} {ver} skipped: {'; '.join(problems)}")
            continue
        versions.append({
            "version": ver, "url": lib.package_url(pid, ver), "sha256": sha, "tree": tree,
            "permissions": manifest["permissions"], "network": manifest["network"],
            "api": manifest["api"],
        })
        newest = manifest
    if not versions:
        return None
    return {
        "id": pid,
        "name": newest["name"],
        "author": newest["author"] or entry["owner"],
        "description": entry.get("description", ""),
        "icon": entry.get("icon") or newest["windows"][0]["icon"],
        "repo": entry["repo"],
        "elevated": entry["elevated"],
        "versions": versions,
    }


def _signed(kind, path, rel, keys, warnings, check_path):
    try:
        obj = _load(path)
    except (OSError, ValueError) as e:
        warnings.append(f"{rel} refused: {e}")
        return None
    why = lib.shape_problems(kind, obj) or check_path(obj)
    if not why and not lib.verify(kind, obj, keys):
        why = ["its signature doesn't verify against keys/approvers.txt"]
    if why:
        warnings.append(f"{rel} refused: {'; '.join(why)}")
        return None
    return obj


def approval_path_problems(rel, obj):
    want = f"approvals/{obj.get('id')}/{obj.get('version')}.json"
    return [] if rel == want else [f"it signs {obj.get('id')} {obj.get('version')}, not {rel}"]


def pass_path_problems(rel, obj):
    want = f"passes/{obj.get('login')}.json"
    return [] if rel == want else [f"it is the pass of {obj.get('login')}, not {rel}"]


def build(root, packages, generated):
    """(index, warnings): the index object and one line per thing left out."""
    warnings = []
    keys = lib.load_approvers(os.path.join(root, "keys", "approvers.txt"))
    plugins = []
    for path in sorted(glob.glob(os.path.join(root, "plugins", "*.json"))):
        file_id = os.path.basename(path)[:-len(".json")]
        try:
            entry = _load(path)
        except (OSError, ValueError) as e:
            warnings.append(f"plugins/{file_id}.json skipped: {e}")
            continue
        problems = lib.check_entry(entry, file_id)
        if problems:
            warnings.append(f"plugins/{file_id}.json skipped: {'; '.join(problems)}")
            continue
        listing = _listing(entry, packages, warnings)
        if listing:
            plugins.append(listing)

    approvals = []
    for path in sorted(glob.glob(os.path.join(root, "approvals", "*", "*.json"))):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        obj = _signed("approval", path, rel, keys, warnings,
                      lambda o, rel=rel: approval_path_problems(rel, o))
        if obj:
            approvals.append(obj)
    passes = []
    for path in sorted(glob.glob(os.path.join(root, "passes", "*.json"))):
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        obj = _signed("pass", path, rel, keys, warnings,
                      lambda o, rel=rel: pass_path_problems(rel, o))
        if obj:
            passes.append(obj)
    revoked = None
    rpath = os.path.join(root, "revoked.json")
    if os.path.isfile(rpath):
        revoked = _signed("revoked", rpath, "revoked.json", keys, warnings, lambda o: [])
    return {"generated": generated, "plugins": plugins, "approvals": approvals,
            "passes": passes, "revoked": revoked}, warnings


def render(index):
    """The exact index.json bytes: ASCII, sorted keys, one trailing newline."""
    return (json.dumps(index, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode()


def keep_time(index, previous_bytes):
    """`index` with the previous index's `generated` if nothing else differs."""
    try:
        old = json.loads(previous_bytes)
    except ValueError:
        return index
    if isinstance(old, dict) and dict(old, generated=None) == dict(index, generated=None):
        return dict(index, generated=old["generated"])
    return index


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", required=True)
    ap.add_argument("--packages", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--previous")
    ap.add_argument("--generated")
    a = ap.parse_args(argv)
    key = os.environ.get("INDEX_KEY", "").encode()
    if not key:
        print("build_index: INDEX_KEY isn't set", file=sys.stderr)
        return 1
    generated = a.generated or datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    index, warnings = build(a.root, a.packages, generated)
    for w in map(lib.log_safe, warnings):
        print(f"::warning::{w}" if os.environ.get("GITHUB_ACTIONS") else f"warning: {w}",
              file=sys.stderr)
    if a.previous and os.path.isfile(a.previous):
        with open(a.previous, "rb") as f:
            index = keep_time(index, f.read())
    data = render(index)
    sig = lib.sign_bytes(lib.INDEX_PREFIX, data, key)
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, "index.json"), "wb") as f:
        f.write(data)
    with open(os.path.join(a.out, "index.json.sig"), "w", encoding="ascii") as f:
        f.write(sig + "\n")
    print(f"index: {len(index['plugins'])} plugins, {len(index['approvals'])} approvals, "
          f"{len(index['passes'])} passes, revoked {'seq ' + str(index['revoked']['seq']) if index['revoked'] else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
