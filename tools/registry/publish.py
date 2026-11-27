#!/usr/bin/env python3
"""Run by .github/workflows/main.yml on main: mirrors each listed version's zip to the registry
release `<id>@<version>` (existing mirrors are never replaced), then builds and signs the index
and replaces the assets of release `index` when the index changed.

Environment: GH_TOKEN, REPO, INDEX_KEY (the index key PEM, from the Actions secret)."""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_index  # noqa: E402
import lib  # noqa: E402
import pr_check  # noqa: E402
from pr_check import Missing, gh, gh_json  # noqa: E402


def warn(msg):
    print(f"::warning::{lib.log_safe(msg)}")


def mirrored(repo, tag, name, packages):
    """Downloads the existing mirror into `packages`; False if there's no mirror yet."""
    try:
        rel = gh_json(f"repos/{repo}/releases/tags/{tag}")
    except Missing:
        return False
    if not any(a.get("name") == name for a in rel.get("assets", [])):
        raise RuntimeError(f"release {tag} has no {name}; fix it by hand")
    with tempfile.TemporaryDirectory() as d:
        gh("release", "download", tag, "-R", repo, "-p", name, "-D", d)
        shutil.move(os.path.join(d, name), os.path.join(packages, tag + ".zip"))
    return True


def mirror(repo, entry, v, packages, sha):
    """Copies the author's zip to a new release `<id>@<version>` after checking it again."""
    pid, ver = entry["id"], v["version"]
    tag, name = lib.mirror_tag(pid, ver), lib.asset_name(pid, ver)
    try:
        _, asset = pr_check.author_release(entry, v)
    except ValueError as e:
        warn(f"{pid} {ver} not mirrored: {e}")
        return
    with tempfile.TemporaryDirectory() as d:
        try:
            path = pr_check.download_asset(entry["repo"], asset, d)
        except (ValueError, RuntimeError) as e:
            warn(f"{pid} {ver} not mirrored: {e}")
            return
        _, tree, _, problems = lib.check_package(path, entry, ver)
        if problems:
            warn(f"{pid} {ver} not mirrored: {'; '.join(problems)}")
            return
        named = os.path.join(d, name)
        os.rename(path, named)
        notes = (f"{pid} {ver}, mirrored from https://github.com/{entry['repo']}/releases/tag/"
                 f"{v['tag']}\n\ntree {tree}\n")
        gh("release", "create", tag, named, "-R", repo, "--target", sha, "--latest=false",
           "--title", f"{pid} {ver}", "--notes", notes)
        shutil.copy(named, os.path.join(packages, tag + ".zip"))
    print(lib.log_safe(f"mirrored {pid} {ver}"))


def entries():
    root = os.getcwd()
    for name in sorted(os.listdir(os.path.join(root, "plugins"))):
        if not name.endswith(".json"):
            continue
        try:
            entry = build_index._load(os.path.join(root, "plugins", name))
        except (OSError, ValueError):
            continue  # build_index reports it
        if not lib.check_entry(entry, name[:-len(".json")]):
            yield entry


def main(env):
    repo, sha = env["REPO"], env["GITHUB_SHA"]
    with tempfile.TemporaryDirectory() as packages, tempfile.TemporaryDirectory() as prev, \
            tempfile.TemporaryDirectory() as out:
        for entry in entries():
            for v in entry["versions"]:
                tag = lib.mirror_tag(entry["id"], v["version"])
                if not mirrored(repo, tag, lib.asset_name(entry["id"], v["version"]), packages):
                    mirror(repo, entry, v, packages, sha)
        previous = os.path.join(prev, "index.json")
        try:
            gh("release", "download", "index", "-R", repo, "-p", "index.json", "-D", prev)
            have_release = True
        except (Missing, RuntimeError):
            have_release = False
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "build_index.py"),
                            "--root", ".", "--packages", packages, "--out", out,
                            "--previous", previous], check=False)
        if r.returncode != 0:
            return 1
        new = os.path.join(out, "index.json")
        if os.path.isfile(previous):
            with open(previous, "rb") as a, open(new, "rb") as b:
                if a.read() == b.read():
                    print("index unchanged")
                    return 0
        if not have_release:
            try:
                gh("release", "view", "index", "-R", repo)
            except (Missing, RuntimeError):
                gh("release", "create", "index", "-R", repo, "--target", sha, "--latest=false",
                   "--title", "Store index", "--notes",
                   "The signed plugin store index, rebuilt from main. Don't edit by hand.")
        gh("release", "upload", "index", new, os.path.join(out, "index.json.sig"), "-R", repo,
           "--clobber")
        print("index published")
    return 0


if __name__ == "__main__":
    sys.exit(main(os.environ))
