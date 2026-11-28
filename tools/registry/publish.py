#!/usr/bin/env python3
"""Run by .github/workflows/main.yml on main: mirrors each listed version's zip to the registry
release `<id>@<version>` (existing mirrors are never replaced), lists new releases from each
plugin's own repo that ask for nothing new (auto_list; the mirror release notes record them), then builds and signs the index
and replaces the assets of release `index` when the index changed.

Environment: GH_TOKEN, REPO, INDEX_KEY (the index key PEM, from the Actions secret)."""

import json
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


def mirror(repo, entry, v, packages, sha, auto=False, tree=None):
    """Copies the author's zip to a new release `<id>@<version>` after checking it again. With
    `tree`, the zip's files must be exactly those (the ones auto_list checked)."""
    pid, ver = entry["id"], v["version"]
    tag, name = lib.mirror_tag(pid, ver), lib.asset_name(pid, ver)
    try:
        _, asset = pr_check.author_release(entry, v)
    except ValueError as e:
        warn(f"{pid} {ver} not mirrored: {e}")
        return False
    with tempfile.TemporaryDirectory() as d:
        try:
            path = pr_check.download_asset(entry["repo"], asset, d)
        except (ValueError, RuntimeError) as e:
            warn(f"{pid} {ver} not mirrored: {e}")
            return False
        _, got, _, problems = lib.check_package(path, entry, ver)
        if problems:
            warn(f"{pid} {ver} not mirrored: {'; '.join(problems)}")
            return False
        if tree is not None and got != tree:
            warn(f"{pid} {ver} not mirrored: its files aren't the files that were checked")
            return False
        named = os.path.join(d, name)
        os.rename(path, named)
        notes = mirror_notes(entry, v, got, auto)
        gh("release", "create", tag, named, "-R", repo, "--target", sha, "--latest=false",
           "--title", f"{pid} {ver}", "--notes", notes)
        shutil.copy(named, os.path.join(packages, tag + ".zip"))
    print(lib.log_safe(f"mirrored {pid} {ver}{' (auto-listed)' if auto else ''}"))
    return True


AUTO_MARK = "auto-listed: "


def mirror_notes(entry, v, tree, auto):
    """The mirror release's notes; an auto-listed version carries its `{version, tag, asset}` on
    a line of its own, which is the only record that it is listed."""
    notes = (f"{entry['id']} {v['version']}, mirrored from https://github.com/{entry['repo']}/"
             f"releases/tag/{v['tag']}\n\ntree {tree}\n")
    if auto:
        notes += "\n" + AUTO_MARK + json.dumps(dict(v, id=entry["id"]), sort_keys=True) + "\n"
    return notes


def auto_marked(releases):
    """{id: [version, …]} from the registry's mirror releases whose notes mark them auto-listed
    (the id and version must match the release's own `<id>@<version>` tag)."""
    out = {}
    for rel in releases:
        tag, body = rel.get("tag_name"), rel.get("body") or ""
        if not isinstance(tag, str) or "@" not in tag:
            continue
        pid, ver = tag.split("@", 1)
        for line in body.splitlines():
            if not line.startswith(AUTO_MARK):
                continue
            try:
                v = json.loads(line[len(AUTO_MARK):])
            except ValueError:
                continue
            ok = (isinstance(v, dict) and set(v) == {"id", "version", "tag", "asset"}
                  and v["id"] == pid and v["version"] == ver
                  and all(isinstance(x, str) for x in v.values()))
            if ok:
                out.setdefault(pid, []).append({k: v[k] for k in ("version", "tag", "asset")})
    return out


def with_auto(entry, marked):
    """A copy of `entry` with its auto-listed versions added after the listed ones."""
    have = {v["version"] for v in entry["versions"]}
    extra = [v for v in marked.get(entry["id"], []) if v["version"] not in have]
    extra.sort(key=lambda v: lib.semver_key(v["version"]))
    return dict(entry, versions=entry["versions"] + extra)


def auto_list(env, entry, packages):
    """The entry's new releases (pr_check.discover) that pass the package checks and ask for
    nothing beyond the newest listed version, in order, stopping at the first that asks for
    more: that one needs a pull request. The newest listed version must already be in
    `packages`. Adds them to `entry` and returns `(version, tree)` pairs, `tree` being the checked
    files' tree hash; the caller mirrors them as auto-listed, only if the files are the same."""
    pid = entry["id"]
    if entry.get("auto") is False:
        return []
    try:
        releases = gh_json(f"repos/{entry['repo']}/releases?per_page=30")
    except (Missing, RuntimeError) as e:
        warn(f"{pid}: can't list the releases of {entry['repo']}: {e}")
        return []
    found = pr_check.discover(entry, releases)
    if not found:
        return []
    newest = max(entry["versions"], key=lambda v: lib.semver_key(v["version"]))
    path = os.path.join(packages, lib.mirror_tag(pid, newest["version"]) + ".zip")
    last = lib.check_package(path, entry, newest["version"])[0] if os.path.isfile(path) else None
    if last is None:
        warn(f"{pid}: {newest['version']} isn't mirrored, so new releases wait")
        return []
    added = []
    for v in found:
        r = pr_check.check_version(env, entry, v)
        if r["problems"]:
            warn(f"{pid} {v['version']} not listed: {'; '.join(r['problems'])}")
            break
        more = pr_check.widened(r, last)
        if more:
            warn(f"{pid} {v['version']} asks for {', '.join(more)}; it needs a pull request")
            break
        entry["versions"].append(v)
        added.append((v, r["tree"]))
        last = r
    return added


def write_entry(entry):
    """Writes `entry`, auto-listed versions included, into the local checkout so this run's
    index lists them. Never pushed: the mirror releases are the record."""
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("write_entry only runs in the Publish workflow's checkout")
    with open(os.path.join(os.getcwd(), "plugins", entry["id"] + ".json"), "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2)


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
        marked = auto_marked(pr_check.gh_lines(f"repos/{repo}/releases?per_page=100",
                                               "--jq", ".[] | {tag_name, body}"))
        for entry in entries():
            entry = with_auto(entry, marked)
            for v in entry["versions"]:
                tag = lib.mirror_tag(entry["id"], v["version"])
                if not mirrored(repo, tag, lib.asset_name(entry["id"], v["version"]), packages):
                    mirror(repo, entry, v, packages, sha)
            for v, tree in auto_list(env, entry, packages):
                mirror(repo, entry, v, packages, sha, auto=True, tree=tree)
            write_entry(entry)
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
