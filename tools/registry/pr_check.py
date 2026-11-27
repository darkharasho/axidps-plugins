#!/usr/bin/env python3
"""The pull request check, run by .github/workflows/pr.yml from the *base* checkout. It never
runs code from the pull request: the PR's files are fetched with `gh api` and read as data,
each package zip is downloaded into its own fresh folder and checked by `check.py` (python -I).

Environment: GH_TOKEN, REPO, PR, PR_AUTHOR, HEAD_REPO, HEAD_SHA, AUTO_MERGE, GITHUB_OUTPUT.
Exits 1 when the PR has problems."""

import base64
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_index  # noqa: E402
import lib  # noqa: E402

MARKER = "<!-- axidps-registry-check -->"
CHECKLIST_MARKER = "<!-- axidps-verification-checklist -->"
LABEL = "verification requested"
BOT = "github-actions[bot]"
MAX_ENTRY_BYTES = 64 * 1024


# ---------------------------------------------------------------- decisions (pure)

def classify(files):
    out = {"plugins": [], "signed": [], "other": []}
    for f in files:
        name = f["filename"]
        # Names go into API paths: only plain id/version/login characters count as data.
        if re.fullmatch(r"plugins/[a-z0-9.-]+\.json", name):
            out["plugins"].append(f)
        elif (re.fullmatch(r"approvals/[a-z0-9.-]+/[A-Za-z0-9.+-]+\.json", name)
              or re.fullmatch(r"passes/[A-Za-z0-9-]+\.json", name) or name == "revoked.json"):
            out["signed"].append(f)
        else:
            out["other"].append(f)
    return out


def _logins(entry):
    return {entry["owner"].lower(), *(m.lower() for m in entry.get("maintainers", []))}


def ownership_problems(old, new, author):
    """New file: the PR author becomes the owner. Changed file: the PR author is its owner or a
    maintainer, and only the owner can hand the id to someone else."""
    a = author.lower()
    if old is None:
        if new["owner"].lower() != a:
            return [f"owner: a new entry's owner must be the pull request's author ({author})"]
        return []
    if a not in _logins(old):
        return [f"{author} isn't the owner or a maintainer of {old['id']}"]
    if new["owner"].lower() != old["owner"].lower() and a != old["owner"].lower():
        return ["owner: only the current owner can hand the id to someone else"]
    return []


def new_versions(old, new):
    """(versions new in `new`, problems): listed versions can't change or go away."""
    before = {v["version"]: v for v in (old or {}).get("versions", [])}
    after = {v["version"]: v for v in new["versions"]}
    problems = []
    for ver, v in before.items():
        if ver not in after:
            problems.append(f"versions: {ver} was listed and can't be removed here; ask the owner")
        elif after[ver] != v:
            problems.append(f"versions: {ver} was listed and can't change; publish a new version")
    return [v for ver, v in after.items() if ver not in before], problems


def release_author_ok(entry, release):
    login = ((release or {}).get("author") or {}).get("login")
    return isinstance(login, str) and login.lower() in _logins(entry)


def auto_merge(plugins_only, problems, deeper, verify, setting):
    return (plugins_only and not problems and not deeper and not verify
            and (setting or "").strip().lower() != "off")


def signed_file_problems(path, obj, keys, base_seq):
    if path == "revoked.json":
        kind = "revoked"
    elif path.startswith("passes/"):
        kind = "pass"
    else:
        kind = "approval"
    why = lib.shape_problems(kind, obj)
    if why:
        return why
    if kind == "approval":
        why = build_index.approval_path_problems(path, obj)
    elif kind == "pass":
        why = build_index.pass_path_problems(path, obj)
    elif obj["seq"] <= base_seq:
        why = [f"seq {obj['seq']} must be higher than main's ({base_seq})"]
    if not why and not lib.verify(kind, obj, keys):
        why = ["its signature doesn't verify against keys/approvers.txt"]
    return why


MAX_PR_FILES = 100


def file_count_problems(listed, changed_files):
    """The file list must be complete (GitHub caps it at 3000) and small."""
    if changed_files > MAX_PR_FILES:
        return [f"this pull request changes {changed_files} files; at most {MAX_PR_FILES}"]
    if listed != changed_files:
        return [f"GitHub listed {listed} of {changed_files} changed files"]
    return []


def code(s):
    """Untrusted text as one inline code span (no backticks, no line breaks), so it can't
    format, link or mention anyone."""
    s = "".join(c if c.isprintable() else " " for c in str(s)).replace("`", "'")
    return f"`{s[:300]}`"


def comment(results, problems):
    lines = [MARKER, "## Registry check", ""]
    if problems:
        lines += ["**Problems:**", ""] + [f"- {code(p)}" for p in problems] + [""]
    for r in results:
        lines.append(f"### {code(r['id'])} {code(r['version'])}")
        lines.append("")
        if r.get("tree"):
            lines.append(f"- tree: {code(r['tree'])}")
        if r.get("sha256"):
            lines.append(f"- sha256: {code(r['sha256'])}")
        if r.get("permissions") is not None:
            lines.append("- permissions: " + (", ".join(code(p) for p in r["permissions"]) or "none"))
            lines.append("- network: " + (", ".join(code(n) for n in r["network"]) or "none"))
        if r.get("deeper") and not r.get("approved"):
            lines.append("- deeper permissions " + ", ".join(code(d) for d in r["deeper"])
                         + ": **needs approval to load**. It can be listed, but it won't load "
                           "until the owner approves this exact version.")
        if r.get("problems"):
            lines.append("- problems:")
            lines += [f"  - {code(p)}" for p in r["problems"]]
        lines.append("")
    if not results and not problems:
        lines.append("Nothing to check.")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- GitHub (gh api, as data)

class Missing(Exception):
    pass


def gh(*args, data=None):
    r = subprocess.run(["gh", *args], input=data, capture_output=True, check=False)
    if r.returncode != 0:
        err = r.stderr.decode(errors="replace")
        if "HTTP 404" in err:
            raise Missing(" ".join(args[:2]))
        raise RuntimeError(f"gh {args[0]} {args[1] if len(args) > 1 else ''} failed: {err.strip()}")
    return r.stdout


def gh_json(*args):
    return json.loads(gh("api", *args))


def gh_lines(*args):
    return [json.loads(l) for l in gh("api", "--paginate", *args).decode().splitlines() if l]


def file_at_head(env, path):
    meta = gh_json(f"repos/{env['HEAD_REPO']}/contents/{path}?ref={env['HEAD_SHA']}")
    if meta.get("type") != "file" or meta.get("size", 0) > MAX_ENTRY_BYTES:
        raise ValueError(f"{path}: not a file of at most {MAX_ENTRY_BYTES} bytes")
    return json.loads(base64.b64decode(meta["content"]))


def base_file(path):
    full = os.path.join(os.getcwd(), path)
    if not os.path.isfile(full):
        return None
    with open(full, "rb") as f:
        return json.load(f)


def download_asset(repo, asset, dest):
    """Release asset `asset` of `repo` into the empty folder `dest`."""
    if asset.get("size", 0) > lib.ZIP_CAP:
        raise ValueError(f"{asset['name']} is {asset['size']} bytes, more than {lib.ZIP_CAP}")
    data = gh("api", "-H", "Accept: application/octet-stream",
              f"repos/{repo}/releases/assets/{int(asset['id'])}")
    path = os.path.join(dest, "package.zip")
    with open(path, "wb") as f:
        f.write(data[:lib.ZIP_CAP + 1])
    return path


def author_release(entry, v):
    """(release, asset) for version `v` of `entry`, or raises ValueError."""
    try:
        rel = gh_json(f"repos/{entry['repo']}/releases/tags/{v['tag']}")
    except Missing:
        raise ValueError(f"{entry['repo']} has no published release {v['tag']}") from None
    if not release_author_ok(entry, rel):
        raise ValueError(f"release {v['tag']} wasn't published by the owner or a maintainer")
    asset = next((a for a in rel.get("assets", []) if a.get("name") == v["asset"]), None)
    if asset is None:
        raise ValueError(f"release {v['tag']} has no asset {v['asset']}")
    return rel, asset


def check_version(env, entry, v):
    r = {"id": entry["id"], "version": v["version"], "problems": []}
    try:
        gh_json(f"repos/{env['REPO']}/releases/tags/{lib.mirror_tag(entry['id'], v['version'])}")
        r["problems"].append("this version is already published; bump the version")
        return r
    except Missing:
        pass
    try:
        _, asset = author_release(entry, v)
    except ValueError as e:
        r["problems"].append(str(e))
        return r
    with tempfile.TemporaryDirectory() as zdir, tempfile.TemporaryDirectory() as edir:
        try:
            zip_path = download_asset(entry["repo"], asset, zdir)
        except (ValueError, RuntimeError) as e:
            r["problems"].append(str(e))
            return r
        entry_path = os.path.join(edir, "entry.json")
        with open(entry_path, "w", encoding="utf-8") as f:
            json.dump(entry, f)
        # No token in the checker's environment.
        env_min = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "LANG": os.environ.get("LANG", "C.UTF-8")}
        out = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check.py"), zip_path,
                              entry_path, v["version"]], capture_output=True, check=False,
                             env=env_min)
    try:
        res = json.loads(out.stdout)
    except ValueError:
        r["problems"].append("the package check crashed")
        return r
    m = res["manifest"] or {}
    r.update(tree=res["tree"], sha256=res["sha256"], problems=res["problems"],
             permissions=m.get("permissions"), network=m.get("network"), deeper=res["deeper"],
             approved=os.path.isfile(f"approvals/{entry['id']}/{v['version']}.json"))
    return r


def upsert_comment(env, marker, body):
    repo, pr = env["REPO"], env["PR"]
    existing = [c for c in gh_lines(f"repos/{repo}/issues/{pr}/comments",
                                    "--jq", ".[] | {id, body, login: .user.login}")
                if c["login"] == BOT and marker in (c["body"] or "")]
    if existing:
        gh("api", "-X", "PATCH", f"repos/{repo}/issues/comments/{int(existing[0]['id'])}",
           "-f", f"body={body}")
    else:
        gh("api", "-X", "POST", f"repos/{repo}/issues/{pr}/comments", "-f", f"body={body}")


def checklist():
    with open(os.path.join(os.getcwd(), "docs", "verification.md"), encoding="utf-8") as f:
        return f"{CHECKLIST_MARKER}\n{f.read()}"


def main(env):
    author = env["PR_AUTHOR"]
    changed = int(gh_json(f"repos/{env['REPO']}/pulls/{env['PR']}")["changed_files"])
    files = [] if changed > MAX_PR_FILES else gh_lines(
        f"repos/{env['REPO']}/pulls/{env['PR']}/files?per_page=100",
        "--jq", ".[] | {filename, status}")
    problems = file_count_problems(len(files), changed)
    if problems:
        files = []
    c = classify(files)
    results, deeper, verify = [], [], False
    if c["other"]:
        names = ", ".join(f["filename"] for f in c["other"])
        if author.lower() == env["REPO"].split("/")[0].lower():
            print(lib.log_safe(f"owner's change outside the registry data, review by hand: {names}"))
        else:
            problems.append(f"only plugins/<id>.json can change in a pull request: {names}")

    for f in c["plugins"]:
        path = f["filename"]
        file_id = path[len("plugins/"):-len(".json")]
        if f["status"] not in ("added", "modified"):
            problems.append(f"{path}: {f['status']} files need the owner")
            continue
        try:
            new = file_at_head(env, path)
            old = base_file(path)
        except (ValueError, Missing) as e:
            problems.append(f"{path}: {e}")
            continue
        why = lib.check_entry(new, file_id)
        if not why and old is not None and lib.check_entry(old, file_id):
            why = ["the entry on main doesn't pass its checks; ask the owner"]
        if not why:
            why = ownership_problems(old, new, author)
        if why:
            problems += [f"{path}: {p}" for p in why]
            continue
        added, why = new_versions(old, new)
        problems += [f"{path}: {p}" for p in why]
        verify = verify or new.get("verify") is True
        for v in added:
            r = check_version(env, new, v)
            results.append(r)
            deeper += r.get("deeper") or []

    if c["signed"]:
        keys = lib.load_approvers("keys/approvers.txt")
        base_revoked = base_file("revoked.json") or {}
        base_seq = base_revoked.get("seq", 0) if "sig" in base_revoked else 0
        for f in c["signed"]:
            path = f["filename"]
            if f["status"] not in ("added", "modified"):
                problems.append(f"{path}: {f['status']} files need the owner")
                continue
            try:
                why = signed_file_problems(path, file_at_head(env, path), keys, base_seq)
            except (ValueError, Missing) as e:
                why = [str(e)]
            problems += [f"{path}: {p}" for p in why]

    all_problems = problems + [p for r in results for p in r["problems"]]
    upsert_comment(env, MARKER, comment(results, problems))
    if verify and not all_problems:
        gh("api", "-X", "POST", f"repos/{env['REPO']}/issues/{env['PR']}/labels",
           "-f", f"labels[]={LABEL}")
        upsert_comment(env, CHECKLIST_MARKER, checklist())
    merge = auto_merge(plugins_only=bool(c["plugins"]) and not c["signed"] and not c["other"],
                       problems=all_problems, deeper=deeper, verify=verify,
                       setting=env.get("AUTO_MERGE", ""))
    if env.get("GITHUB_OUTPUT"):
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write(f"automerge={'true' if merge else 'false'}\n")
    for p in all_problems:
        print(lib.log_safe(f"problem: {p}"))
    return 1 if all_problems else 0


if __name__ == "__main__":
    sys.exit(main(os.environ))
