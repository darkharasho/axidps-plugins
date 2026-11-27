"""The owner's signing tools: `approve`, `pass` and `revoke`. Each shows what it will sign, asks
y/N, reads the approver key from 1Password into memory (`op read`), signs through openssl with
the key on stdin, writes the file, commits it on a new branch and pushes that branch. The key is
never printed, written to disk or passed on a command line.

Run them from an up-to-date `main` checkout of the registry with no uncommitted changes."""

import argparse
import base64
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402

OP_REF = "op://Private/axidps approver key/private key"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class Refused(Exception):
    pass


# ---------------------------------------------------------------- what gets signed

def approval_body(pid, version, tree, manifest, grant, no_verify, today):
    if no_verify and grant:
        raise Refused("--grant needs verification: an approval made with --no-verify "
                      "unlocks no deeper permission")
    for g in grant:
        if g not in lib.DEEPER:
            raise Refused(f'"{g}" isn\'t a deeper permission ({", ".join(lib.DEEPER)})')
        if g not in manifest["permissions"]:
            raise Refused(f'the manifest doesn\'t ask for "{g}"')
    if manifest["id"] != pid or manifest["version"] != version:
        raise Refused(f"the package is {manifest['id']} {manifest['version']}")
    return {"id": pid, "version": version, "tree": tree, "verified": not no_verify,
            "grant": list(grant), "signed": today}


def _valid_pattern(p):
    if p.endswith(".*"):
        prefix = p[:-2]
        return lib.valid_id(prefix + ".x") and not (prefix + ".").startswith("axidps.")
    return lib.valid_id(p) and not p.startswith("axidps.")


def pass_body(login, key_b64, ids, grant, days, today):
    if not lib.valid_login(login):
        raise Refused(f"{login!r} isn't a GitHub login")
    if lib._b64(key_b64, 32) is None:
        raise Refused("--key must be the base64 public key `axidps plugin dev-key` prints")
    if not ids or not all(_valid_pattern(p) for p in ids):
        raise Refused("--ids must list plugin ids or prefix.* patterns (not axidps.*)")
    if not grant or not all(g in lib.DEEPER for g in grant):
        raise Refused(f"--grant must list deeper permissions ({', '.join(lib.DEEPER)})")
    if not 1 <= days <= 366:
        raise Refused("--days must be 1-366")
    expires = datetime.date.fromisoformat(today) + datetime.timedelta(days=days)
    return {"login": login, "ids": list(ids), "grant": list(grant),
            "expires": expires.isoformat(), "key": key_b64}


REVOKE_FIELDS = {
    "version": ("id", "version", "tree"),
    "verification": ("id", "version"),
    "id": ("id",),
    "pass": ("login", "key"),
}
REVOKE_LISTS = {"version": "versions", "verification": "verifications", "id": "ids",
                "pass": "passes"}


def revoke_body(revoked, what, fields, reason):
    """The next revoked.json body (unsigned, seq + 1) with one more `what` entry."""
    if not reason or not all(" " <= c <= "~" for c in reason):
        raise Refused("--reason must be printable ASCII text")
    entry = {f: fields[f] for f in REVOKE_FIELDS[what]}
    entry["reason"] = reason
    body = {k: v for k, v in revoked.items() if k not in ("sig", "approver")}
    for name in REVOKE_LISTS.values():
        body.setdefault(name, [])
    body[REVOKE_LISTS[what]] = body[REVOKE_LISTS[what]] + [entry]
    body["seq"] = revoked.get("seq", 0) + 1
    return body


# ---------------------------------------------------------------- the key, git, downloads

def read_key(run=subprocess.run):
    """The approver private key PEM, in memory only."""
    r = run(["op", "read", OP_REF], capture_output=True, check=False)
    if r.returncode != 0 or b"PRIVATE KEY" not in r.stdout:
        raise Refused("couldn't read the approver key from 1Password (op read)")
    return r.stdout


def confirm(text, ask=input):
    print(text)
    return ask("Sign this? [y/N] ").strip().lower() in ("y", "yes")


def _git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, check=False)


def _ready():
    if _git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip() != "main":
        raise Refused("run this on the main branch")
    if _git("status", "--porcelain", "--untracked-files=no").stdout.strip():
        raise Refused("commit or stash your changes first")


def publish(branch, files, message):
    """Writes `files` ({relative path: object}) on new branch `branch`, commits and pushes."""
    r = _git("switch", "-c", branch)
    if r.returncode != 0:
        raise Refused(f"couldn't make branch {branch}: {r.stderr.strip()}")
    try:
        for rel, obj in files.items():
            path = os.path.join(ROOT, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="ascii") as f:
                f.write(json.dumps(obj, indent=2, ensure_ascii=True) + "\n")
        for step in (("add", "--", *files), ("commit", "-q", "-m", message),
                     ("push", "-q", "-u", "origin", branch)):
            r = _git(*step)
            if r.returncode != 0:
                raise Refused(f"git {step[0]} failed: {r.stderr.strip()}")
    finally:
        _git("switch", "-q", "main")
    print(f"Pushed {branch}. Open a pull request: gh pr create -R {lib.REGISTRY} "
          f"--head {branch} --fill")


def _gh_json(*args):
    r = subprocess.run(["gh", "api", *args], capture_output=True, check=False)
    return json.loads(r.stdout) if r.returncode == 0 else None


def _load_entry(pid):
    path = os.path.join(ROOT, "plugins", f"{pid}.json")
    try:
        with open(path, "rb") as f:
            entry = json.load(f)
    except (OSError, ValueError) as e:
        raise Refused(f"plugins/{pid}.json: {e}") from None
    problems = lib.check_entry(entry, pid)
    if problems:
        raise Refused(f"plugins/{pid}.json: {'; '.join(problems)}")
    return entry


def fetch_package(entry, version, dest):
    """The package zip for `version` in the empty folder `dest`: the registry's mirror, or
    else the author's release (published by the owner or a maintainer)."""
    pid = entry["id"]
    name = lib.asset_name(pid, version)
    r = subprocess.run(["gh", "release", "download", lib.mirror_tag(pid, version), "-R",
                        lib.REGISTRY, "-p", name, "-D", dest], capture_output=True, check=False)
    if r.returncode == 0:
        return os.path.join(dest, name), "the registry's mirror"
    v = next((v for v in entry["versions"] if v["version"] == version), None)
    if v is None:
        raise Refused(f"plugins/{pid}.json doesn't list {version}")
    rel = _gh_json(f"repos/{entry['repo']}/releases/tags/{v['tag']}")
    logins = {entry["owner"].lower(), *(m.lower() for m in entry.get("maintainers", []))}
    if not rel or (rel.get("author") or {}).get("login", "").lower() not in logins:
        raise Refused(f"no release {v['tag']} in {entry['repo']} by the plugin's owner")
    r = subprocess.run(["gh", "release", "download", v["tag"], "-R", entry["repo"], "-p",
                        v["asset"], "-D", dest], capture_output=True, check=False)
    if r.returncode != 0:
        raise Refused(f"couldn't download {v['asset']} from {entry['repo']} {v['tag']}")
    return os.path.join(dest, v["asset"]), f"{entry['repo']} {v['tag']}"


def _checked_package(pid, version, zip_arg):
    entry = _load_entry(pid)
    with tempfile.TemporaryDirectory() as d:
        if zip_arg:
            path, source = zip_arg, zip_arg
        else:
            path, source = fetch_package(entry, version, d)
        manifest, tree, sha, problems = lib.check_package(path, entry, version)
    if problems:
        raise Refused("the package fails its checks:\n  " + "\n  ".join(problems))
    return manifest, tree, sha, source


def _today():
    return datetime.datetime.now(datetime.UTC).date().isoformat()


def _sign_and_publish(kind, body, rel, branch, message, summary):
    if not confirm(f"{summary}\n\n{kind} to sign:\n{json.dumps(body, indent=2)}\n"):
        print("Nothing signed.")
        return 1
    key = read_key()
    obj = lib.sign(kind, body, key)
    del key
    publish(branch, {rel: obj}, message)
    return 0


def _run(fn, argv):
    try:
        _ready()
        return fn(argv)
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------- the commands

def approve_args(argv):
    ap = argparse.ArgumentParser(prog="approve", description="Sign an approval for one version.")
    ap.add_argument("id")
    ap.add_argument("version")
    ap.add_argument("--grant", default="", help="deeper permissions to allow, comma-separated")
    ap.add_argument("--no-verify", action="store_true",
                    help="approve without the Verified badge (no --grant)")
    ap.add_argument("--zip", help="check this local zip instead of downloading the package")
    a = ap.parse_args(argv)
    a.grant = [g for g in a.grant.split(",") if g]
    if a.grant and a.no_verify:
        ap.error("--grant can't be used with --no-verify: an unverified approval unlocks "
                 "no deeper permission")
    return a


def _approve(argv):
    a = approve_args(argv)
    manifest, tree, sha, source = _checked_package(a.id, a.version, a.zip)
    body = approval_body(a.id, a.version, tree, manifest, a.grant, a.no_verify, _today())
    summary = (f"{a.id} {a.version} from {source}\n  sha256 {sha}\n  tree   {tree}\n"
               f"  permissions: {', '.join(manifest['permissions']) or 'none'}\n"
               f"  network: {', '.join(manifest['network']) or 'none'}")
    return _sign_and_publish("approval", body, f"approvals/{a.id}/{a.version}.json",
                             f"approve/{a.id}-{a.version}", f"Approve {a.id} {a.version}",
                             summary)


def _pass(argv):
    ap = argparse.ArgumentParser(prog="pass", description="Sign a developer pass.")
    ap.add_argument("login")
    ap.add_argument("--key", required=True, help="the author's `axidps plugin dev-key` output")
    ap.add_argument("--ids", required=True, help="plugin ids or prefix.* patterns, comma-separated")
    ap.add_argument("--grant", required=True, help="deeper permissions, comma-separated")
    ap.add_argument("--days", type=int, default=90)
    a = ap.parse_args(argv)
    body = pass_body(a.login, a.key, [x for x in a.ids.split(",") if x],
                     [g for g in a.grant.split(",") if g], a.days, _today())
    return _sign_and_publish("pass", body, f"passes/{a.login}.json", f"pass/{a.login}",
                             f"Developer pass for {a.login}", f"Pass for {a.login}")


def _revoke(argv):
    ap = argparse.ArgumentParser(prog="revoke", description="Add a revocation to revoked.json.")
    sub = ap.add_subparsers(dest="what", required=True)
    p = sub.add_parser("version", help="that content stops loading for everyone")
    p.add_argument("id")
    p.add_argument("version")
    p.add_argument("--tree", help="tree hash (default: from the mirrored package)")
    p = sub.add_parser("verification", help="that version loses Verified and its grants")
    p.add_argument("id")
    p.add_argument("version")
    p = sub.add_parser("id", help="every version stops loading")
    p.add_argument("id")
    p = sub.add_parser("pass", help="a developer pass stops counting")
    p.add_argument("login")
    p.add_argument("--key", help="the pass's key (default: from passes/<login>.json)")
    for p in sub.choices.values():
        p.add_argument("--reason", required=True)
    a = ap.parse_args(argv)
    fields = {k: getattr(a, k, None) for k in ("id", "version", "login", "key", "tree")}
    if a.what == "version" and not fields["tree"]:
        fields["tree"] = _checked_package(a.id, a.version, None)[1]
    if a.what == "version" and not re.fullmatch(r"[0-9a-f]{64}", fields["tree"]):
        raise Refused("--tree must be 64 lowercase hex characters")
    if a.what == "pass" and not fields["key"]:
        try:
            with open(os.path.join(ROOT, "passes", f"{a.login}.json"), "rb") as f:
                fields["key"] = json.load(f)["key"]
        except (OSError, ValueError, KeyError):
            raise Refused(f"no passes/{a.login}.json; give --key") from None
    if a.what == "pass" and lib._b64(fields["key"], 32) is None:
        raise Refused("--key must be a base64 32-byte key")
    path = os.path.join(ROOT, "revoked.json")
    with open(path, "rb") as f:
        current = json.load(f)
    keys = lib.load_approvers(os.path.join(ROOT, "keys", "approvers.txt"))
    if "sig" in current and not lib.verify("revoked", current, keys):
        raise Refused("the current revoked.json doesn't verify; fix that first")
    body = revoke_body(current, a.what, fields, a.reason)
    label = " ".join(str(fields[f]) for f in REVOKE_FIELDS[a.what] if f != "key")
    return _sign_and_publish("revoked", body, "revoked.json", f"revoke/{body['seq']}",
                             f"Revoke {a.what} {label}", f"revoked.json seq {body['seq']}")


def approve_main(argv):
    return _run(_approve, argv)


def pass_main(argv):
    return _run(_pass, argv)


def revoke_main(argv):
    return _run(_revoke, argv)
