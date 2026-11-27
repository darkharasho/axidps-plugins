"""Fixtures that pin AxiAdmin's TypeScript port of lib._unpack / lib.tree_hash,
pr_check.comment and the approval file format. Writes port-fixtures.json next to this file.

Run: python3 -I tools/registry/port_fixtures.py

Approval files are signed with a throwaway Ed25519 key made by openssl at generation time;
only its public half (`pub`, base64 of the 32 raw bytes) is stored. A plain build() reuses the
committed approval files, so the currency test is deterministic."""

import base64
import io
import json
import os
import struct
import subprocess
import sys
import warnings
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import lib  # noqa: E402
import pr_check  # noqa: E402

PATH = os.path.join(HERE, "port-fixtures.json")
DATE = (2026, 1, 1, 0, 0, 0)


def _info(name, kind=None, system=3, mode=0o100644):
    i = zipfile.ZipInfo(name, DATE)
    i.filename = name  # raw: ZipInfo() would cut it at a NUL
    i.compress_type = kind if kind is not None else zipfile.ZIP_DEFLATED
    i.create_system = system
    i.external_attr = (0o040755 if name.endswith("/") else mode) << 16
    return i


def _zip(entries, stored=False):
    """entries: (name, bytes) or (name, bytes, ZipInfo). Fixed dates, order, compression level."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for e in entries:
            name, data = e[0], e[1]
            info = e[2] if len(e) > 2 else _info(
                name, zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # duplicate names are the point
                z.writestr(info, data)
    return buf.getvalue()


def _unicode_path_extra(name):
    payload = b"\x01" + struct.pack("<I", zlib.crc32(name.encode())) + name.encode()
    return struct.pack("<HH", lib.UNICODE_PATH_EXTRA, len(payload)) + payload


def _zip_cases():
    c = []

    def add(name, data):
        c.append((name, data))
    add("stored", _zip([("a.txt", b"hello"), ("b.txt", b"world")], stored=True))
    add("deflated", _zip([("a.txt", b"hello " * 500), ("b/c.txt", b"x" * 1000)]))
    add("nested with directory entries", _zip([
        ("d/", b""), ("d/e/", b""), ("d/e/f.txt", b"deep"), ("d/g.txt", b"g"), ("top.txt", b"t")]))
    add("an empty file", _zip([("empty.txt", b""), ("full.txt", b"x")]))
    add("a UTF-8 flag name", _zip([("café/über.txt", b"utf8")]))
    add("a duplicate path", _zip([("a.txt", b"1"), ("a.txt", b"2")]))
    add("paths that differ only in case", _zip([("A.txt", b"1"), ("a.txt", b"2")]))
    add("a file and a directory with the same name", _zip([("a", b"file"), ("a/", b"")]))
    add("a file under a path that is already a file", _zip([("a", b"file"), ("a/b.txt", b"x")]))
    for label, name in (("../x", "../x"), ("/abs", "/abs"), ("a\\b", "a\\b"), ("c:x", "c:x"),
                        ("a//b", "a//b"), ("./a", "./a")):
        add(f"the path {label}", _zip([(name, b"x")]))
    add("a control character in a name", _zip([("a\x01b.txt", b"x")]))
    info = _info("u.txt")
    info.extra = _unicode_path_extra("v.txt")
    add("a Unicode Path extra", _zip([("u.txt", b"x", info)]))
    # A header name of the single byte 0xFF with no UTF-8 flag: patch an ASCII placeholder.
    raw = _zip([("aZb.txt", b"x")])
    add("a non-UTF-8 name with no UTF-8 flag", raw.replace(b"aZb.txt", b"a\xffb.txt"))
    link = _info("link", mode=0o120777)
    add("a symlink", _zip([("real.txt", b"x"), ("link", b"real.txt", link)]))
    add("501 files", _zip([(f"f{n:03d}.txt", b"x") for n in range(501)]))
    add("past MAX_UNPACKED", _zip([("zeros.bin", bytes(6 * 1024 * 1024))]))
    ok = _zip([("c.txt", b"CRC-mismatch-body")], stored=True)
    add("a CRC mismatch", ok.replace(b"CRC-mismatch-body", b"CRC-mismatch-bodz"))
    add("not a zip", b"this is not a zip file")
    return c


def _zip_fixtures():
    out = []
    for name, data in _zip_cases():
        try:
            files = lib._unpack(data)
            out.append({"name": name, "zip": base64.b64encode(data).decode(),
                        "files": {p: base64.b64encode(b).decode() for p, b in files.items()},
                        "tree": lib.tree_hash(list(files.items())), "refused": False,
                        "reason": None})
        except ValueError as e:
            out.append({"name": name, "zip": base64.b64encode(data).decode(), "files": None,
                        "tree": None, "refused": True, "reason": str(e)})
    return out


def _comment_fixtures():
    tree, sha = "ab" * 32, "cd" * 32
    cases = [
        ([{"id": "someone.card", "version": "1.2.3", "tree": tree, "sha256": sha,
           "permissions": ["fight", "textures"], "network": ["api.example.com", "cdn.example.com"],
           "elevated": ["textures"], "deeper": ["textures"], "approved": False, "problems": []},
          {"id": "someone.plain", "version": "0.1.0", "tree": tree, "sha256": sha,
           "permissions": [], "network": [], "elevated": [], "deeper": [], "approved": False,
           "problems": []}], []),
        ([{"id": "someone.bad", "version": "2.0.0", "tree": None, "sha256": sha,
           "problems": ["the package has no axidps-plugin.json at its root", "second problem"]},
          {"id": "someone.ok", "version": "1.0.0", "tree": tree, "sha256": sha,
           "permissions": ["fight", "world"], "network": [], "elevated": [],
           "deeper": ["world"], "approved": True, "problems": []}],
         ["entries/x.json: not valid JSON", "two entries share an id"]),
        ([{"id": "evil`id\nwith newline", "version": "1.0.0`\n# heading", "tree": tree,
           "sha256": sha, "permissions": ["fi`ght\nx"], "network": ["a`b\nc.example.com"],
           "elevated": ["te`x\ntures"], "deeper": [], "approved": False,
           "problems": ["bad `tick` and\nnewline @someone"]}], ["top `level`\nproblem"]),
        ([], []),
    ]
    return [{"results": r, "problems": p, "text": pr_check.comment(r, p)} for r, p in cases]


def _throwaway_key():
    r = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519"], capture_output=True,
                       check=True)
    return r.stdout


def _approval_files(key_pem):
    pub = base64.b64encode(lib.raw_public(lib.public_pem(key_pem))).decode()
    tree = "0123456789abcdef" * 4
    bodies = [
        {"id": "someone.card", "version": "1.2.3", "tree": tree, "verified": True,
         "grant": ["textures", "world"], "signed": "2026-11-27"},
        {"id": "someone.plain", "version": "0.1.0-beta.1", "tree": tree[::-1], "verified": True,
         "grant": [], "signed": "2026-11-26"},
        {"id": "someone.unverified", "version": "3.0.0", "tree": tree, "verified": False,
         "grant": [], "signed": "2026-11-25"},
    ]
    out = []
    for b in bodies:
        obj = lib.sign("approval", b, key_pem)
        assert lib.verify("approval", obj, [base64.b64decode(pub)])
        out.append({"obj": obj, "text": json.dumps(obj, indent=2, ensure_ascii=True) + "\n",
                    "pub": pub})
    return out


def build(key_pem=None):
    """The fixtures. Approval files are the committed ones unless `key_pem` signs fresh ones."""
    approvals = None
    if key_pem is None and os.path.exists(PATH):
        with open(PATH, encoding="utf-8") as f:
            approvals = json.load(f)["approval_files"]
    if approvals is None:
        approvals = _approval_files(key_pem or _throwaway_key())
    return {"zips": _zip_fixtures(), "comments": _comment_fixtures(), "approval_files": approvals}


def main():
    data = build(_throwaway_key())  # the key lives only in this process's memory
    with open(PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)  # insertion order: approval objs keep their signed order
        f.write("\n")
    for z in data["zips"]:
        print(f"{'refused' if z['refused'] else 'ok     '}  {z['name']}: {z['reason']}")


if __name__ == "__main__":
    main()
