"""Tests for lib.py: the same bytes, hashes and rules as axidps's Rust code.

Run: python3 -I -m unittest discover tools/registry
"""

import base64
import io
import json
import os
import struct
import tempfile
import unittest
import zipfile
import zlib

import lib

HERE = os.path.dirname(os.path.abspath(__file__))


def vectors():
    with open(os.path.join(HERE, "vectors.json"), "rb") as f:
        return json.load(f)


def seed_pem(seed):
    """PKCS#8 PEM of an Ed25519 seed, as `openssl genpkey -algorithm ed25519` writes."""
    der = bytes.fromhex("302e020100300506032b657004220420") + bytes(seed)
    b64 = base64.b64encode(der).decode()
    return f"-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n".encode()


SEED7 = seed_pem([7] * 32)

MANIFEST = {
    "id": "someone.card", "name": "Card", "version": "1.0.0", "api": 1,
    "permissions": ["fight"], "network": ["api.example.com"],
    "windows": [{"id": "card", "title": "Card", "entry": "card.html"}],
}

ENTRY = {
    "id": "someone.card", "owner": "someone", "repo": "someone/card",
    "versions": [{"version": "1.0.0", "tag": "v1.0.0", "asset": "card.zip"}],
}


def good_files(manifest=None):
    m = dict(MANIFEST, **(manifest or {}))
    return [
        ("axidps-plugin.json", json.dumps(m).encode()),
        ("card.html", b"<p>1.0.0</p>"),
        ("js/app.js", b"console.log(1)\r\n"),
    ]


def unicode_path_extra(header_name, real_name):
    """An Info-ZIP Unicode Path extra field (0x7075) naming `real_name`, with the CRC of the
    header name so that readers which honour it (the zip crate does) use `real_name`."""
    data = b"\x01" + struct.pack("<I", zlib.crc32(header_name.encode())) + real_name.encode()
    return struct.pack("<HH", 0x7075, len(data)) + data


def zip_of(files, symlink=None, unicode_path=None):
    """A zip of `files` (names written raw; a trailing `/` makes a folder entry)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            info = zipfile.ZipInfo(name)
            info.filename = name  # raw: ZipInfo() would cut it at a NUL
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o040755 if name.endswith("/") else 0o100644) << 16
            z.writestr(info, data)
        if symlink:
            info = zipfile.ZipInfo(symlink[0])
            info.create_system = 3
            info.external_attr = 0o120777 << 16
            z.writestr(info, symlink[1])
        if unicode_path:
            info = zipfile.ZipInfo(unicode_path[0])
            info.extra = unicode_path_extra(*unicode_path)
            z.writestr(info, b"x")
    return buf.getvalue()


def lying_bomb(claimed):
    """A deflated run of zeros bigger than MAX_UNPACKED whose headers claim `claimed` bytes."""
    z = bytearray(zip_of(good_files() + [("zeros.bin", bytes(lib.MAX_UNPACKED + 1024))]))
    name = b"zeros.bin"
    for sig, size_at, name_at in ((b"PK\x03\x04", 22, 30), (b"PK\x01\x02", 24, 46)):
        at = next(i for i in range(len(z)) if z[i:i + 4] == sig
                  and z[i + name_at:i + name_at + len(name)] == name)
        z[at + size_at:at + size_at + 4] = struct.pack("<I", claimed)
    return bytes(z)


class Scratch:
    """Writes zips into a fresh empty folder, as CI does."""

    def __init__(self):
        self.dir = tempfile.TemporaryDirectory()

    def write(self, data, name="p.zip"):
        path = os.path.join(self.dir.name, name)
        with open(path, "wb") as f:
            f.write(data)
        return path


class CanonicalTests(unittest.TestCase):
    def test_canonical_vectors_match(self):
        cases = vectors()["canonical"]
        for case in cases:
            want = case["out"]
            if want is None:
                with self.assertRaises(ValueError, msg=repr(case["in"])):
                    lib.canonical(case["in"])
            else:
                self.assertEqual(lib.canonical(case["in"]), want)
        self.assertGreaterEqual(sum(c["out"] is None for c in cases), 4)

    def test_bool_is_not_an_int_and_ints_stay_in_u64(self):
        self.assertEqual(lib.canonical([True, False, None, 0]), "[true,false,null,0]")
        self.assertEqual(lib.canonical(2**64 - 1), "18446744073709551615")
        for bad in (2**64, -1, 1.0, float("nan"), {"a": [2**70]}, {1: 2}, (1,), b"x", "\x7f", "é"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                lib.canonical(bad)

    def test_sorted_by_bytes_and_only_quote_and_backslash_escaped(self):
        self.assertEqual(lib.canonical({"b": "/", "B": "\\", "a": '"'}),
                         '{"B":"\\\\","a":"\\"","b":"/"}')


class TreeTests(unittest.TestCase):
    def test_tree_vectors_match(self):
        cases = vectors()["tree"]
        self.assertGreaterEqual(len(cases), 4)
        for case in cases:
            files = [(p, base64.b64decode(b)) for p, b in case["files"]]
            self.assertEqual(lib.tree_hash(files), case["hash"])

    def test_order_is_by_path_bytes(self):
        a = [("a.js", b"1"), ("a/b.js", b"2")]
        self.assertEqual(lib.tree_hash(a), lib.tree_hash(a[::-1]))
        self.assertNotEqual(lib.tree_hash(a), lib.tree_hash([("a.js", b"2"), ("a/b.js", b"1")]))


class SignTests(unittest.TestCase):
    def test_key_id_of_the_vector_key(self):
        pub = lib.public_pem(SEED7)
        self.assertIn(b"BEGIN PUBLIC KEY", pub)
        self.assertEqual(lib.key_id(pub), "fe812c12f3ab4ce6")
        raw = base64.b64decode(vectors()["signed"][0]["pub"])
        self.assertEqual(lib.raw_public(pub), raw)
        self.assertEqual(lib.key_id(lib.pem_of_raw(raw)), "fe812c12f3ab4ce6")

    def test_signed_vectors_verify_and_python_signs_the_same(self):
        for case in vectors()["signed"]:
            keys = [base64.b64decode(case["pub"])]
            obj = case["object"]
            self.assertTrue(lib.verify(case["kind"], obj, keys), case["kind"])
            body = {k: v for k, v in obj.items() if k not in ("sig", "approver")}
            self.assertEqual(lib.sign(case["kind"], body, SEED7), obj)

    def test_tampered_fields_are_refused(self):
        case = vectors()["signed"][0]
        keys = [base64.b64decode(case["pub"])]
        obj = case["object"]
        for field, value in [("grant", ["network", "world"]), ("tree", "0" * 64),
                             ("issued", obj["issued"] + 1), ("extra", 1),
                             ("approver", "0000000000000000")]:
            t = dict(obj, **{field: value})
            self.assertFalse(lib.verify(case["kind"], t, keys), field)
        self.assertFalse(lib.verify("pass", obj, keys))
        self.assertFalse(lib.verify(case["kind"], obj, []))
        other = lib.raw_public(lib.public_pem(seed_pem([8] * 32)))
        self.assertFalse(lib.verify(case["kind"], obj, [other]))
        self.assertTrue(lib.verify(case["kind"], obj, [other, keys[0]]))
        sig = base64.b64decode(obj["sig"])
        for bad in (base64.b64encode(sig[:-1]).decode(), "not base64!", obj["sig"].rstrip("="),
                    base64.b64encode(bytes([sig[0] ^ 1]) + sig[1:]).decode()):
            self.assertFalse(lib.verify(case["kind"], dict(obj, sig=bad), keys), bad)
        no_sig = {k: v for k, v in obj.items() if k != "sig"}
        self.assertFalse(lib.verify(case["kind"], no_sig, keys))
        self.assertFalse(lib.verify(case["kind"], dict(obj, note="é"), keys))

    def test_index_bytes_sign_and_verify(self):
        data = b'{"plugins":[]}'
        sig = lib.sign_bytes(lib.INDEX_PREFIX, data, SEED7)
        pk = lib.raw_public(lib.public_pem(SEED7))
        self.assertTrue(lib.verify_bytes(lib.INDEX_PREFIX, data, sig, [pk]))
        self.assertFalse(lib.verify_bytes(b"axidps-approval-v1\n", data, sig, [pk]))
        self.assertFalse(lib.verify_bytes(lib.INDEX_PREFIX, data + b" ", sig, [pk]))

    def test_the_key_never_reaches_a_file_or_argv(self):
        # sign() hands openssl the key on stdin; nothing named like a key is left in /tmp.
        before = set(os.listdir(tempfile.gettempdir()))
        lib.sign("approval", {"id": "a.b.c"}, SEED7)
        for name in set(os.listdir(tempfile.gettempdir())) - before:
            path = os.path.join(tempfile.gettempdir(), name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    self.assertNotIn(b"PRIVATE KEY", f.read())


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.s = Scratch()
        self.addCleanup(self.s.dir.cleanup)

    def check(self, data, entry=ENTRY, version="1.0.0"):
        return lib.check_package(self.s.write(data), entry, version)

    def test_good_package(self):
        files = good_files()
        data = zip_of(files)
        manifest, tree, sha, problems = self.check(data)
        self.assertEqual(problems, [])
        self.assertEqual(tree, lib.tree_hash(files))
        self.assertEqual(sha, lib.sha256_hex(data))
        self.assertEqual(manifest["permissions"], ["fight"])
        self.assertEqual(manifest["network"], ["api.example.com"])
        self.assertEqual(manifest["api"], 1)
        # Folder entries are fine and don't change the tree.
        _, tree2, _, problems = self.check(zip_of([("js/", b"")] + files))
        self.assertEqual((problems, tree2), ([], tree))

    def test_hostile_zip_cases(self):
        many = [(f"f/{i}.txt", b"x") for i in range(lib.MAX_FILES)]
        cases = {
            "dotdot": (zip_of(good_files() + [("../x", b"x")]), "a . or .. component"),
            "inner dotdot": (zip_of(good_files() + [("js/../../x", b"x")]), "a . or .. component"),
            "absolute": (zip_of(good_files() + [("/tmp/x", b"x")]), "an absolute path"),
            "drive letter": (zip_of(good_files() + [("C:/x", b"x")]), "a drive letter"),
            "backslash": (zip_of(good_files() + [("js\\x.js", b"x")]), "\\ in the name"),
            "nul": (zip_of(good_files() + [("a\0b", b"x")]), "control characters"),
            "control": (zip_of(good_files() + [("a\x1bb", b"x")]), "control characters"),
            "empty component": (zip_of(good_files() + [("js//x.js", b"x")]), "an empty path component"),
            "dot component": (zip_of(good_files() + [("./x.js", b"x")]), "a . or .. component"),
            "case duplicate": (zip_of(good_files() + [("Card.html", b"x")]), "a duplicate path"),
            "case duplicate folder": (zip_of(good_files() + [("JS/b.js", b"x")]), "a duplicate path"),
            "file over folder": (zip_of(good_files() + [("js", b"x")]), "a duplicate path"),
            "symlink": (zip_of(good_files(), symlink=("link", b"/etc/passwd")), "not a plain file"),
            "unicode path field": (zip_of(good_files(), unicode_path=("ok.js", "../../evil.js")),
                                   "Unicode Path extra field"),
            "bomb": (zip_of(good_files() + [("zeros.bin", bytes(lib.MAX_UNPACKED + 1024))]),
                     "unpacks to more than"),
            "lying bomb": (lying_bomb(10), "CRC"),
            "too many files": (zip_of(good_files() + many), "more than 500 files"),
            "not a zip": (b"PK nope", "not a zip"),
            "no manifest": (zip_of(good_files()[1:]), "no axidps-plugin.json at its root"),
            "manifest not at root": (zip_of([("x/" + n, d) for n, d in good_files()]),
                                     "no axidps-plugin.json at its root"),
            "wrong id": (zip_of(good_files({"id": "someone.other"})), "the entry says"),
            "wrong version": (zip_of(good_files({"version": "1.0.1"})), "the entry says"),
            "bad manifest": (zip_of(good_files({"permissions": ["fight", "root"]})),
                             'unknown permission "root"'),
            "missing entry file": (zip_of(good_files({"windows": [
                {"id": "card", "title": "Card", "entry": "nope.html"}]})), '"nope.html" not found'),
            "sdk folder": (zip_of(good_files() + [("_sdk/x.js", b"x")]), '"_sdk" folder'),
            "local host": (zip_of(good_files({"network": ["localhost"]})), "public host name"),
        }
        for what, (data, reason) in cases.items():
            manifest, tree, sha, problems = self.check(data)
            self.assertTrue(any(reason in p for p in problems), f"{what}: {problems}")
            self.assertIsNone(manifest, what)
        # The reserved prefix is refused whatever the package says.
        files = good_files({"id": "axidps.card"})
        entry = dict(ENTRY, id="axidps.card")
        self.assertTrue(self.check(zip_of(files), entry)[3])

    def test_a_zip_bigger_than_the_overlay_downloads_is_refused(self):
        big = os.urandom(lib.ZIP_CAP + 1)
        data = zip_of(good_files() + [("big.bin", big)])
        self.assertTrue(any("bytes" in p for p in self.check(data)[3]))

    def test_extra_fields_other_than_unicode_path_are_fine(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, data in good_files():
                info = zipfile.ZipInfo(name)
                info.extra = struct.pack("<HH", 0x5455, 5) + b"\x01\0\0\0\0"  # timestamp
                z.writestr(info, data)
        self.assertEqual(self.check(buf.getvalue())[3], [])

    def test_log_safe(self):
        self.assertEqual(lib.log_safe("a\nb\x1b"), "a b ")
        self.assertEqual(lib.log_safe("::error::x"), " ::error::x")
        self.assertEqual(lib.log_safe("\n::add-mask::x"), "  ::add-mask::x")
        self.assertEqual(lib.log_safe("ok :: fine"), "ok :: fine")

    def test_utf8_names_hash_as_utf8(self):
        files = good_files() + [("café.txt", b"x")]
        _, tree, _, problems = self.check(zip_of(files))
        self.assertEqual((problems, tree), ([], lib.tree_hash(files)))


class ManifestTests(unittest.TestCase):
    def problems(self, edit):
        m = json.loads(json.dumps(MANIFEST))
        edit(m)
        files = {"card.html": b"x"}
        return lib.manifest_problems(json.dumps(m).encode(), files)[1]

    def test_rules_follow_plugin_check(self):
        self.assertEqual(self.problems(lambda m: None), [])
        bad = [
            lambda m: m.pop("name"),
            lambda m: m.update(name="  "),
            lambda m: m.update(id="Bad Id"),
            lambda m: m.update(version="1.0"),
            lambda m: m.update(version="01.0.0"),
            lambda m: m.update(api=1.5),
            lambda m: m.update(api=True),
            lambda m: m.update(author=3),
            lambda m: m.update(permissions=["fight", "nope"]),
            lambda m: m.update(network=["https://x.com"]),
            lambda m: m.update(network=["127.0.0.1"]),
            lambda m: m.update(network=["*.com"]),
            lambda m: m.update(network=["printer.local"]),
            lambda m: m.update(windows=[]),
            lambda m: m.update(windows=[MANIFEST["windows"][0]] * 2),
            lambda m: m["windows"][0].update(entry="../x.html"),
            lambda m: m["windows"][0].update(entry="_sdk/x.html"),
            lambda m: m["windows"][0].update(id="Card"),
            lambda m: m["windows"][0].update(open="yes"),
            lambda m: m["windows"][0].update(place="top"),
        ]
        for i, edit in enumerate(bad):
            self.assertTrue(self.problems(edit), i)
        ok = [
            lambda m: m.update(network=["*.example.com"], author="someone"),
            lambda m: m.update(permissions=["fight", "world", "textures"]),
            lambda m: m.update(version="1.0.0-beta.1+build.5"),
            lambda m: m["windows"][0].update(icon="unknown-icon", place="below-meter", open=True),
            lambda m: m["windows"][0].update(entry="card%2Ehtml"),
        ]
        for i, edit in enumerate(ok):
            self.assertEqual(self.problems(edit), [], i)

    def test_deeper(self):
        self.assertEqual(lib.deeper(["fight", "world", "textures", "nope"]), ["world", "textures"])


class EntryTests(unittest.TestCase):
    def test_good_entry(self):
        self.assertEqual(lib.check_entry(ENTRY, "someone.card"), [])
        full = dict(ENTRY, maintainers=["helper-1"], verify=True, description="Big DPS.",
                    icon="chart")
        self.assertEqual(lib.check_entry(full, "someone.card"), [])

    def test_bad_entries(self):
        v = ENTRY["versions"][0]
        bad = [
            (dict(ENTRY), "other.card"),
            (dict(ENTRY, id="axidps.card"), "axidps.card"),
            (dict(ENTRY, owner="bad login!"), "someone.card"),
            (dict(ENTRY, repo="someone"), "someone.card"),
            (dict(ENTRY, repo="someone/../x"), "someone.card"),
            (dict(ENTRY, versions=[]), "someone.card"),
            (dict(ENTRY, versions=[v, v]), "someone.card"),
            (dict(ENTRY, versions=[dict(v, version="1")]), "someone.card"),
            (dict(ENTRY, versions=[dict(v, tag="v1 0")]), "someone.card"),
            (dict(ENTRY, versions=[dict(v, asset="../card.zip")]), "someone.card"),
            (dict(ENTRY, verify="yes"), "someone.card"),
            (dict(ENTRY, maintainers="x"), "someone.card"),
            (dict(ENTRY, icon="nope"), "someone.card"),
            (dict(ENTRY, surprise=1), "someone.card"),
            ([], "someone.card"),
        ]
        for i, (entry, file_id) in enumerate(bad):
            self.assertTrue(lib.check_entry(entry, file_id), i)


class SignedShapeTests(unittest.TestCase):
    """Field shapes as trust.rs parses them."""

    def test_revoked_shapes(self):
        good = {"seq": 1,
                "versions": [{"id": "a.b.c", "version": "1.0.0", "tree": "0" * 64, "reason": "r"}],
                "verifications": [{"id": "a.b.c", "version": "1.0.0", "reason": "r"}],
                "ids": [{"id": "a.b.c", "reason": "r"}],
                "passes": [{"login": "x", "key": base64.b64encode(bytes(32)).decode(), "reason": "r"}]}
        self.assertEqual(lib.shape_problems("revoked", good), [])
        for edit in [
            {"seq": -1}, {"seq": "1"},
            {"verifications": [{"id": "a.b.c", "version": "1.0.0"}]},
            {"versions": [{"id": "a.b.c", "version": "1.0.0", "reason": "r"}]},
            {"passes": [{"login": "x", "key": "short", "reason": "r"}]},
            {"ids": {"id": "a.b.c"}},
        ]:
            self.assertTrue(lib.shape_problems("revoked", dict(good, **edit)), edit)

    def test_approval_and_pass_shapes(self):
        a = {"id": "a.b.c", "version": "1.0.0", "tree": "0" * 64, "verified": True,
             "grant": ["world"], "signed": "2026-11-26"}
        self.assertEqual(lib.shape_problems("approval", a), [])
        for edit in [{"verified": 1}, {"grant": "world"}, {"tree": 5}]:
            self.assertTrue(lib.shape_problems("approval", dict(a, **edit)), edit)
        p = {"login": "x", "ids": ["x.*"], "grant": ["world"], "expires": "2027-02-24",
             "key": base64.b64encode(bytes(32)).decode()}
        self.assertEqual(lib.shape_problems("pass", p), [])
        for edit in [{"expires": "2027-2-24"}, {"expires": 1795651200}, {"key": "AAAA"}, {"ids": [1]}]:
            self.assertTrue(lib.shape_problems("pass", dict(p, **edit)), edit)


if __name__ == "__main__":
    unittest.main()
