"""Tests for build_index.py, owner.py (approve / pass / revoke) and pr_check.py's decisions.

Run: python3 -I -m unittest discover tools/registry
"""

import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

import build_index
import lib
import owner
import pr_check
from test_lib import ENTRY, SEED7, good_files, seed_pem, zip_of

APPROVER_PUB = lib.raw_public(lib.public_pem(SEED7))
B64_APPROVER = base64.b64encode(APPROVER_PUB).decode()
TODAY = "2026-11-26"


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else json.dumps(data, indent=2).encode())


class Registry:
    """A registry checkout and a folder of mirrored zips, in temp folders."""

    def __init__(self, test):
        self.root = tempfile.mkdtemp()
        self.packages = tempfile.mkdtemp()
        test.addCleanup(lambda: [__import__("shutil").rmtree(d) for d in (self.root, self.packages)])
        write(os.path.join(self.root, "keys/approvers.txt"), f"# approvers\n{B64_APPROVER}\n".encode())
        write(os.path.join(self.root, "revoked.json"),
              {"seq": 0, "versions": [], "verifications": [], "ids": [], "passes": []})

    def entry(self, entry):
        write(os.path.join(self.root, f"plugins/{entry['id']}.json"), entry)

    def package(self, pid, version, files):
        data = zip_of(files)
        write(os.path.join(self.packages, lib.mirror_tag(pid, version) + ".zip"), data)
        return data

    def signed(self, rel, kind, body, key=SEED7):
        obj = lib.sign(kind, body, key)
        write(os.path.join(self.root, rel), obj)
        return obj

    def build(self, generated="2026-11-26T12:00:00Z"):
        return build_index.build(self.root, self.packages, generated)


class BuildIndexTests(unittest.TestCase):
    def setUp(self):
        self.r = Registry(self)
        self.files = good_files({"author": "Someone", "permissions": ["fight", "world"],
                                 "windows": [{"id": "card", "title": "Card", "entry": "card.html",
                                              "icon": "chart"}]})
        self.r.entry(dict(ENTRY, description="Big numbers.",
                          versions=ENTRY["versions"] + [{"version": "1.1.0", "tag": "v1.1.0",
                                                          "asset": "card.zip"}]))
        self.zip = self.r.package("someone.card", "1.0.0", self.files)

    def test_listing_shape(self):
        index, warnings = self.r.build()
        self.assertEqual(index["generated"], "2026-11-26T12:00:00Z")
        [listing] = index["plugins"]
        self.assertEqual(set(listing), {"id", "name", "author", "description", "icon", "repo",
                                        "elevated", "versions"})
        self.assertEqual((listing["id"], listing["name"], listing["author"], listing["icon"],
                          listing["repo"], listing["description"]),
                         ("someone.card", "Card", "Someone", "chart", "someone/card",
                          "Big numbers."))
        [v] = listing["versions"]
        self.assertEqual(v, {
            "version": "1.0.0",
            "url": "https://github.com/darkharasho/axidps-plugins/releases/download/"
                   "someone.card@1.0.0/someone.card-1.0.0.zip",
            "sha256": lib.sha256_hex(self.zip), "tree": lib.tree_hash(self.files),
            "permissions": ["fight", "world"], "network": ["api.example.com"], "api": 1})
        self.assertTrue(v["url"].startswith(lib.PACKAGE_PREFIX))
        # 1.1.0 has no mirrored zip yet: left out, with a warning.
        self.assertTrue(any("1.1.0" in w for w in warnings), warnings)

    def test_signed_items_are_copied_only_if_they_verify(self):
        tree = lib.tree_hash(self.files)
        good = self.r.signed("approvals/someone.card/1.0.0.json", "approval",
                             {"id": "someone.card", "version": "1.0.0", "tree": tree,
                              "verified": True, "grant": ["world"], "signed": TODAY})
        self.r.signed("approvals/someone.card/1.1.0.json", "approval",
                      {"id": "someone.card", "version": "1.1.0", "tree": tree,
                       "verified": True, "grant": [], "signed": TODAY}, key=seed_pem([8] * 32))
        bad = dict(good, grant=["world", "squad"])
        write(os.path.join(self.r.root, "approvals/someone.card/0.9.0.json"), bad)
        # A file whose path disagrees with what it signs isn't copied either.
        write(os.path.join(self.r.root, "approvals/other.card/1.0.0.json"), good)
        p = self.r.signed("passes/someone.json", "pass",
                          {"login": "someone", "ids": ["someone.*"], "grant": ["world"],
                           "expires": "2027-02-24", "key": B64_APPROVER})
        rev = self.r.signed("revoked.json", "revoked",
                            {"seq": 2, "versions": [], "ids": [], "passes": [],
                             "verifications": [{"id": "x.y.z", "version": "1.0.0", "reason": "r"}]})
        index, warnings = self.r.build()
        self.assertEqual(index["approvals"], [good])
        self.assertEqual(index["passes"], [p])
        self.assertEqual(index["revoked"], rev)
        self.assertEqual(sum("refused" in w for w in warnings), 3, warnings)

    def test_unsigned_revoked_is_left_out(self):
        index, warnings = self.r.build()
        self.assertIsNone(index["revoked"])
        self.assertEqual((index["approvals"], index["passes"]), ([], []))

    def test_a_package_that_fails_its_checks_isnt_listed(self):
        self.r.package("someone.card", "1.0.0", good_files({"version": "9.9.9"}))
        index, warnings = self.r.build()
        self.assertEqual(index["plugins"], [])
        self.assertTrue(any("9.9.9" in w for w in warnings), warnings)

    def test_axidps_ids_and_bad_entries_are_skipped(self):
        self.r.entry(dict(ENTRY, id="axidps.card"))
        write(os.path.join(self.r.root, "plugins/broken.json"), b"{nope")
        index, warnings = self.r.build()
        self.assertEqual([l["id"] for l in index["plugins"]], ["someone.card"])
        # The two entries, 1.1.0 not mirrored, and the unsigned revoked.json stub.
        self.assertEqual(len(warnings), 4, warnings)

    def test_newest_version_names_the_listing(self):
        self.r.package("someone.card", "1.1.0", good_files({"name": "Card Two", "version": "1.1.0"}))
        [listing] = self.r.build()[0]["plugins"]
        self.assertEqual([v["version"] for v in listing["versions"]], ["1.0.0", "1.1.0"])
        self.assertEqual((listing["name"], listing["author"], listing["icon"]),
                         ("Card Two", "someone", "plug"))

    def test_rendered_bytes_sign_and_keep_the_old_time_when_nothing_changed(self):
        index, _ = self.r.build()
        data = build_index.render(index)
        self.assertTrue(data.isascii() and data.endswith(b"\n"))
        sig = lib.sign_bytes(lib.INDEX_PREFIX, data, SEED7)
        self.assertTrue(lib.verify_bytes(lib.INDEX_PREFIX, data, sig, [APPROVER_PUB]))
        later, _ = self.r.build(generated="2026-11-27T00:00:00Z")
        self.assertEqual(build_index.render(build_index.keep_time(later, data)), data)
        self.r.entry(dict(ENTRY, description="Changed."))
        changed, _ = self.r.build(generated="2026-11-27T00:00:00Z")
        self.assertEqual(build_index.keep_time(changed, data)["generated"], "2026-11-27T00:00:00Z")
        self.assertEqual(build_index.keep_time(changed, b"not json")["generated"],
                         "2026-11-27T00:00:00Z")


    def test_index_carries_elevated(self):
        self.r.entry(dict(ENTRY, elevated=["textures"]))
        index, _ = self.r.build()
        [listing] = index["plugins"]
        self.assertEqual(listing["elevated"], ["textures"])


class StandingTests(unittest.TestCase):
    BODY = {"id": "someone.card", "grant": ["textures"], "signed": TODAY}

    def test_standing_shape(self):
        self.assertEqual(lib.shape_problems("standing", self.BODY), [])
        why = lib.shape_problems("standing", {"id": "someone.card", "signed": TODAY})
        self.assertTrue(why and why[0].startswith("grant:"), why)

    def test_sign_verify_standing(self):
        obj = lib.sign("standing", self.BODY, SEED7)
        self.assertTrue(lib.verify("standing", obj, [APPROVER_PUB]))
        self.assertFalse(lib.verify("approval", obj, [APPROVER_PUB]), "the kind is signed too")

    def test_index_copies_standing(self):
        r = Registry(self)
        r.entry(ENTRY)
        good = r.signed("standing/someone.card.json", "standing", self.BODY)
        r.signed("standing/other.json", "standing", self.BODY)
        index, warnings = r.build()
        self.assertEqual(index["standing"], [good])
        self.assertTrue(any("standing/other.json refused" in w for w in warnings), warnings)

    def test_classify_standing_is_signed(self):
        c = pr_check.classify([{"filename": "standing/someone.card.json", "status": "added"}])
        self.assertEqual(len(c["signed"]), 1)
        obj = lib.sign("standing", self.BODY, SEED7)
        self.assertEqual(pr_check.signed_file_problems(
            "standing/someone.card.json", obj, [APPROVER_PUB], 0), [])
        self.assertTrue(pr_check.signed_file_problems(
            "standing/other.json", obj, [APPROVER_PUB], 0))

    def test_revoked_standing_entries_shape(self):
        base = {"seq": 1, "versions": [], "verifications": [], "ids": [], "passes": []}
        self.assertEqual(lib.shape_problems(
            "revoked", dict(base, standing=[{"id": "a.b", "reason": "r"}])), [])
        self.assertTrue(lib.shape_problems("revoked", dict(base, standing=[{"id": "a.b"}])))


class StandingOwnerTests(unittest.TestCase):
    def test_standing_body_defaults_and_sorts(self):
        body = owner.standing_body("someone.card", ["world", "textures", "world"], TODAY)
        self.assertEqual(body, {"id": "someone.card", "grant": ["textures", "world"], "signed": TODAY})
        self.assertEqual(lib.shape_problems("standing", body), [])

    def test_standing_body_refuses_empty(self):
        with self.assertRaises(owner.Refused):
            owner.standing_body("someone.card", [], TODAY)
        with self.assertRaises(owner.Refused):
            owner.standing_body("someone.card", ["fight"], TODAY)

    def test_approve_args_standing_without_version(self):
        a = owner.approve_args(["someone.card", "--standing"])
        self.assertTrue(a.standing)
        self.assertIsNone(a.version)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            owner.approve_args(["someone.card"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            owner.approve_args(["someone.card", "1.0.0", "--standing"])

    def test_revoke_standing_entry(self):
        body = owner.revoke_body({"seq": 3}, "standing", {"id": "someone.card"}, "taken over")
        self.assertEqual(body["standing"], [{"id": "someone.card", "reason": "taken over"}])
        self.assertEqual(body["seq"], 4)
        self.assertEqual(lib.shape_problems("revoked", body), [])


class AutoReleaseTests(unittest.TestCase):
    ENTRY = dict(ENTRY, maintainers=["helper"])

    @staticmethod
    def rel(tag, login="someone", asset="card.zip", draft=False, pre=False):
        return {"tag_name": tag, "draft": draft, "prerelease": pre, "author": {"login": login},
                "assets": [{"name": asset}]}

    def test_discover_picks_newer_published_owner_releases(self):
        found = pr_check.discover(self.ENTRY, [self.rel("v1.2.0", "helper"), self.rel("v1.1.0")])
        self.assertEqual(found, [{"version": "1.1.0", "tag": "v1.1.0", "asset": "card.zip"},
                                 {"version": "1.2.0", "tag": "v1.2.0", "asset": "card.zip"}])

    def test_discover_skips_prerelease_draft_and_strangers(self):
        rels = [self.rel("v1.1.0", pre=True), self.rel("v1.2.0", draft=True),
                self.rel("v1.3.0", "stranger"), self.rel("v1.4.0", asset="other.zip")]
        self.assertEqual(pr_check.discover(self.ENTRY, rels), [])

    def test_discover_skips_older_or_bad_tags(self):
        rels = [self.rel("v1.0.0"), self.rel("v0.9.0"), self.rel("latest"), self.rel("1.5.0")]
        self.assertEqual(pr_check.discover(self.ENTRY, rels), [])
        e = dict(self.ENTRY, versions=[{"version": "1.0.0-beta.2", "tag": "v1.0.0-beta.2",
                                        "asset": "card.zip"}])
        self.assertEqual([v["version"] for v in pr_check.discover(e, [self.rel("v1.0.0")])],
                         ["1.0.0"], "a release is newer than its pre-releases")

    def test_discover_off_when_auto_false(self):
        e = dict(self.ENTRY, auto=False)
        self.assertEqual(pr_check.discover(e, [self.rel("v1.1.0")]), [])

    def test_widened_reports_new_permission_and_host(self):
        last = {"permissions": ["fight"], "network": ["api.example.com"]}
        new = {"permissions": ["fight", "world"], "network": ["api.example.com", "dps.report"]}
        self.assertEqual(pr_check.widened(new, last), ["world", "network dps.report"])

    def test_widened_empty_when_within(self):
        last = {"permissions": ["fight", "world"], "network": ["api.example.com"]}
        self.assertEqual(pr_check.widened({"permissions": ["fight"], "network": []}, last), [])

    def test_check_entry_accepts_auto_bool_refuses_other(self):
        self.assertEqual(lib.check_entry(dict(ENTRY, auto=False), "someone.card"), [])
        self.assertEqual(lib.check_entry(dict(ENTRY, auto="no"), "someone.card"),
                         ["auto: must be true or false"])

    def test_semver_order(self):
        order = ["0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0", "1.0.1", "1.10.0"]
        self.assertEqual(sorted(reversed(order), key=lib.semver_key), order)


class AutoListTests(unittest.TestCase):
    """publish.auto_list with GitHub faked: releases, the package check and the contents API."""

    def setUp(self):
        import publish
        self.publish = publish
        self.r = Registry(self)
        self.r.entry(ENTRY)
        self.r.package("someone.card", "1.0.0", good_files())
        self.calls = []
        rels = [AutoReleaseTests.rel(t) for t in ("v1.1.0", "v1.2.0", "v1.3.0")]
        asks = {"1.1.0": ["fight"], "1.2.0": ["fight", "world"], "1.3.0": ["fight"]}

        def gh_json(path):
            if path.startswith("repos/someone/card/releases"):
                return rels
            if "/contents/" in path:
                return {"sha": "abc"}
            raise AssertionError(path)

        def check_version(env, entry, v):
            return {"id": entry["id"], "version": v["version"], "problems": [],
                    "permissions": asks[v["version"]], "network": ["api.example.com"]}

        for mod, name, fn in ((publish, "gh_json", gh_json), (publish, "gh", lambda *a, **k: self.calls.append(a)),
                              (publish.pr_check, "check_version", check_version)):
            old = getattr(mod, name)
            setattr(mod, name, fn)
            self.addCleanup(setattr, mod, name, old)

    def test_lists_within_and_stops_at_a_widened_release(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            added = self.publish.auto_list({"REPO": "darkharasho/axidps-plugins"},
                                           json.loads(json.dumps(ENTRY)), self.r.packages)
        self.assertEqual([v["version"] for v in added], ["1.1.0"])
        self.assertIn("someone.card 1.2.0 asks for world; it needs a pull request", out.getvalue())
        self.assertEqual(self.calls, [], "nothing is written to the repository")

    def test_nothing_new_when_auto_false(self):
        e = dict(ENTRY, auto=False)
        self.assertEqual(self.publish.auto_list({"REPO": "x/y"}, e, self.r.packages), [])

    def test_auto_notes_round_trip(self):
        v = {"version": "1.1.0", "tag": "v1.1.0", "asset": "card.zip"}
        notes = self.publish.mirror_notes(ENTRY, v, "t" * 64, auto=True)
        rels = [{"tag_name": "someone.card@1.1.0", "body": notes},
                {"tag_name": "someone.card@1.0.0", "body": self.publish.mirror_notes(
                    ENTRY, ENTRY["versions"][0], "t" * 64, auto=False)},
                {"tag_name": "other.x@1.1.0", "body": notes},
                {"tag_name": "index", "body": "auto-listed: {}"}]
        self.assertEqual(self.publish.auto_marked(rels), {"someone.card": [v]},
                         "only a note whose version and id match its own tag counts")

    def test_with_auto_adds_recorded_versions_once(self):
        v = {"version": "1.1.0", "tag": "v1.1.0", "asset": "card.zip"}
        e = self.publish.with_auto(ENTRY, {"someone.card": [v, ENTRY["versions"][0]]})
        self.assertEqual([x["version"] for x in e["versions"]], ["1.0.0", "1.1.0"])
        self.assertEqual(len(ENTRY["versions"]), 1, "the entry itself is left alone")


class OwnerTests(unittest.TestCase):
    MANIFEST = {"id": "someone.card", "version": "1.0.0", "permissions": ["fight", "world"]}

    def test_approval_body(self):
        body = owner.approval_body("someone.card", "1.0.0", "a" * 64, self.MANIFEST,
                                   ["world"], False, TODAY)
        self.assertEqual(body, {"id": "someone.card", "version": "1.0.0", "tree": "a" * 64,
                                "verified": True, "grant": ["world"], "signed": TODAY})
        self.assertEqual(lib.shape_problems("approval", body), [])
        plain = owner.approval_body("someone.card", "1.0.0", "a" * 64, self.MANIFEST, [], True, TODAY)
        self.assertEqual((plain["verified"], plain["grant"]), (False, []))

    def test_grant_defaults_to_elevated(self):
        e = {"elevated": ["textures"]}
        self.assertEqual(owner.grant_for(e, [], False), ["textures"])
        self.assertEqual(owner.grant_for(e, ["textures"], False), ["textures"])
        with self.assertRaises(owner.Refused) as ctx:
            owner.grant_for(e, ["world"], False)
        self.assertIn("isn't in elevated", str(ctx.exception))
        self.assertEqual(owner.grant_for(e, [], True), [])

    def test_grant_with_no_verify_is_refused(self):
        with self.assertRaises(owner.Refused):
            owner.approval_body("someone.card", "1.0.0", "a" * 64, self.MANIFEST,
                                ["world"], True, TODAY)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            owner.approve_args(["someone.card", "1.0.0", "--grant", "world", "--no-verify"])

    def test_grant_must_be_deeper_and_in_the_manifest(self):
        for grant in (["squad"], ["fight"], ["nope"]):
            with self.assertRaises(owner.Refused, msg=grant):
                owner.approval_body("someone.card", "1.0.0", "a" * 64, self.MANIFEST,
                                    grant, False, TODAY)

    def test_pass_body(self):
        body = owner.pass_body("someone", B64_APPROVER, ["someone.*", "other.card"], ["world"],
                               90, TODAY)
        self.assertEqual(body, {"login": "someone", "ids": ["someone.*", "other.card"],
                                "grant": ["world"], "expires": "2027-02-24",
                                "key": B64_APPROVER})
        self.assertEqual(lib.shape_problems("pass", body), [])
        for args in [("bad login!", B64_APPROVER, ["a.b.c"], ["world"]),
                     ("someone", "AAAA", ["a.b.c"], ["world"]),
                     ("someone", B64_APPROVER, ["*"], ["world"]),
                     ("someone", B64_APPROVER, ["axidps.*"], ["world"]),
                     ("someone", B64_APPROVER, [], ["world"]),
                     ("someone", B64_APPROVER, ["a.b.c"], []),
                     ("someone", B64_APPROVER, ["a.b.c"], ["fight"])]:
            with self.assertRaises(owner.Refused, msg=args):
                owner.pass_body(*args, 90, TODAY)
        with self.assertRaises(owner.Refused):
            owner.pass_body("someone", B64_APPROVER, ["a.b.c"], ["world"], 0, TODAY)

    def test_revocations_match_trust_rs(self):
        r = {"seq": 3, "versions": [], "verifications": [], "ids": [], "passes": [],
             "approver": "x", "sig": "y"}
        out = owner.revoke_body(r, "verification", {"id": "a.b.c", "version": "1.0.0"}, "bad")
        self.assertEqual(out["seq"], 4)
        self.assertNotIn("sig", out)
        self.assertNotIn("approver", out)
        self.assertEqual(out["verifications"], [{"id": "a.b.c", "version": "1.0.0", "reason": "bad"}])
        out = owner.revoke_body(out, "version", {"id": "a.b.c", "version": "1.0.0",
                                                  "tree": "b" * 64}, "malware")
        self.assertEqual(out["versions"], [{"id": "a.b.c", "version": "1.0.0", "tree": "b" * 64,
                                            "reason": "malware"}])
        out = owner.revoke_body(out, "id", {"id": "a.b.c"}, "gone")
        out = owner.revoke_body(out, "pass", {"login": "x", "key": B64_APPROVER}, "lost")
        self.assertEqual(out["ids"], [{"id": "a.b.c", "reason": "gone"}])
        self.assertEqual(out["passes"], [{"login": "x", "key": B64_APPROVER, "reason": "lost"}])
        self.assertEqual(out["seq"], 7)
        self.assertEqual(lib.shape_problems("revoked", out), [])
        with self.assertRaises(owner.Refused):
            owner.revoke_body(out, "verification", {"id": "a.b.c", "version": "1.0.0"}, "")
        with self.assertRaises(owner.Refused):
            owner.revoke_body(out, "verification", {"id": "a.b.c", "version": "1.0.0"}, "é")

    def test_the_key_is_read_from_1password_only(self):
        self.assertEqual(owner.OP_REF, "op://Private/axidps approver key/private key")
        calls = []

        def fake_run(argv, **kw):
            calls.append((argv, kw))

            class R:
                returncode = 0
                stdout = SEED7
            return R()
        key = owner.read_key(run=fake_run)
        self.assertEqual(key, SEED7)
        [(argv, kw)] = calls
        self.assertEqual(argv, ["op", "read", owner.OP_REF])
        self.assertTrue(kw.get("capture_output"))


class PrDecisionTests(unittest.TestCase):
    def test_classify(self):
        c = pr_check.classify([
            {"filename": "plugins/a.b.c.json", "status": "added"},
            {"filename": "approvals/a.b.c/1.0.0.json", "status": "added"},
            {"filename": "passes/x.json", "status": "modified"},
            {"filename": "revoked.json", "status": "modified"},
            {"filename": "tools/registry/lib.py", "status": "modified"},
            {"filename": "plugins/sub/x.json", "status": "added"},
        ])
        self.assertEqual([f["filename"] for f in c["plugins"]], ["plugins/a.b.c.json"])
        self.assertEqual([f["filename"] for f in c["signed"]],
                         ["approvals/a.b.c/1.0.0.json", "passes/x.json", "revoked.json"])
        self.assertEqual([f["filename"] for f in c["other"]],
                         ["tools/registry/lib.py", "plugins/sub/x.json"])

    def test_file_list_must_be_complete_and_small(self):
        self.assertEqual(pr_check.file_count_problems(3, 3), [])
        self.assertEqual(pr_check.file_count_problems(100, 100), [])
        # GitHub's file list stops at 3000: a short list must never pass as complete.
        self.assertTrue(pr_check.file_count_problems(3000, 3001))
        self.assertTrue(pr_check.file_count_problems(99, 100))
        self.assertTrue(pr_check.file_count_problems(101, 101))

    def test_ownership(self):
        old = dict(ENTRY, maintainers=["helper"])
        self.assertEqual(pr_check.ownership_problems(None, ENTRY, "someone"), [])
        self.assertTrue(pr_check.ownership_problems(None, ENTRY, "stranger"))
        self.assertEqual(pr_check.ownership_problems(old, old, "someone"), [])
        self.assertEqual(pr_check.ownership_problems(old, old, "helper"), [])
        self.assertTrue(pr_check.ownership_problems(old, old, "stranger"))
        # A maintainer can't hand the id to someone else; GitHub logins compare without case.
        self.assertTrue(pr_check.ownership_problems(old, dict(old, owner="helper"), "helper"))
        self.assertEqual(pr_check.ownership_problems(old, dict(old, owner="helper"), "SomeOne"), [])

    def test_listed_versions_dont_change(self):
        v1 = ENTRY["versions"][0]
        v2 = {"version": "1.1.0", "tag": "v1.1.0", "asset": "card.zip"}
        new, problems = pr_check.new_versions(ENTRY, dict(ENTRY, versions=[v1, v2]))
        self.assertEqual((new, problems), ([v2], []))
        self.assertEqual(pr_check.new_versions(None, ENTRY), ([v1], []))
        _, problems = pr_check.new_versions(ENTRY, dict(ENTRY, versions=[dict(v1, tag="v1.0.0b")]))
        self.assertTrue(problems)
        _, problems = pr_check.new_versions(dict(ENTRY, versions=[v1, v2]), ENTRY)
        self.assertTrue(problems)

    def test_release_author(self):
        e = dict(ENTRY, maintainers=["helper"])
        self.assertTrue(pr_check.release_author_ok(e, {"author": {"login": "Helper"}}))
        self.assertFalse(pr_check.release_author_ok(e, {"author": {"login": "stranger"}}))
        self.assertFalse(pr_check.release_author_ok(e, {}))

    def test_auto_merge(self):
        ok = dict(plugins_only=True, problems=[], deeper=[], verify=False, setting="on")
        self.assertTrue(pr_check.auto_merge(**ok))
        self.assertTrue(pr_check.auto_merge(**dict(ok, setting="")))
        for edit in ({"plugins_only": False}, {"problems": ["x"]}, {"deeper": ["world"]},
                     {"verify": True}, {"setting": "off"}, {"setting": "OFF"}):
            self.assertFalse(pr_check.auto_merge(**dict(ok, **edit)), edit)

    def test_signed_file_checks(self):
        tree = "c" * 64
        a = lib.sign("approval", {"id": "a.b.c", "version": "1.0.0", "tree": tree,
                                  "verified": True, "grant": [], "signed": TODAY}, SEED7)
        keys = [APPROVER_PUB]
        self.assertEqual(pr_check.signed_file_problems("approvals/a.b.c/1.0.0.json", a, keys, 0), [])
        self.assertTrue(pr_check.signed_file_problems("approvals/a.b.c/2.0.0.json", a, keys, 0))
        self.assertTrue(pr_check.signed_file_problems("approvals/a.b.c/1.0.0.json",
                                                      dict(a, tree="d" * 64), keys, 0))
        self.assertTrue(pr_check.signed_file_problems("approvals/a.b.c/1.0.0.json", a, [], 0))
        p = lib.sign("pass", {"login": "x", "ids": ["x.*"], "grant": ["world"],
                              "expires": "2027-01-01", "key": B64_APPROVER}, SEED7)
        self.assertEqual(pr_check.signed_file_problems("passes/x.json", p, keys, 0), [])
        self.assertTrue(pr_check.signed_file_problems("passes/y.json", p, keys, 0))
        r = lib.sign("revoked", {"seq": 2, "versions": [], "verifications": [], "ids": [],
                                 "passes": []}, SEED7)
        self.assertEqual(pr_check.signed_file_problems("revoked.json", r, keys, 1), [])
        self.assertTrue(pr_check.signed_file_problems("revoked.json", r, keys, 2))

    def test_elevated_matches_manifest(self):
        self.assertEqual(
            pr_check.elevated_problems({"elevated": ["textures"]}, ["textures", "world"]),
            ["the manifest asks for textures, world; elevated lists textures"])
        self.assertEqual(
            pr_check.elevated_problems({"elevated": ["world", "textures"]}, ["textures", "world"]), [])
        self.assertEqual(pr_check.elevated_problems({"elevated": []}, []), [])

    def test_comment_shows_elevated(self):
        base = {"id": "a.b.c", "version": "1.0.0", "permissions": ["fight", "textures"],
                "network": []}
        self.assertIn("- elevated: `textures`",
                      pr_check.comment([dict(base, elevated=["textures"])], []))
        self.assertIn("- elevated: none", pr_check.comment([dict(base, elevated=[])], []))

    def test_comment_keeps_untrusted_text_in_code(self):
        body = pr_check.comment([{
            "id": "a.b.c", "version": "1.0.0", "tree": "c" * 64, "sha256": "d" * 64,
            "permissions": ["fight", "world"], "network": ["api.example.com"],
            "deeper": ["world"], "approved": False, "problems": ["entry \"@someone `x`\": bad"],
        }], ["owner: @x"])
        self.assertIn(pr_check.MARKER, body)
        self.assertIn("needs approval to load", body)
        self.assertNotIn("`x`", body)
        for line in body.splitlines():
            if "@" in line:
                self.assertTrue(line.strip().startswith("- `") or line.strip().startswith("`"), line)



class PortFixtures(unittest.TestCase):
    """port-fixtures.json pins AxiAdmin's TypeScript port; it must match what lib produces."""

    def test_port_fixtures_are_current(self):
        import port_fixtures
        with open(port_fixtures.PATH, encoding="utf-8") as f:
            committed = json.load(f)
        built = port_fixtures.build()
        self.assertEqual(built["comments"], committed["comments"])
        self.assertEqual(built["approval_files"], committed["approval_files"])
        # Deflate output can differ between zlib versions, so zip bytes aren't compared; what
        # the port sees (the unpacked result) is, and the committed bytes must still decode to it.
        self.assertEqual([{k: v for k, v in z.items() if k != "zip"} for z in built["zips"]],
                         [{k: v for k, v in z.items() if k != "zip"} for z in committed["zips"]])
        for z in committed["zips"]:
            try:
                files = lib._unpack(base64.b64decode(z["zip"]))
            except ValueError:
                self.assertTrue(z["refused"], z["name"])
                continue
            self.assertFalse(z["refused"], z["name"])
            self.assertEqual({p: base64.b64encode(b).decode() for p, b in files.items()},
                             z["files"], z["name"])
            self.assertEqual(lib.tree_hash(list(files.items())), z["tree"], z["name"])

    def test_approval_files_verify_and_are_canonical_text(self):
        import port_fixtures
        with open(port_fixtures.PATH, encoding="utf-8") as f:
            committed = json.load(f)  # key order survives the trip from disk
        self.assertTrue(committed["approval_files"])
        for a in committed["approval_files"]:
            self.assertEqual(list(a["obj"]), ["id", "version", "tree", "verified", "grant",
                                              "signed", "approver", "sig"])
            self.assertEqual(json.dumps(a["obj"], indent=2, ensure_ascii=True) + "\n", a["text"])
            self.assertEqual(json.loads(a["text"]), a["obj"])
            self.assertTrue(lib.verify("approval", a["obj"], [base64.b64decode(a["pub"])]))


if __name__ == "__main__":
    unittest.main()
