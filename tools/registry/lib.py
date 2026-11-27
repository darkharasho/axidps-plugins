"""Registry rules shared by CI and the owner's tools. Mirrors axidps's crates/axidps-plugins:
sign.rs (canonical JSON, signatures), tree.rs (tree hash), keys.rs (key ids), trust.rs (signed
object shapes), manifest.rs and install.rs (package rules). Standard library plus the openssl
CLI only. A private key only ever goes to openssl on stdin."""

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import unicodedata
import zipfile

MANIFEST_FILE = "axidps-plugin.json"
MAX_UNPACKED = 5 * 1024 * 1024
MAX_FILES = 500
MAX_MANIFEST_BYTES = 64 * 1024
# The overlay downloads at most this many bytes of a package zip.
ZIP_CAP = MAX_UNPACKED + 1024 * 1024
SUPPORTED_API = 1
INDEX_PREFIX = b"axidps-index-v1\n"
KINDS = ("approval", "pass", "revoked")
REGISTRY = "darkharasho/axidps-plugins"
PACKAGE_PREFIX = f"https://github.com/{REGISTRY}/releases/download/"
ICONS = ("chart", "users", "shield", "swords", "activity", "x", "grid", "layers", "sliders",
         "plug", "download", "columns", "plus")
BASIC = ("fight",)
DEEPER = ("world", "position", "squad", "enemies", "textures")
U64_MAX = 2**64 - 1

_SPKI = bytes.fromhex("302a300506032b6570032100")
_SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?", re.ASCII)
_LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}", re.ASCII)
_REPO = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9._+-]{1,100}", re.ASCII)
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


# ---------------------------------------------------------------- canonical JSON, hashes

def canonical(v):
    """sign.rs `canonical`: sorted keys, no whitespace, printable ASCII strings, integers in
    0..=u64::MAX. Anything else raises ValueError."""
    out = []
    _write(v, out)
    return "".join(out)


def _write(v, out):
    if v is None:
        out.append("null")
    elif isinstance(v, bool):  # before int: bool is an int in Python
        out.append("true" if v else "false")
    elif isinstance(v, int):
        if not 0 <= v <= U64_MAX:
            raise ValueError(f"canonical JSON: {v} isn't a non-negative integer")
        out.append(str(v))
    elif isinstance(v, str):
        _write_str(v, out)
    elif isinstance(v, list):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _write(x, out)
        out.append("]")
    elif isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise ValueError("canonical JSON: keys must be strings")
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda k: k.encode("utf-8", "surrogatepass"))):
            if i:
                out.append(",")
            _write_str(k, out)
            out.append(":")
            _write(v[k], out)
        out.append("}")
    else:
        raise ValueError(f"canonical JSON: {type(v).__name__} isn't allowed")


def _write_str(s, out):
    bad = next((c for c in s if not " " <= c <= "~"), None)
    if bad is not None:
        raise ValueError(f"canonical JSON: {bad!r} isn't printable ASCII")
    out.append('"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"')


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def tree_hash(files):
    """tree.rs `hash_files`: SHA-256 over `path NUL size NUL bytes`, sorted by path bytes."""
    h = hashlib.sha256()
    for path, data in sorted(files, key=lambda f: f[0].encode()):
        h.update(path.encode() + b"\0" + str(len(data)).encode() + b"\0")
        h.update(data)
    return h.hexdigest()


# ---------------------------------------------------------------- keys and signatures

def _b64(s, size):
    """Strict standard base64 of exactly `size` bytes (as Rust's STANDARD decodes), else None."""
    if not isinstance(s, str):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except ValueError:
        return None
    if len(raw) != size or base64.b64encode(raw).decode() != s:
        return None
    return raw


def raw_public(pub_pem):
    """The 32-byte key inside an Ed25519 public key PEM."""
    text = pub_pem.decode() if isinstance(pub_pem, bytes) else pub_pem
    body = "".join(l for l in text.strip().splitlines() if not l.startswith("-----"))
    der = base64.b64decode(body)
    if len(der) != 44 or not der.startswith(_SPKI):
        raise ValueError("not an Ed25519 public key")
    return der[12:]


def pem_of_raw(raw):
    return (b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(_SPKI + raw)
            + b"\n-----END PUBLIC KEY-----\n")


def key_id(pub_pem):
    """keys.rs: lowercase hex of the first 8 bytes of SHA-256 of the 32-byte public key."""
    return hashlib.sha256(raw_public(pub_pem)).hexdigest()[:16]


def _id_of_raw(raw):
    return hashlib.sha256(raw).hexdigest()[:16]


def public_pem(key_pem):
    """The public half of a private key PEM (bytes), via openssl with the key on stdin."""
    r = subprocess.run(["openssl", "pkey", "-in", "/dev/stdin", "-pubout"], input=key_pem,
                       capture_output=True, check=False)
    if r.returncode != 0:
        raise ValueError("openssl couldn't read the private key")
    return r.stdout


def sign_bytes(prefix, data, key_pem):
    """Standard base64 Ed25519 signature over `prefix + data`; the key goes in on stdin."""
    with tempfile.TemporaryDirectory() as d:
        msg = os.path.join(d, "msg")
        with open(msg, "wb") as f:
            f.write(prefix + data)
        r = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", "/dev/stdin",
                            "-in", msg], input=key_pem, capture_output=True, check=False)
    if r.returncode != 0 or len(r.stdout) != 64:
        raise ValueError("openssl couldn't sign")
    return base64.b64encode(r.stdout).decode()


def verify_bytes(prefix, data, sig_b64, keys):
    """True if `sig_b64` is a signature over `prefix + data` by any of `keys` (32-byte raw)."""
    sig = _b64(sig_b64, 64)
    if sig is None:
        return False
    with tempfile.TemporaryDirectory() as d:
        sig_path, msg = os.path.join(d, "sig"), os.path.join(d, "msg")
        with open(sig_path, "wb") as f:
            f.write(sig)
        with open(msg, "wb") as f:
            f.write(prefix + data)
        for i, k in enumerate(keys):
            pub = os.path.join(d, f"pub{i}.pem")
            with open(pub, "wb") as f:
                f.write(pem_of_raw(k))
            r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub,
                                "-rawin", "-in", msg, "-sigfile", sig_path],
                               capture_output=True, check=False)
            if r.returncode == 0:
                return True
    return False


def _message(kind, obj):
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind}")
    body = {k: v for k, v in obj.items() if k != "sig"}
    return f"axidps-{kind}-v1\n".encode(), canonical(body).encode()


def sign(kind, obj, key_pem):
    """`obj` with `approver` (the key's id) and `sig` over `axidps-<kind>-v1\\n` + canonical."""
    body = {k: v for k, v in obj.items() if k not in ("sig", "approver")}
    body["approver"] = key_id(public_pem(key_pem))
    prefix, data = _message(kind, body)
    return dict(body, sig=sign_bytes(prefix, data, key_pem))


def verify(kind, obj, keys):
    """sign.rs `verify_object`: `sig` checks out under a trusted key whose id is `approver`."""
    if not isinstance(obj, dict) or not isinstance(obj.get("sig"), str):
        return False
    approver = obj.get("approver")
    trusted = [k for k in keys if _id_of_raw(k) == approver]
    if not trusted:
        return False
    try:
        prefix, data = _message(kind, obj)
    except ValueError:
        return False
    return verify_bytes(prefix, data, obj["sig"], trusted)


def load_approvers(path):
    """`keys/approvers.txt`: one standard-base64 32-byte public key per line; `#` comments."""
    keys = []
    with open(path, encoding="ascii") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                raw = _b64(line, 32)
                if raw is None:
                    raise ValueError(f"{path}: {line!r} isn't a base64 32-byte key")
                keys.append(raw)
    return keys


# ---------------------------------------------------------------- signed object shapes

def _need(o, f, kind, out):
    if not isinstance(o.get(f), kind) or (kind is int and isinstance(o.get(f), bool)):
        out.append(f"{f}: not a {kind.__name__}")
        return False
    return True


def _strings(o, f, out):
    v = o.get(f)
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        out.append(f"{f}: not a list of strings")


def _entries(o, f, fields, out):
    v = o.get(f, [])
    if not isinstance(v, list) or not all(isinstance(e, dict) for e in v):
        out.append(f"{f}: not a list of objects")
        return
    for i, e in enumerate(v):
        for name in fields:
            if name == "key":
                if _b64(e.get("key"), 32) is None:
                    out.append(f"{f}[{i}].key: not a base64 32-byte key")
            elif not isinstance(e.get(name), str):
                out.append(f"{f}[{i}].{name}: not a string")


def shape_problems(kind, o):
    """The fields trust.rs needs for an approval, pass or revoked object, as it parses them."""
    out = []
    if not isinstance(o, dict):
        return ["not an object"]
    if kind == "approval":
        for f in ("id", "version", "tree"):
            _need(o, f, str, out)
        _need(o, "verified", bool, out)
        _strings(o, "grant", out)
    elif kind == "pass":
        for f in ("login", "expires"):
            _need(o, f, str, out)
        if isinstance(o.get("expires"), str) and not _DATE.fullmatch(o["expires"]):
            out.append("expires: not YYYY-MM-DD")
        _strings(o, "ids", out)
        _strings(o, "grant", out)
        if _b64(o.get("key"), 32) is None:
            out.append("key: not a base64 32-byte key")
    elif kind == "revoked":
        if _need(o, "seq", int, out) and not 0 <= o["seq"] <= U64_MAX:
            out.append("seq: not a number")
        _entries(o, "versions", ("id", "version", "tree", "reason"), out)
        _entries(o, "verifications", ("id", "version", "reason"), out)
        _entries(o, "ids", ("id", "reason"), out)
        _entries(o, "passes", ("login", "key", "reason"), out)
    else:
        out.append(f"unknown kind {kind}")
    return out


# ---------------------------------------------------------------- names and manifests

def valid_id(s):
    return isinstance(s, str) and 3 <= len(s) <= 48 and re.fullmatch(r"[a-z0-9.-]+", s) is not None


def valid_semver(s):
    return isinstance(s, str) and _SEMVER.fullmatch(s) is not None


def valid_login(s):
    return isinstance(s, str) and _LOGIN.fullmatch(s) is not None


def deeper(permissions):
    return [p for p in permissions if p in DEEPER]


_LOCAL_TLDS = ("localhost", "local", "lan", "internal", "home.arpa")


def valid_host(s):
    """manifest.rs `valid_host`: a public host name, optional leading `*.`."""
    h = s[2:] if s.startswith("*.") else s
    labels = h.split(".")
    last = labels[-1].lower()
    numeric = (last.isascii() and last.isdigit()) or last == "" or (
        last.startswith("0x") and all(c in "0123456789abcdef" for c in last[2:]))
    lower = h.lower()
    local = any(lower == t or lower.endswith("." + t) for t in _LOCAL_TLDS)
    return (h != "" and len(h) <= 253 and len(labels) >= 2 and not numeric and not local
            and all(l and len(l) <= 63 and not l.startswith("-") and not l.endswith("-")
                    and re.fullmatch(r"[A-Za-z0-9-]+", l) for l in labels))


def _valid_window_id(s):
    return s != "" and re.fullmatch(r"[a-z0-9-]+", s) is not None


def _valid_entry(s):
    return (s != "" and not s.startswith("/") and not any(c in s for c in "\0\\:")
            and all(c not in ("", ".", "..") for c in s.split("/"))
            and s.split("/")[0] != "_sdk")


def _percent_decode(s):
    """serve.rs `percent_decode`: `%XX` decoded, other bytes kept; None if not UTF-8."""
    b = s.encode()
    out = bytearray()
    i = 0
    while i < len(b):
        h = b[i + 1:i + 3]
        if b[i] == 0x25 and len(h) == 2 and all(c in b"0123456789abcdefABCDEF" for c in h):
            out.append(int(h, 16))
            i += 3
        else:
            out.append(b[i])
            i += 1
    try:
        return out.decode()
    except UnicodeDecodeError:
        return None


def _resolves(entry, files):
    """serve.rs `resolve`, against in-memory files: the entry names one of them."""
    rel = _percent_decode(entry)
    if (rel is None or rel == "" or "\0" in rel or "\\" in rel or rel.startswith("/")
            or ".." in rel.split("/") or rel.endswith("/")):
        return False
    return "/".join(c for c in rel.split("/") if c not in ("", ".")) in files


def _str_field(o, k, ctx, out):
    v = o.get(k)
    if isinstance(v, str) and v.strip():
        return v
    if isinstance(v, str):
        out.append(f"{ctx}{k}: must not be empty")
    elif k in o:
        out.append(f"{ctx}{k}: must be a string")
    else:
        out.append(f"{ctx}{k}: missing")
    return None


def _str_list(o, k, out):
    v = o.get(k)
    if v is None and k not in o:
        return []
    if not isinstance(v, list):
        out.append(f"{k}: must be a list")
        return []
    if not all(isinstance(x, str) for x in v):
        out.append(f"{k}: entries must be strings")
    return [x for x in v if isinstance(x, str)]


def _no_constants(name):
    raise ValueError(f"{name} isn't JSON")


def manifest_problems(data, files):
    """manifest.rs `problems` plus `axidps plugin check`'s missing-entry lines. `files` holds
    the package's file paths. Returns (manifest or None, problems)."""
    if len(data) > MAX_MANIFEST_BYTES:
        return None, [f"manifest: {len(data)} bytes, at most {MAX_MANIFEST_BYTES}"]
    try:
        o = json.loads(data.decode("utf-8"), parse_constant=_no_constants)
    except ValueError as e:
        return None, [f"manifest: not valid JSON ({e})"]
    if not isinstance(o, dict):
        return None, ["manifest: must be a JSON object"]
    out = []
    mid = _str_field(o, "id", "", out)
    if mid is not None and not valid_id(mid):
        out.append(f'id: "{mid}" must be 3-48 characters of a-z 0-9 . -')
    name = _str_field(o, "name", "", out)
    version = _str_field(o, "version", "", out)
    if version is not None and not valid_semver(version):
        out.append(f'version: "{version}" is not a semantic version (like 1.0.0)')
    author = o.get("author", "")
    if not isinstance(author, str):
        out.append("author: must be a string")
        author = ""
    api, newer_api = 0, False
    a = o.get("api")
    if "api" not in o:
        out.append("api: missing")
    elif isinstance(a, bool) or not isinstance(a, (int, float)):
        out.append("api: must be a number")
    elif isinstance(a, float) or not 0 <= a <= 2**32 - 1:
        out.append("api: must be a whole number")
    else:
        api, newer_api = a, a != SUPPORTED_API
    permissions = _str_list(o, "permissions", out)
    for p in permissions:
        if p not in BASIC and p not in DEEPER:
            out.append(f'permissions: unknown permission "{p}"')
    network = _str_list(o, "network", out)
    for n in network:
        if not valid_host(n):
            out.append(f'network: "{n}" must be a public host name like api.example.com '
                       "(HTTPS only, no scheme, port or path; not an IP address, localhost "
                       "or a local-network name)")
    windows = []
    w = o.get("windows")
    if "windows" not in o:
        out.append("windows: missing")
    elif not isinstance(w, list):
        out.append("windows: must be a list")
    else:
        if not 1 <= len(w) <= 4:
            out.append(f"windows: {len(w)} given, {'at least 1' if not w else 'at most 4'}")
        for i, x in enumerate(w):
            win = _window(x, i, out)
            if win is not None:
                if any(y["id"] == win["id"] for y in windows):
                    out.append(f'windows[{i}].id: "{win["id"]}" is used twice')
                windows.append(win)
    if any(p == "_sdk" or p.startswith("_sdk/") for p in files):
        out.append('folder: a top-level "_sdk" folder is not allowed (the host serves /_sdk/)')
    if newer_api and out:
        out.insert(0, "needs a newer axidps")
    # `axidps plugin check`: window entries that aren't files, unless already reported.
    if isinstance(w, list):
        for i, x in enumerate(w):
            e = x.get("entry") if isinstance(x, dict) else None
            field = f"windows[{i}].entry"
            if (isinstance(e, str) and not _resolves(e, files)
                    and not any(p.startswith(field + ":") for p in out)):
                out.append(f"{field}: {json.dumps(e)} not found")
    if out:
        return None, out
    return {"id": mid, "name": name, "version": version, "author": author, "api": api,
            "permissions": permissions, "network": network, "windows": windows}, []


def _window(w, i, out):
    ctx = f"windows[{i}]."
    if not isinstance(w, dict):
        out.append(f"windows[{i}]: must be an object")
        return None
    before = len(out)
    wid = _str_field(w, "id", ctx, out)
    if wid is not None and not _valid_window_id(wid):
        out.append(f'{ctx}id: "{wid}" must be a-z 0-9 -')
    title = _str_field(w, "title", ctx, out)
    entry = _str_field(w, "entry", ctx, out)
    if entry is not None and not _valid_entry(entry):
        out.append(f'{ctx}entry: "{entry}" must be a path inside the plugin folder')
    desc = w.get("description", "")
    if not isinstance(desc, str):
        out.append(f"{ctx}description: must be a string")
    icon = w.get("icon")
    icon = icon if icon in ICONS else "plug"
    if "open" in w and not isinstance(w["open"], bool):
        out.append(f"{ctx}open: must be true or false")
    if "place" in w and w["place"] not in ("beside-meter", "below-meter"):
        out.append(f'{ctx}place: must be "beside-meter" or "below-meter"')
    if len(out) != before:
        return None
    return {"id": wid, "title": title, "entry": entry, "icon": icon}


# ---------------------------------------------------------------- registry entries

ENTRY_FIELDS = ("id", "owner", "maintainers", "repo", "description", "icon", "verify",
                "versions")


def check_entry(entry, file_id):
    """Problems with a `plugins/<file_id>.json` entry."""
    if not isinstance(entry, dict):
        return ["the entry must be a JSON object"]
    out = [f"{k}: not a known field" for k in entry if k not in ENTRY_FIELDS]
    eid = entry.get("id")
    if not valid_id(eid):
        out.append("id: must be 3-48 characters of a-z 0-9 . -")
    elif eid.startswith("axidps."):
        out.append("id: axidps.* ids are reserved for bundled plugins")
    if eid != file_id:
        out.append(f"id: must match the file name (plugins/{file_id}.json)")
    if not valid_login(entry.get("owner")):
        out.append("owner: must be a GitHub login")
    m = entry.get("maintainers", [])
    if not isinstance(m, list) or not all(valid_login(x) for x in m):
        out.append("maintainers: must be a list of GitHub logins")
    repo = entry.get("repo")
    if (not isinstance(repo, str) or not _REPO.fullmatch(repo)
            or repo.split("/")[1] in (".", "..")):
        out.append('repo: must be "owner/name" of a GitHub repository')
    d = entry.get("description", "")
    if not isinstance(d, str) or len(d) > 300 or any(unicodedata.category(c) == "Cc" for c in d):
        out.append("description: must be text of at most 300 characters")
    if "icon" in entry and entry["icon"] not in ICONS:
        out.append(f"icon: must be one of {', '.join(ICONS)}")
    if not isinstance(entry.get("verify", False), bool):
        out.append("verify: must be true or false")
    vs = entry.get("versions")
    if not isinstance(vs, list) or not vs:
        out.append("versions: must be a non-empty list")
        return out
    seen = set()
    for i, v in enumerate(vs):
        ctx = f"versions[{i}]"
        if not isinstance(v, dict) or set(v) != {"version", "tag", "asset"}:
            out.append(f"{ctx}: must be {{version, tag, asset}}")
            continue
        if not valid_semver(v["version"]):
            out.append(f"{ctx}.version: not a semantic version (like 1.0.0)")
        elif v["version"] in seen:
            out.append(f"{ctx}.version: listed twice")
        seen.add(v["version"] if isinstance(v["version"], str) else None)
        if not isinstance(v["tag"], str) or not _NAME.fullmatch(v["tag"]):
            out.append(f"{ctx}.tag: must be 1-100 characters of A-Z a-z 0-9 . _ + -")
        a = v["asset"]
        if not isinstance(a, str) or not _NAME.fullmatch(a) or not a.endswith(".zip"):
            out.append(f"{ctx}.asset: must be a .zip file name of A-Z a-z 0-9 . _ + -")
    return out


def mirror_tag(pid, version):
    """The registry release a version's zip is mirrored to."""
    return f"{pid}@{version}"


def asset_name(pid, version):
    return f"{pid}-{version}.zip"


def package_url(pid, version):
    return f"{PACKAGE_PREFIX}{mirror_tag(pid, version)}/{asset_name(pid, version)}"


# ---------------------------------------------------------------- packages

UNICODE_PATH_EXTRA = 0x7075


def _extra_ids(extra):
    """The header ids of a zip entry's extra fields."""
    ids, i = [], 0
    while i + 4 <= len(extra):
        hid, size = int.from_bytes(extra[i:i + 2], "little"), int.from_bytes(extra[i + 2:i + 4], "little")
        ids.append(hid)
        i += 4 + size
    return ids


def log_safe(s):
    """`s` for a log line: printable characters only, no line breaks, and no leading `::` that
    GitHub Actions would read as a workflow command."""
    s = "".join(c if c.isprintable() else " " for c in str(s))
    return " " + s if s.lstrip().startswith("::") else s


def _components(info):
    """install.rs `components` on the entry's raw name: (parts, is_dir) or raises ValueError."""
    # The zip crate the client uses replaces the header name with an Info-ZIP Unicode Path
    # extra field when its CRC matches, so the name checked here could differ from the one
    # installed: refuse such entries, and any name zipfile itself rewrote.
    if UNICODE_PATH_EXTRA in _extra_ids(info.extra):
        raise ValueError(f'entry "{log_safe(info.filename)}": a Unicode Path extra field '
                         "(names must be in the header only)")
    if info.orig_filename != info.filename and "\0" not in info.orig_filename:
        raise ValueError(f'entry "{log_safe(info.orig_filename)}": its name reads differently '
                         "in different zip readers")
    raw = (info.orig_filename.encode("utf-8") if info.flag_bits & 0x800
           else info.orig_filename.encode("cp437"))
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("an entry name isn't UTF-8") from None
    shown = "".join(c if c.isprintable() else "?" for c in name)

    def bad(why):
        return ValueError(f'entry "{shown}": {why}')
    if any(unicodedata.category(c) == "Cc" for c in name):
        raise bad("control characters in the name")
    if "\\" in name:
        raise bad("\\ in the name")
    if ":" in name:
        raise bad("a drive letter or : in the name")
    if name.startswith("/"):
        raise bad("an absolute path")
    is_dir = name.endswith("/")
    parts = (name[:-1] if is_dir else name).split("/")
    for p in parts:
        if p == "":
            raise bad("an empty path component")
        if p in (".", ".."):
            raise bad("a . or .. component")
    return parts, is_dir


def _unpack(data):
    """install.rs `unpack`, in memory: {path: bytes} of the plain files, or raises ValueError."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = z.infolist()
    except (zipfile.BadZipFile, ValueError, OSError, EOFError) as e:
        raise ValueError(f"not a zip: {e}") from None
    if len(infos) > MAX_FILES * 2:
        raise ValueError(f"more than {MAX_FILES} files")
    seen = {}

    def claim(path, is_dir):
        key = path.lower()
        if key in seen:
            p, d = seen[key]
            if is_dir and d and p == path:
                return
            raise ValueError(f'entry "{path}": a duplicate path')
        seen[key] = (path, is_dir)
    files, total = {}, 0
    for info in infos:
        parts, is_dir = _components(info)
        path = "/".join(parts)
        mode = info.external_attr >> 16 if info.create_system == 3 else 0
        kind = mode & 0o170000
        if kind not in (0, 0o040000 if is_dir else 0o100000):
            raise ValueError(f'entry "{path}": not a plain file')
        for n in range(1, len(parts)):
            claim("/".join(parts[:n]), True)
        claim(path, is_dir)
        if is_dir:
            continue
        if len(files) + 1 > MAX_FILES:
            raise ValueError(f"more than {MAX_FILES} files")
        left = MAX_UNPACKED - total
        try:
            with z.open(info) as f:
                body = f.read(left + 1)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError, OSError,
                EOFError) as e:
            raise ValueError(f'entry "{path}": {e}') from None
        total += len(body)
        if total > MAX_UNPACKED:
            raise ValueError(f"unpacks to more than {MAX_UNPACKED} bytes")
        files[path] = body
    return files


def check_package(zip_path, entry, version):
    """A downloaded package checked as an install would check it: (manifest, tree, sha256,
    problems). `manifest` is None and `tree` is None when the package can't be used."""
    with open(zip_path, "rb") as f:
        data = f.read(ZIP_CAP + 1)
    sha = sha256_hex(data)
    if len(data) > ZIP_CAP:
        return None, None, sha, [f"the zip is more than {ZIP_CAP} bytes"]
    try:
        files = _unpack(data)
    except ValueError as e:
        return None, None, sha, [str(e)]
    tree = tree_hash(list(files.items()))
    if MANIFEST_FILE not in files:
        return None, tree, sha, [f"the package has no {MANIFEST_FILE} at its root"]
    manifest, problems = manifest_problems(files[MANIFEST_FILE], files)
    eid = entry.get("id") if isinstance(entry, dict) else None
    if not valid_id(eid) or eid.startswith("axidps."):
        problems.append(f'"{eid}" is not a store plugin id')
    if manifest is not None and (manifest["id"] != eid or manifest["version"] != version):
        problems.append(f"the package is {manifest['id']} {manifest['version']}, "
                        f"the entry says {eid} {version}")
    return (manifest if not problems else None), tree, sha, problems
