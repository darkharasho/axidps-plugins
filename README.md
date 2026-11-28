# axidps-plugins

The plugin registry for the [axidps](https://github.com/darkharasho/axidps) plugin store.

- **Publish a plugin:** [docs/publishing.md](docs/publishing.md)
- **Verification checklist:** [docs/verification.md](docs/verification.md)

## Layout

```
plugins/<id>.json                one per plugin, edited by its author
approvals/<id>/<version>.json    approvals, signed by the owner
standing/<id>.json               standing approvals (a plugin's permissions, every version), signed by the owner
passes/<github login>.json       developer passes, signed by the owner
revoked.json                     revocations, signed by the owner (seq only goes up)
keys/approvers.txt               the approver public keys CI checks signatures against
tools/registry/                  CI checks and the owner's signing tools
```

## The index

On every push to main, and hourly, CI mirrors each new version's zip to a release
`<id>@<version>`. It also lists new releases from each plugin's own repository that ask for
nothing beyond its newest listed version; their mirror release's notes carry an
`auto-listed:` line, which is the record that they are listed (see docs/publishing.md). It then builds `index.json` and its signature `index.json.sig`, and publishes
both as assets of the release `index`:

```
https://github.com/darkharasho/axidps-plugins/releases/download/index/index.json
https://github.com/darkharasho/axidps-plugins/releases/download/index/index.json.sig
```

The index key (the Actions secret `INDEX_KEY`) signs the index. It vouches for listings only
and can never grant more than basic permissions. Approvals, standing approvals, passes and
`revoked.json` carry their own approver signatures, and axidps checks those itself.

## Owner tools

Run these from an up-to-date `main` checkout. Each one shows what it will sign and asks y/N.
It then reads the approver key from 1Password with `op read`, signs through `openssl` with the
key on stdin, commits the file on a new branch and pushes it. The key is never printed or
written to disk.

```
tools/registry/approve <id> <version> [--grant world,position] [--no-verify]
tools/registry/approve <id> --standing [--grant textures]
tools/registry/pass <login> --key <base64> --ids someone.*,other.id --grant world [--days 90]
tools/registry/revoke version <id> <version> --reason "..."
tools/registry/revoke verification <id> <version> --reason "..."
tools/registry/revoke id <id> --reason "..."
tools/registry/revoke standing <id> [--sig <sig>] --reason "..."
tools/registry/revoke pass <login> --reason "..."
```

## Settings

- Secret `INDEX_KEY`: the index-signing key, PKCS#8 PEM.
- Variable `AUTO_MERGE`: set it to `off` to stop basic-only pull requests from merging on
  their own.

## Tests

```
python3 -I -m unittest discover tools/registry
```

`tools/registry/vectors.json` is a copy of axidps's `crates/axidps-plugins/tests/vectors.json`,
and CI checks that the two match.

## License

MIT. See [LICENSE](LICENSE).
