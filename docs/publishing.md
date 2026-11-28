# Publishing a plugin

The axidps plugin store lists the plugins in this repository. To publish yours, open a pull
request that adds `plugins/<id>.json`.

## 1. Make the package

- Check the plugin folder with `axidps plugin check <folder>`. It must print `ok`.
- Zip the folder's contents so that `axidps-plugin.json` sits at the root of the zip, not
  inside a subfolder.
- Limits: at most 500 files and 5 MB unpacked. Use plain files and folders only (no
  symlinks), with `/`-separated names and no `..`, absolute paths, `\` or `:`. Two names that
  differ only in case aren't allowed, and neither is a top-level `_sdk` folder.
- Ids starting with `axidps.` are reserved for bundled plugins.

## 2. Publish a GitHub release

Create a release in your own repository and attach the zip as an asset. You, or a maintainer
listed in your entry, must publish it. CI checks the release's author.

## 3. Open a pull request

Add `plugins/<id>.json`, with the file name matching the id:

```json
{
  "id": "example.dps-card",
  "owner": "your-github-login",
  "maintainers": [],
  "repo": "your-github-login/dps-card",
  "description": "Your DPS, big.",
  "icon": "chart",
  "versions": [{"version": "1.2.0", "tag": "v1.2.0", "asset": "dps-card.zip"}],
  "verify": false,
  "elevated": ["textures"]
}
```

- `owner` must be you, the account that opens the first pull request for the id. That claims
  the id. Only the owner and `maintainers` can change the entry later, and only the owner can
  hand it to someone else.
- `versions` are permanent once merged. To fix a release, publish a new version and add it to
  the list.
- `elevated` is required: the deeper permissions the plugin needs (see below), or `[]` for
  none. It must equal the deeper permissions in each new version's manifest.
- `description` (up to 300 characters) and `icon` are optional. `icon` is one of `chart`,
  `users`, `shield`, `swords`, `activity`, `x`, `grid`, `layers`, `sliders`, `plug`,
  `download`, `columns` or `plus`. Without it, the first window's icon is used.

CI downloads each new version's zip and checks it the way an install would. It comments the
tree hash, the SHA-256, the permissions and the network hosts. A pull request that asks only
for basic permissions (`fight`), doesn't ask for verification and passes every check is merged
automatically.

Once merged, the registry mirrors the zip to its own release `<id>@<version>`, so installs keep
working even if your repository changes. The version then appears in the store as Unverified.

## Later versions: just publish a release

After the first pull request, you don't need one per version. Every hour the registry looks at
your repository's releases and lists a new one by itself when:

- it is published (not a draft or pre-release) by you or a maintainer;
- its tag is `v` and a version newer than every listed one, like `v1.3.0`;
- it has an asset with the same name as your newest listed version's (`dps-card.zip`);
- it passes the same package checks as a pull request;
- its manifest asks for no permission and no network host that your newest listed version
  didn't ask for.

A release that asks for more is skipped, with a warning in the registry's Publish run. Add it
with a pull request as in step 3. Set `"auto": false` in your entry to turn this off.

## Verification and deeper permissions

Set `"verify": true` to ask for verification. The owner reviews the package against
[the checklist](verification.md). A verified version gets the Verified badge.

The deeper permissions are `world`, `position`, `squad`, `enemies` and `textures`. A version
that asks for any of them can still be listed, but it won't load until the owner approves it.
The owner can approve one version (it gets Verified), or give the plugin a **standing
approval** for those permissions. With a standing approval, every later version that asks for
no more loads with them as soon as it is listed. The store shows it as **Permissions approved**
rather than Verified, because nobody read that version's code.

List the ones your plugin needs in the entry's `"elevated"`, for example
`"elevated": ["textures"]`, or `[]` if it needs none. CI fails a new version whose manifest asks
for a different set of deeper permissions than `elevated` lists. The owner's approval grants
what `elevated` lists by default.

## Developer passes

To test deeper permissions on your own machine before review, run `axidps plugin dev-key`.
Send the public key it prints and your GitHub login to the owner. A pass works only with
developer mode on, for plugins loaded from your own plugins folder whose ids it lists, and only
until it expires (90 days by default).
