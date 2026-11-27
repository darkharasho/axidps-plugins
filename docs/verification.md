## Verification checklist

This pull request asks for verification (`"verify": true`). The owner reviews the unpacked
files of each version at the tree hash in the registry check comment, and approves a version
only if all of these hold:

- [ ] **Readable source.** The package's code is readable. Minified or bundled code is only
      allowed with its source next to it in the package.
- [ ] **Every network domain explained.** Each host in `network` is listed in the README with
      what the plugin sends there and gets back.
- [ ] **Every deeper permission explained.** Each of `world`, `position`, `squad`, `enemies` or
      `textures` the manifest asks for is explained in the README, with what it does in game.
- [ ] **ArenaNet's third-party tool policy.** Nothing in it breaks the policy. That means no
      automation, no input on the player's behalf and no reading game memory beyond what
      axidps gives a plugin.
- [ ] **What it does.** The README has a short "what it does" section.

When everything checks out, the owner runs this on their machine:

```
tools/registry/approve <id> <version> [--grant world,position]
```

The tool recomputes the tree hash, shows the manifest, signs with the approver key and pushes
`approvals/<id>/<version>.json` on a branch for the owner to merge. Each approval is for one
exact version and tree hash. A new version is Unverified until it is approved too. Until then
the store keeps offering the last approved version and shows "update awaiting review".
