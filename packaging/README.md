# Packaging sandboxfs as a shippable `.pkg`

Builds one notarized installer that ships the whole stack as a version-locked unit:

```
sandbox.pkg
└─ /Applications/sandbox.app
   ├─ Contents/Extensions/fskit-appex.appex   the FSKit module
   └─ Contents/MacOS/sandboxfs               the CLI  →  /usr/local/bin/sandboxfs
```

The app, appex, and CLI ship together because an FSKit module is only discoverable
through its containing `.app`, and the CLI is useless without the matching appex.

## Quick start

```sh
# Local dry run — no certs, validates assembly + pkg layout + postinstall:
SANDBOXFS_ADHOC=1 ./packaging/package.sh

# Real distributable artifact (needs the prerequisites below):
SANDBOXFS_DEVID_APP="Developer ID Application: Your Name (TEAMID)" \
SANDBOXFS_DEVID_INSTALLER="Developer ID Installer: Your Name (TEAMID)" \
SANDBOXFS_NOTARY_PROFILE="sandboxfs-notary" \
SANDBOXFS_PROVISION_PROFILE="/path/to/sandboxfs.provisionprofile" \
./packaging/package.sh
# → dist/sandbox-<version>.pkg  (signed, notarized, stapled)
```

## Prerequisites for a real build

1. **Developer ID Application** + **Developer ID Installer** certificates in the
   login keychain (from the team that owns the App IDs).
   `security find-identity -v -p codesigning` should list both.
2. **Notary credentials** stored once as a keychain profile:
   ```sh
   xcrun notarytool store-credentials sandboxfs-notary \
       --apple-id you@example.com --team-id TEAMID --password <app-specific-pw>
   ```
3. **The FSKit entitlement — RESOLVED, works under Developer ID.**
   The appex carries `com.apple.developer.fskit.fsmodule`. Verified 2026-06-17:
   it passes Apple notarization under a plain **Developer ID** signature with
   **no provisioning profile** (submission Accepted, stapled, Gatekeeper reports
   "Notarized Developer ID"). `SANDBOXFS_PROVISION_PROFILE` stays available only
   as a fallback should Apple's policy ever change.

> Team is `2SZJVCZSQ6` for both the project and the Developer ID certs — no
> mismatch. (An earlier "Personal Team / ZMVV2957A5" reading was a stale Xcode
> account cache, not the real membership.)

## What the install does

- Lands `sandbox.app` in `/Applications`.
- `postinstall` symlinks the embedded CLI to `/usr/local/bin/sandboxfs` and
  best-effort registers the app so `pluginkit` discovers the appex.

## What the user does once (cannot be automated from a root installer)

1. Launch `sandbox.app` once (creates the per-user FSKit settings store + finalizes registration).
2. `sandboxfs enable` — enables the module + bounces `fskitd` (prompts for sudo).
3. Grant **Full Disk Access** to `fskit-appex.appex` if mounting content under
   TCC-protected dirs (`~/Documents`, `~/Desktop`, `~/Downloads`, iCloud).

See the installer's conclusion screen (`resources/conclusion.html`) for the
user-facing version.

## Files

| File | Role |
|---|---|
| `package.sh` | the pipeline: archive → assemble → sign → pkgbuild → productbuild → notarize → staple |
| `entitlements/sandbox.entitlements` | host app (sandbox + user-selected read-only) |
| `entitlements/sandboxfs.entitlements` | CLI (hardened runtime, no capabilities) |
| `../fskit-appex/SandboxFS.entitlements` | appex (FSKit module + sandbox + file exception) — reused from the project |
| `scripts/postinstall` | symlink CLI, register app |
| `distribution.xml` | productbuild distribution (UI, OS check) |
| `resources/{welcome,conclusion}.html` | installer screens |
