# Installing sandboxfs

## 1. Install

Download the latest `sandboxfs-<version>-arm64.dmg` from
[Releases](https://github.com/aspect-build/sandboxfs/releases), open it, and run
the `.pkg` inside. It installs:

- the **`sandboxfs`** CLI symlinked to `/usr/local/bin/sandboxfs`,
- the **metricsd** LaunchDaemon (`/Library/LaunchDaemons/build.aspect.sandbox.metricsd.plist`),
- **sandbox.app** in `/Applications` (the metrics dashboard).

No activation needed.

> Requires macOS 26.4 or newer.

## 2. Wire it into Bazel

Add to your `.bazelrc`:

```
common --enable_platform_specific_config
common:macos --sandbox_backend=aspect-sandbox=sandboxfs
common:macos --spawn_strategy=aspect-sandbox,local
# Enable metrics if you'd like to
# common:macos --sandbox_backend_opt=sandboxfs=--metrics
```

`metricsd` is installed and loaded already; uncomment the last line to record
build metrics and view them in **sandbox.app**.

---

## Building a release (maintainers)

Releases are cut automatically by `.github/workflows/release.yml`:

- push to `main` → a `rolling` prerelease,
- push a `v*.*.*` tag → a versioned release.

To build a signed, notarized artifact locally:

```
SANDBOXFS_DEVID_APP="Developer ID Application: SAHIN YORT (2SZJVCZSQ6)" \
SANDBOXFS_DEVID_INSTALLER="Developer ID Installer: SAHIN YORT (2SZJVCZSQ6)" \
SANDBOXFS_NOTARY_PROFILE="sandboxfs-notary" SANDBOXFS_TEAM_ID="2SZJVCZSQ6" \
./packaging/package.sh
```

`SANDBOXFS_ADHOC=1 ./packaging/package.sh` does an unsigned dry run.
