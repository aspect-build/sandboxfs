# Contributing

sandboxfs is a sandbox implementation for Bazel on macOS that projects an action's inputs as
real files instead of symlinks. Contributions are welcome — bug reports, backends, measurements
that contradict ours.

Most of this document is about the Xcode half of the project, because that is the part with
traps in it. The Rust half behaves the way you expect: `cargo build`, `cargo test --workspace`.

## What is and isn't here

This repository holds the controller Bazel talks to, the backend interface, the `fskit` backend
built on FSKit, the metrics daemon, and the dashboard app. The default `cfs` backend is a
separate commercial product and is not part of this repository; `crates/backend-cfs` here is an
MIT-licensed stand-in with the same entry point that returns "unsupported". A build of this
repository is complete and useful without it — it serves `fskit`, and every test passes.

| Path | What it is |
|---|---|
| `crates/backend` | The `Backend` trait, the protobuf wire codec, the blob store, the pool location, daemon-level counters |
| `crates/sandboxd` | The `sandboxfs` binary: the stdio server Bazel drives, its worker pool, the metrics gate |
| `crates/backend-fskit` | The `fskit` backend — writes a manifest the appex materializes lazily |
| `crates/metrics` | The root `metricsd` LaunchDaemon: kdebug syscall attribution per workspace, and its XPC feed |
| `crates/backend-cfs` | Stand-in for the commercial backend (see above) |
| `fskit-appex/` | The FSKit module `fskit` mounts |
| `sandbox/` | The metrics dashboard app |
| `packaging/` | Signing, notarization, `.pkg`/`.dmg` assembly |

---

# The Xcode journey

`sandbox.xcodeproj` contains **one scheme, `sandbox`, and two targets**:

- **`sandbox`** — the dashboard app (`sandbox/`). It is also the registration vehicle: an FSKit
  module is only discoverable through the `.app` that embeds it.
- **the appex** (`fskit-appex/`) — an ExtensionKit extension, embedded into the app at
  `Contents/Extensions/`. This is what actually serves `fskit` mounts.

They ship as one version-locked artifact, together with the Rust CLI, for that reason.

Entitlements are per target: `fskit-appex/SandboxFS.entitlements` for the extension (it carries
`com.apple.developer.fskit.fsmodule`) and `packaging/entitlements/sandbox.entitlements` for the
app.

## Before you open the project

**You need a full Xcode, and probably the beta.** The FSKit APIs the appex uses only exist in
the macOS 26.4 SDK, and at the time of writing the appex needs a beta SDK to compile at all —
which is why the release workflow is run by hand instead of on push, and why GitHub-hosted
runners cannot cut releases yet.

`xcode-select` commonly points at the Command Line Tools, which have no `xcodebuild`. Rather
than repoint it globally, set `DEVELOPER_DIR` for the invocation:

```
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild -scheme sandbox -configuration Release
```

`packaging/package.sh` does this for you: with no explicit `DEVELOPER_DIR` it picks
`Xcode-beta.app` first, then `Xcode.app`, so it works regardless of what `xcode-select` says.

## Registering the appex

This is the part that surprises everyone. macOS discovers an FSKit module through the containing
app, so editing appex code is not enough — the system keeps serving the previously registered
copy until you force it to pick up the new one:

1. Build the app **in Release** — the embedding target, not just the appex.
2. **Launch it.** Registration happens when the containing app runs.
3. `killall fskit-appex` — the running extension process is holding the old code; killing it
   makes the next mount spawn the new one.

To remove a debug registration:

```
pluginkit -r <path to the .appex>
```

Stale registrations are the usual cause of "my change had no effect": you are still talking to a
copy of the extension registered from some earlier build.

> **TODO** — the day-to-day loop inside Xcode (which scheme to run, where the appex's stdout
> goes, how to attach the debugger to a running `fskit-appex`, what Console.app filter is worth
> keeping) is best described by someone who lives in it. This section is a skeleton to fill in.

## Mounting by hand

You do not need Bazel to exercise the appex. The CLI carries a dev helper that builds a manifest
from a real directory tree:

```
sandboxfs mkmanifest <src_dir> <out.pb>
mount -F -t sandboxfs -o nobrowse <out.pb> <mnt>
```

`sandboxfs debugmanifest <manifest.pb>` dumps what a manifest actually contains, which is the
fastest way to tell a projection bug from a manifest bug.

## Signing traps

- The archive step in `packaging/package.sh` builds with `CODE_SIGNING_ALLOWED=NO` on purpose and
  re-signs everything inside-out afterwards, so the archive stays identity-agnostic.
- `SANDBOXFS_ADHOC=1 ./packaging/package.sh` does a full unsigned dry run — it validates the
  assembly, the pkg layout and the postinstall without needing certificates. Use it before
  claiming a packaging change works.
- A locally built dashboard app must be ad-hoc signed **with its entitlements** before `open`.
  Launching an unsigned or wrongly signed build of a sandboxed app fails to spawn with error
  162, which reads like a crash and is not one.

> **TODO** — provisioning profiles and the FSKit capability: what a contributor without Aspect's
> team ID can and cannot build, and what the failure looks like when they can't.

---

# The Rust half

```
cargo build
cargo test --workspace
```

There is no PR CI yet, so run the suite locally before opening one.

## Writing a backend

The most useful place to contribute. A backend implements `backend::Backend`:

- `create(sandbox_id, manifest_bytes, store)` — materialize the action's input tree and return
  the path it runs in. Return `CreateOutcome::MissingContent(digests)` when the manifest
  references content the session store lacks; Bazel pushes those and retries. That is a normal,
  recoverable outcome, not an error.
- `collect(sandbox_id, exec_root)` — harvest the action's declared outputs.
- `destroy(sandbox_id)` — release the sandbox.

`start`, `metrics_prefix`, `blobs_pushed`, `capture_content`, and `report_text` are optional.
Implementations are shared across worker threads, so `&self` and `Send + Sync`.

Wire it up in `select()` in `crates/sandboxd/src/main.rs` and give it a name in `resolve()`. The
backend name is folded into the pool key, so two backends never share a workspace subtree.

`crates/backend-cfs` is the one file to leave alone: its `open` signature is mirrored by the commercial
crate, and changing it here breaks that build without any local test failing.

## Running a real Bazel build

You need a Bazel that supports `--sandbox_backend`. That flag is not upstream yet — see
[bazelbuild/bazel#29165](https://github.com/bazelbuild/bazel/issues/29165) — so this currently
means a patched Bazel distributed by Aspect. Then:

```
common --enable_platform_specific_config
common:macos --sandbox_backend=aspect-sandbox=sandboxfs
common:macos --spawn_strategy=aspect-sandbox,local
```

---

# House rules

Design constraints, not preferences — a change that violates one will be sent back:

- **No symlinks in a projected tree.** Real files, or hardlinks where inode identity is the
  point. Not leaking host paths through `realpath`/`argv[0]`/`dladdr` is the whole premise.
- **No state outside what Bazel already maintains.** Placement and layout of a pool are fine; a
  second source of truth that survives a build is not.
- **No environment-variable feature gates.** If it works it ships unconditionally; if it doesn't
  it comes out. Existing `CFS_*` knobs are tuning, not switches for half-finished work.
- **Never slower than `darwin-sandbox`.** Parity is the floor, not the goal.

## Style

- Comments explain *why*, never *what*. The codebase is dense with rationale — measured numbers,
  syscall costs, why an approach was rejected — and nearly free of comments restating the line
  below them.
- No banner comments dividing a file into sections, no `MARK:`.
- Prefer deleting code to adding it. The smallest change that fully solves the problem wins.
- Tests live beside what they test in `#[cfg(test)] mod tests`, named as the sentence they
  assert.

## Performance claims

This project exists for one number, so measurements are held to a standard:

- Report **Elapsed time** from Bazel's own output.
- Say whether the build was cold or warm, and make cold actually cold.
- Compare against `darwin-sandbox` on the same machine and workload, back to back — not against
  a number from another session.
- Watch for machine noise: thermal state, power, and other load move these numbers more than
  most changes do.

## Pull requests

One concern per PR. Commit messages are lowercase and imperative, saying what the change does
and why it was needed. Include the measurement if the claim is performance.

By contributing you agree that your contributions are licensed under the MIT License, the same
terms as this repository ([LICENSE](LICENSE)).
