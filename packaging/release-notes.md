## sandboxfs

A fast, symlink-free macOS sandbox for Bazel, backed by an FSKit filesystem.

### Requirements

- macOS on Apple Silicon (arm64). The default `cfs` backend runs on current and older releases; the `fskit` backend requires macOS **26.4+**.
- A Bazel built with **[bazelbuild/bazel#29886](https://github.com/bazelbuild/bazel/pull/29886)** — the `--sandbox_backend` spawn strategy isn't in a released Bazel yet (see below).

### Install

Download `sandboxfs-0.0.0-arm64.dmg`, open it, and run the `.pkg` inside — it installs the `sandboxfs` CLI at `/usr/local/bin/sandboxfs` and the `metricsd` daemon. (You can also run the `.pkg` directly.) No activation needed.

### Configure Bazel

Add to your `.bazelrc`:

```
common --enable_platform_specific_config
common:macos --sandbox_backend=aspect-sandbox=sandboxfs
common:macos --spawn_strategy=aspect-sandbox,local
# Enable metrics if you'd like to
# common:macos --sandbox_backend_opt=sandboxfs=--metrics
```

`metricsd` is installed and running; uncomment the last line to record build metrics and view them in **sandbox.app**.

### Getting a compatible Bazel (PR #29886)

The `--sandbox_backend` strategy is not in any released Bazel. The easiest way
to get a compatible one is a prebuilt binary via bazelisk — add a `.bazeliskrc`
next to your `MODULE.bazel`:

```
BAZELISK_BASE_URL=https://pub-90373ea72c18406aa51795a25b1e5957.r2.dev/bazel
USE_BAZEL_VERSION=9.2.0-sandboxfs
```

bazelisk downloads the fork on the next invocation. See
<https://pub-90373ea72c18406aa51795a25b1e5957.r2.dev/index.html> for the current
version and checksum.

Prefer building it yourself? Build from
[thesayyn/bazel@sandboxfs](https://github.com/thesayyn/bazel/tree/sandboxfs):

```
git clone --depth 1 -b sandboxfs https://github.com/thesayyn/bazel.git
cd bazel
bazel build //src:bazel-dev
```

The binary lands at `bazel-bin/src/bazel-dev`; point your builds at it with
`USE_BAZEL_VERSION=/absolute/path/to/bazel-bin/src/bazel-dev`.
