The lazyfs backend: one FSKit mount per workspace, one subroot per sandbox, nothing materialized.

A create resolves the action's input tree, writes it to `manifests/<name>.pb`, and touches
`mnt/<name>` once — that lookup is what makes the appex build the subroot, and it leaves the kernel
holding a positive entry for the name. Names are unique per create: Bazel reuses sandbox ids, and a
name the kernel has ever answered ENOENT for is negative-cached per name, so a reused one would
stay dead for the rest of the build. Declared outputs and writable dirs project as symlinks to host
scratch, which is where the action's writes actually land; `collect` renames them to the exec root.

Requires macOS 27 or later — the appex serves this shape only from its `FSVolume.Handler` volume.
The Swift half lives in `fskit-appex/`; `cargo run -p backend-fskit --example e2e` checks the whole
round trip against a real mount, and `--example probe` decodes a manifest.
