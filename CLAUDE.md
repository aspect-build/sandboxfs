- No comment is the best comment, write code that explains itself.
- Best code is no code, understand what you are dealing with first and write minimum amount of code. 
- In order for appex to re-register you need to build (release) and launch the app that embeds the appex and then run `killall fskit-appex`
- You can use `pluginkit -r ` to deregister a debug appex.
- No banner style comments sectioning the code, no MARK: comments.
- No environment var based feature gates, if something works it stays, if it doesn't its out.

# Constraints

- No use of symlinks, unless the cost of not using them outweighs the performance. Prefer hardlinks over symlinks if you must use symlinks.
- No state outside of what Bazel maintains in the name of being performant. 
- Always strive to be better than `darwin-sandbox`, and then `local`. being slower even by 1% isn't acceptable, goal is to beat it by flat 20%. 
- Preserve inodes, that's the only way to serve content from page cache.

# Guidelines

- `--reuse_sandbox_directories` is not respected by sandboxfs.
- Do not use `bazel clean` to rerun actions, that introduces inconsistencies in the measurement due to network fetches and skyframe calculations which skews the measurement. use --action_env="bust=$(date)" to make actions rerun.
- Check for machine noise, plugged into power, thermal throttling.
- Find the minimum set of deps to quickly iterate, do not chain bazel build commands that take 30min while you sit idle.