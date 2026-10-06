# benchmark

Per-syscall cost of five ways to stage a Bazel action's inputs on macOS: a userspace **fskit**
volume, a per-file byte **copy()**, a per-file **symlink()** farm, a per-file **link()** farm, and
one APFS **clonefile()** of the tree. The same generated trees, laid down each way, read back by
one C harness (readdir, getattrlistbulk, stat, open, read, mmap fault, execve), cold and warm. The
exec'd tool is a 16MB binary that has already run once on the host, so its cold column is what a
backend adds on top: nothing for a shared inode, a fresh AMFI validation for a new one.

```
python3 benchmark/bench.py                 # one sample → results.json, numbers.json, index.html
python3 benchmark/bench.py --run 2         # another sample → results.2.json
python3 benchmark/bench.py --aggregate     # median of every results*.json → numbers.json, index.html
open benchmark/index.html
```

- `bench.c` generates the trees, lays them down, and times every call (`bench work <dir> [meta|open|read|full]`).
- `stage/` is `bench-stage`, the fskit driver: mounts and creates a sandbox through `backend-fskit`
  exactly as the daemon would. bench.py builds it with cargo; fskit is skipped when the appex is not
  registered (see CONTRIBUTING.md).
- `chart.html` is the page template; `index.html` is it with `numbers.json` filled in.
- `numbers.json` is the slide file: `payloads.<name>.<metric>.<backend>.{cold, warm}`, unit in the key.

Trees and laid-down copies live under `BENCH_ROOT` (default `~/.sandboxfs/bench`), not here: FSKit
resource access is TCC-gated and the appex is denied `~/Documents`. Cold is `sudo purge` only when
sudo is passwordless (`sudo -v` first); otherwise it is first touch after laydown, and `numbers.json`
says which you got. Run on AC power.

`pathbench.py` holds the path-stability experiments written up in the cfs repo's CACHING.md.
