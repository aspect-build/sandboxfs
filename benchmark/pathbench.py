#!/usr/bin/env python3
"""Experiments on sandbox path caching. Placement/laydown cost (clonefile vs
rename, stable vs unique names) is NOT the point of any of these — it's
never what's reported. The only thing that matters is READ I/O speed
(readdir/getattrlistbulk/stat/open/read/fault) and whether it's faster when
things are left stable (vnode reuse, low churn) vs churned.

--exp io (default): full read-I/O (readdir/getattrlistbulk/stat/open/read/
fault over the WHOLE tree, via `bench work`) across four ways a target tree
can exist — laydown/placement cost is never reported, only what reading it
back afterward costs:
  sitting    - clonefile once at the start, never touched again.
  fresh      - every round: rm + clonefile(2) straight onto the target.
  mv_stable  - every round: clonefile into a stash name, rm the fixed
               target, rename(2) the stash tree onto it.
  mv_churn   - identical, but rename(2) onto a fresh, never-repeated target
               name every round.
  fresh_warm - same as fresh, but pre-page-faults the whole tree (one
               throwaway `work()` pass) before the MEASURED pass — tests
               whether the fresh/sitting gap is just an empty per-vnode UBC
               (fixable by warming it) rather than a structural tax.
--siblings N layers a background churn of N threads doing their own
clonefile+rm cycles elsewhere, to see whether a gap holds under contention.

--exp touched: is an UNTOUCHED path faster to stat(2) than a TOUCHED one?
  untouched  - clonefile once up front, then just re-stat it forever.
  touched    - every cycle: rm the path, clonefile(src, path) fresh onto it,
               then stat it.

--exp renamepath: clonefile(tree) into a stash, then mv (rename(2)) it into
place — does the PLACEMENT path being stable vs unique move the numbers?
  stable  - every cycle: clonefile(src, stash/tmp_i), rm the fixed dst,
            rename(stash/tmp_i, dst).
  unique  - identical, but dst is a fresh name every cycle.

    python3 benchmark/pathbench.py [iters] [--siblings N] [--exp io|touched|renamepath]
"""
import json, os, random, shutil, statistics, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bench")
ROOT = os.environ.get("BENCH_ROOT") or os.path.expanduser("~/.sandboxfs/bench")   # same trees bench.py generates
SRC = os.path.join(ROOT, "input", "manysmall", "pkg000")
SRC_IO = os.path.join(ROOT, "input", "manysmall")
BASE = os.path.join(ROOT, "work", "pathbench")
LOOKUPS = 1
OPS = ["readdir", "getattrlistbulk", "stat", "open", "read", "fault"]
WORK_OPS = ["readdir", "getattrlistbulk", "stat", "open", "read"]   # "fault" is a re-read variant, not extra work


def build():
    if not os.path.exists(BIN) or os.path.getmtime(os.path.join(HERE, "bench.c")) > os.path.getmtime(BIN):
        subprocess.run(["cc", "-O2", "-o", BIN, os.path.join(HERE, "bench.c"), "-framework", "CoreFoundation"], check=True)


def clone_ns(src, dst):
    return int(subprocess.run([BIN, "clone", src, dst], capture_output=True, check=True).stdout)


def stat_ns(path):
    out = subprocess.run([BIN, "lookup", path, str(LOOKUPS)], capture_output=True, check=True, text=True).stdout
    return json.loads(out)[0]


def rename_ns(src, dst):
    return int(subprocess.run([BIN, "rename", src, dst], capture_output=True, check=True).stdout)


def rm(path):
    if os.path.lexists(path):
        shutil.rmtree(path)


def start_churn(sibling_dir, n, stop):
    """Background contention: N threads, each mints a never-repeated name,
    clonefile's it, removes it, forever — the syscall load a busy /sandbox
    pool of concurrent build actions would put on the filesystem."""
    counters = [0] * n

    def run(idx):
        while not stop.is_set():
            d = os.path.join(sibling_dir, f"churn_{idx}_{counters[idx]:08d}")
            try:
                clone_ns(SRC, d)
                rm(d)
            except Exception:
                pass
            counters[idx] += 1
    threads = [threading.Thread(target=run, args=(i,), daemon=True) for i in range(n)]
    for t in threads:
        t.start()
    return threads, counters


def work_json(path):
    out = subprocess.run([BIN, "work", path], capture_output=True, check=True, text=True).stdout
    return json.loads(out)


def summarize(vals):
    vals = sorted(vals)
    n = len(vals)
    return (f"n={n:<4d} mean={statistics.mean(vals):9.0f} median={statistics.median(vals):9.0f} "
            f"p10={vals[int(n*0.10)]:9.0f} p90={vals[min(int(n*0.90), n-1)]:9.0f} "
            f"p99={vals[min(int(n*0.99), n-1)]:9.0f} max={vals[-1]:9.0f}")


def permutation_p(a, b, stat=statistics.median, iters=4000):
    obs = abs(stat(a) - stat(b))
    pooled = a + b
    na = len(a)
    hits = 0
    for _ in range(iters):
        random.shuffle(pooled)
        if abs(stat(pooled[:na]) - stat(pooled[na:])) >= obs:
            hits += 1
    return hits / iters


def run(iters, siblings):
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)

    stop = threading.Event()
    counters = None
    if siblings:
        churn_dir = os.path.join(BASE, "siblings")
        os.makedirs(churn_dir, exist_ok=True)
        _, counters = start_churn(churn_dir, siblings, stop)
        time.sleep(0.5)   # let churn ramp up before measuring

    untouched_dst = os.path.join(BASE, "untouched")
    touched_dst = os.path.join(BASE, "touched")
    rm(untouched_dst)
    clone_ns(SRC, untouched_dst)   # created once, never touched again

    untouched, touched = [], []
    order = ["untouched", "touched"]
    for i in range(iters):
        if i % 2:
            order = order[::-1]
        for arm in order:
            if arm == "untouched":
                untouched.append(stat_ns(untouched_dst))
            else:
                rm(touched_dst)
                clone_ns(SRC, touched_dst)
                touched.append(stat_ns(touched_dst))

    if counters is not None:
        print(f"  churn: {siblings} threads minted {sum(counters)} unique dirs during this run", file=sys.stderr)
    stop.set()
    shutil.rmtree(BASE, ignore_errors=True)
    return untouched, touched


def run_renamepath(iters, siblings):
    """clonefile always lands in a throwaway stash name; the only variable is
    whether the rename(2) DESTINATION is a fixed name (reused, rm'd first) or
    a fresh one every cycle (never existed before)."""
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)
    stash = os.path.join(BASE, "stash")
    os.makedirs(stash, exist_ok=True)

    stop = threading.Event()
    counters = None
    if siblings:
        churn_dir = os.path.join(BASE, "siblings")
        os.makedirs(churn_dir, exist_ok=True)
        _, counters = start_churn(churn_dir, siblings, stop)
        time.sleep(0.5)

    stable_dst = os.path.join(BASE, "rename_stable")
    place_stable, stat_stable = [], []
    place_unique, stat_unique = [], []
    order = ["stable", "unique"]
    for i in range(iters):
        if i % 2:
            order = order[::-1]
        for arm in order:
            tmp = os.path.join(stash, f"tmp_{arm}_{i:06d}")
            clone_ns(SRC, tmp)   # off critical path in a real system
            dst = stable_dst if arm == "stable" else os.path.join(BASE, f"rename_seq_{i:06d}")
            rm(dst)
            p = rename_ns(tmp, dst)
            s = stat_ns(dst)
            rm(dst)
            if arm == "stable":
                place_stable.append(p); stat_stable.append(s)
            else:
                place_unique.append(p); stat_unique.append(s)

    if counters is not None:
        print(f"  churn: {siblings} threads minted {sum(counters)} unique dirs during this run", file=sys.stderr)
    stop.set()
    shutil.rmtree(BASE, ignore_errors=True)
    return (place_stable, stat_stable), (place_unique, stat_unique)


def run_io(rounds, siblings):
    """Full read-I/O (readdir/getattrlistbulk/stat/open/read/fault over the
    WHOLE tree, via `bench work`) across four ways a target tree can exist.
    Laydown/placement cost is never reported — only the resulting work()
    numbers. Arms, round-robin interleaved so every arm sees the same
    moment-to-moment system load:

      sitting    - clonefile once at the start, never touched again.
      fresh      - every round: rm + clonefile(2) straight onto the target.
      mv_stable  - every round: clonefile into a stash name, rm the fixed
                   target, rename(2) the stash tree onto it.
      mv_churn   - identical, but rename(2) onto a fresh, never-repeated
                   target name every round (removed after measuring).
    """
    shutil.rmtree(BASE, ignore_errors=True)
    os.makedirs(BASE, exist_ok=True)
    stash = os.path.join(BASE, "stash")
    os.makedirs(stash, exist_ok=True)

    stop = threading.Event()
    counters = None
    if siblings:
        churn_dir = os.path.join(BASE, "siblings")
        os.makedirs(churn_dir, exist_ok=True)
        _, counters = start_churn(churn_dir, siblings, stop)
        time.sleep(0.5)

    sitting_dst = os.path.join(BASE, "sitting")
    fresh_dst = os.path.join(BASE, "fresh")
    mv_stable_dst = os.path.join(BASE, "mv_stable")
    fresh_warm_dst = os.path.join(BASE, "fresh_warm")
    clone_ns(SRC_IO, sitting_dst)   # created once, never touched again

    arms = ["sitting", "fresh", "mv_stable", "mv_churn", "fresh_warm"]
    results = {a: [] for a in arms}
    order = arms[:]
    for i in range(rounds):
        order = order[1:] + order[:1]   # round-robin so every arm rotates through every slot
        for arm in order:
            if arm == "sitting":
                target = sitting_dst
            elif arm == "fresh":
                rm(fresh_dst)
                clone_ns(SRC_IO, fresh_dst)
                target = fresh_dst
            elif arm == "mv_stable":
                tmp = os.path.join(stash, f"tmp_mvstable_{i:05d}")
                clone_ns(SRC_IO, tmp)
                rm(mv_stable_dst)
                rename_ns(tmp, mv_stable_dst)
                target = mv_stable_dst
            elif arm == "mv_churn":
                tmp = os.path.join(stash, f"tmp_mvchurn_{i:05d}")
                clone_ns(SRC_IO, tmp)
                target = os.path.join(BASE, f"mv_churn_{i:05d}")
                rename_ns(tmp, target)
            else:  # fresh_warm
                rm(fresh_warm_dst)
                clone_ns(SRC_IO, fresh_warm_dst)
                work_json(fresh_warm_dst)   # throwaway pre-page-fault pass
                target = fresh_warm_dst
            results[arm].append(work_json(target))
            if arm == "mv_churn":
                rm(target)   # never revisited — clean up immediately

    if counters is not None:
        print(f"  churn: {siblings} threads minted {sum(counters)} unique dirs during this run", file=sys.stderr)
    stop.set()
    shutil.rmtree(BASE, ignore_errors=True)
    return results


def report_io(results, rounds, label):
    def total_work(w):
        return sum(w[o]["total_ns"] for o in WORK_OPS)

    print(f"\n#### full read I/O per round (whole-tree work() pass) — {label}, {rounds} rounds/arm ####")
    for arm, rs in results.items():
        totals = [total_work(w) for w in rs]
        print(f"  {arm:10s} work-total: {summarize(totals)}")

    pairs = [("sitting", "fresh"), ("mv_stable", "mv_churn"), ("fresh", "mv_stable"), ("sitting", "mv_stable"),
             ("fresh", "fresh_warm"), ("sitting", "fresh_warm")]
    for a, b in pairs:
        report(a, [total_work(w) for w in results[a]], b, [total_work(w) for w in results[b]],
               f"work-total: {a} vs {b}")
        for op in OPS:
            av = [w[op]["total_ns"] for w in results[a]]
            bv = [w[op]["total_ns"] for w in results[b]]
            p = permutation_p(av, bv, stat=statistics.mean)
            d = statistics.mean(av) - statistics.mean(bv)
            print(f"    {op:16s} mean delta ({a}-{b}) = {d:+9.0f} ns  p={p:.3f}")


def report(name_a, a, name_b, b, header):
    print(f"\n#### {header} ####")
    print(f"  {name_a:9s}: {summarize(a)}")
    print(f"  {name_b:9s}: {summarize(b)}")
    total_a, total_b = sum(a), sum(b)
    for name, stat in [("median", statistics.median), ("mean", statistics.mean)]:
        d = stat(a) - stat(b)
        p = permutation_p(a, b, stat=stat)
        ratio = stat(b) / stat(a) if stat(a) else float("inf")
        print(f"  {name:6s} delta ({name_a}-{name_b}) = {d:+9.0f} ns   ratio {name_b}/{name_a} = {ratio:.2f}x   p={p:.4f}")
    n = len(a)
    print(f"  sum over {n} calls: {name_a}={total_a/1e6:.2f}ms  {name_b}={total_b/1e6:.2f}ms  "
          f"-> {name_b} costs {(total_b-total_a)/1e6:+.2f}ms more per {n} syscalls "
          f"({(total_b-total_a)/n:+.0f} ns/call amortized)")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    siblings = 0
    if "--siblings" in sys.argv:
        siblings = int(sys.argv[sys.argv.index("--siblings") + 1])
    exp = "io"
    if "--exp" in sys.argv:
        exp = sys.argv[sys.argv.index("--exp") + 1]
    default_iters = 20 if exp == "io" else 400   # io rounds are whole-tree passes, much heavier per round
    iters = int(args[0]) if args else default_iters

    build()
    if not os.path.isdir(SRC) or not os.path.isdir(SRC_IO):
        print(f"missing input trees — run bench.py once to generate inputs first", file=sys.stderr)
        sys.exit(1)

    label = f"contended (siblings={siblings})" if siblings else "isolated"
    print(f"running {iters} interleaved rounds/arm, {label}, exp={exp} ...", file=sys.stderr)

    if exp == "io":
        results = run_io(iters, siblings)
        report_io(results, iters, label)
    elif exp == "touched":
        untouched, touched = run(iters, siblings)
        report("untouched", untouched, "touched", touched, f"untouched vs touched — {label}, {iters} cycles/arm")
    elif exp == "renamepath":
        (place_stable, stat_stable), (place_unique, stat_unique) = run_renamepath(iters, siblings)
        report("stable", place_stable, "unique", place_unique,
               f"rename(2) placement cost, stable vs unique dst — {label}, {iters} cycles/arm")
        report("stable", stat_stable, "unique", stat_unique,
               f"first stat(2) after rename, stable vs unique dst — {label}, {iters} cycles/arm")
    else:
        print(f"unknown --exp {exp}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
