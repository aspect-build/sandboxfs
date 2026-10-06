#!/usr/bin/env python3
"""Benchmark five sandbox laydown strategies against a bazel-like tree.

    python3 benchmark/bench.py [--seed N] [--keep] [--no-cold] [--render-only]

Builds bench.c, generates the input trees once, then for each backend lays a tree down and runs
the same workloads (C self-timing harness + find + grep) cold and warm. The only variable in a
`work` run is the filesystem. Writes results.json (raw), numbers.json (slide-ready: cold/warm per
metric, ms or µs) and index.html (chart.html with the numbers filled in).

Everything lives under BENCH_ROOT (default ~/.sandboxfs/bench): FSKit resource access is TCC-gated
and the appex is denied ~/Documents, so the inputs cannot sit next to this script.

Cold is `sudo purge` when sudo works without a prompt; otherwise it is first touch after laydown,
which is honest for fskit and clonefile (fresh vnodes) but reads cache-warm for copy/link/symlink.
numbers.json records which one you got.

fskit needs the appex registered (build + launch the embedding app, `killall fskit-appex`); the
`bench-stage` driver in stage/ is built here via cargo.
"""
import argparse, datetime, glob, json, os, platform, shutil, statistics, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "bench")
SRC = os.path.join(HERE, "bench.c")
ROOT = os.environ.get("BENCH_ROOT") or os.path.expanduser("~/.sandboxfs/bench")
INPUT = os.path.join(ROOT, "input")
WORK = os.path.join(ROOT, "work")
FSKIT_BASE = os.path.join(ROOT, "fskit")
RESULTS = os.path.join(HERE, "results.json")
NUMBERS = os.path.join(HERE, "numbers.json")
REPO = os.path.dirname(HERE)
STAGE = os.path.join(REPO, "target/release/bench-stage")
CHART = os.path.join(HERE, "chart.html")
OPS = ["readdir", "getattrlistbulk", "stat", "open", "read", "fault"]
WORK_OPS = ["readdir", "getattrlistbulk", "stat", "open", "read"]   # "work total" (fault re-reads content)

IMPL_ORDER = ["fskit", "copy", "symlink", "link", "clonefile"]
LABELS = {"fskit": "fskit", "copy": "copy()", "symlink": "symlink()", "link": "link()", "clonefile": "clonefile()"}
PAYLOADS = ["manysmall", "fewlarge", "nodemod", "treeheavy"]


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, **kw)


def build():
    if not os.path.exists(BIN) or os.path.getmtime(SRC) > os.path.getmtime(BIN):
        print("building bench.c ...", file=sys.stderr)
        run(["cc", "-O2", "-o", BIN, SRC, "-framework", "CoreFoundation"])
    subprocess.run(["cargo", "build", "--release", "-q", "-p", "bench-stage"], cwd=REPO)


def purge():
    return subprocess.run(["sudo", "-n", "purge"], capture_output=True).returncode == 0


def timed(cmd):
    t = time.monotonic()
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return time.monotonic() - t


NONCE = int(time.time())     # per-run salt so each run's exec binaries are cdhash-fresh


def build_tool(path, tag):
    """A trivial locally-built (ad-hoc signed) exe with a UNIQUE embedded constant, so each
    (payload, backend) binary has its own cdhash. AMFI validates a cdhash once and caches it
    kernel-wide; a unique+fresh cdhash makes every first launch a true cold validation."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    src = f"int _u={tag};int main(){{return _u*0;}}".encode()
    run(["cc", "-O2", "-x", "c", "-o", path, "-"], input=src)


def tool_name(impl):
    return f"tool_{impl}"


def warmup(root):
    run([BIN, "work", root], capture_output=True)


def measure_io(root):
    work = run([BIN, "work", root], capture_output=True, text=True).stdout
    # -L / -RS follow symlinked leaves: a symlink farm (and fskit, whose leaves are host symlinks)
    # must pay the read, not get skipped.
    p = root.rstrip("/") + "/"
    return {
        "work": json.loads(work),
        "find_s": timed(["find", "-L", p, "-type", "f"]),
        "grep_s": timed(["grep", "-RSI", "zzz_no_match_token", p]),
    }


def measure_exec(root, impl):
    """Exec the backend's own binary 30×: first launch = cold code-sign validation, p50 = warm."""
    tool = os.path.join(root, tool_name(impl))
    r = json.loads(run([BIN, "exec", tool, "30"], capture_output=True, text=True).stdout)
    if r["failed"]:
        raise RuntimeError(f"{r['failed']}/{r['count']} launches of {tool} failed")
    return r


# Each lay_* returns (root, cold_laydown_s, warm_laydown_s). The C binary times its own laydown, so
# process spawn is not in the number. A syscall laydown costs the same either way; fskit's first
# create of a tree on a fresh mount is its cold, the second create of the same tree its warm.

def lay_syscall(mode):
    def lay(src, dst):
        ns = int(run([BIN, mode, src, dst], capture_output=True).stdout)
        return dst, ns / 1e9, ns / 1e9
    return lay


FSKIT = {}

def fskit_unmount():
    for line in subprocess.run(["/sbin/mount"], capture_output=True, text=True).stdout.splitlines():
        if "sandboxfs" in line and FSKIT_BASE in line:
            subprocess.run(["/sbin/umount", "-f", line.split(" on ")[1].split(" (")[0]], capture_output=True)

def lay_fskit(src, _dst):
    """A fresh mount per tree so nothing is served from a previous payload's kernel caches."""
    fskit_unmount()
    shutil.rmtree(FSKIT_BASE, ignore_errors=True)
    out = json.loads(run([STAGE, FSKIT_BASE, src, "2"], capture_output=True, text=True).stdout)
    FSKIT.setdefault("mount_s", out["mount_ns"] / 1e9)
    cold, warm = out["creates"]
    # The sandbox root holds the source directory by name; measure the tree, as the others do.
    return os.path.join(cold["path"], os.path.basename(src)), cold["ns"] / 1e9, warm["ns"] / 1e9


LAY = {"fskit": lay_fskit, "copy": lay_syscall("copy"), "symlink": lay_syscall("symlink"),
       "link": lay_syscall("link"), "clonefile": lay_syscall("clone")}


def report(payload, files, laydown, execr, phases):
    c = lambda s: "%-17s" % s
    L = lambda v: "%.1f" % v if v is not None else "-"
    print(f"\n#### {payload} ({files} files) ####")
    print(c("laydown ms") + "".join(c(L(laydown[n]["warm"] * 1e3 if laydown.get(n) else None)) for n in IMPL_ORDER))
    print(c("exec 1st ms") + "".join(c(L(execr[n]["first_ns"] / 1e6 if n in execr else None)) for n in IMPL_ORDER))
    print(c("exec warm ms") + "".join(c(L(execr[n]["p50_ns"] / 1e6 if n in execr else None)) for n in IMPL_ORDER))
    for phase, res in phases.items():
        print(f"-- {phase} --")
        for op in OPS:
            print(c(f"{op} p50 µs") + "".join(
                c(L(res[n]["work"][op]["p50_ns"] / 1000 if n in res and res[n]["work"][op]["count"] else None))
                for n in IMPL_ORDER))
        print(c("find ms") + "".join(c(L(res[n]["find_s"] * 1e3 if n in res else None)) for n in IMPL_ORDER))
        print(c("grep ms") + "".join(c(L(res[n]["grep_s"] * 1e3 if n in res else None)) for n in IMPL_ORDER))


def machine():
    sysctl = lambda k: subprocess.run(["sysctl", "-n", k], capture_output=True, text=True).stdout.strip()
    power = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True).stdout.splitlines()
    return {"model": sysctl("hw.model"), "cpu": sysctl("machdep.cpu.brand_string"),
            "memory_gb": int(sysctl("hw.memsize")) // 2**30, "macos": platform.mac_ver()[0],
            "power": power[0].strip() if power else ""}


def op_p50_us(res, op):
    return {n: res[n]["work"][op]["p50_ns"] / 1000 for n in IMPL_ORDER if n in res and res[n]["work"][op]["count"]}

def work_total_ms(io):
    return sum(io["work"][o]["total_ns"] for o in WORK_OPS) / 1e6


def median_merge(runs):
    """One result tree from several: the median of every numeric leaf, keys present in all runs."""
    if all(isinstance(r, dict) for r in runs):
        keys = set.intersection(*(set(r) for r in runs))
        return {k: median_merge([r[k] for r in runs]) for k in runs[0] if k in keys}
    if all(isinstance(r, (int, float)) and not isinstance(r, bool) for r in runs):
        return statistics.median(runs)
    return runs[-1]


def write_numbers(data, cold_mode, runs):
    """The slide file: every metric is {backend: {cold, warm}}, unit in the key; values are medians
    across `runs` samples."""
    def pair(cold, warm, places):
        return {n: {"cold": round(cold[n], places), "warm": round(warm[n], places)}
                for n in IMPL_ORDER if n in cold and n in warm}
    payloads = {}
    for pay, d in data.items():
        c, w = d["phases"].get("COLD", {}), d["phases"].get("WARM", {})
        lay = d["laydown"]
        ex = d["exec"]
        payloads[pay] = {
            "files": d["files"],
            "laydown_ms": pair({n: v["cold"] * 1e3 for n, v in lay.items() if v}, {n: v["warm"] * 1e3 for n, v in lay.items() if v}, 3),
            "exec_ms": pair({n: e["first_ns"] / 1e6 for n, e in ex.items()}, {n: e["p50_ns"] / 1e6 for n, e in ex.items()}, 2),
            "ops_us": {op: pair(op_p50_us(c, op), op_p50_us(w, op), 1) for op in OPS},
            "e2e_ms": {
                "work_total": pair({n: work_total_ms(c[n]) for n in c}, {n: work_total_ms(w[n]) for n in w}, 1),
                "find": pair({n: c[n]["find_s"] * 1e3 for n in c}, {n: w[n]["find_s"] * 1e3 for n in w}, 1),
                "grep": pair({n: c[n]["grep_s"] * 1e3 for n in c}, {n: w[n]["grep_s"] * 1e3 for n in w}, 1),
            },
        }
    out = {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "machine": machine(),
        "cold": cold_mode,
        "runs": runs,
        "backends": IMPL_ORDER,
        "labels": LABELS,
        "fskit_mount_ms": round(FSKIT["mount_s"] * 1e3, 1) if FSKIT.get("mount_s") else None,
        "payloads": payloads,
    }
    with open(NUMBERS, "w") as f:
        json.dump(out, f, indent=1)
    print(f"wrote {NUMBERS}", file=sys.stderr)
    return out


def write_html(numbers):
    html = open(CHART).read().replace("__DATA__", json.dumps(numbers, separators=(",", ":")), 1)
    out = os.path.join(HERE, "index.html")
    with open(out, "w") as f:
        f.write(html)
    print(f"wrote {out}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--keep", action="store_true", help="keep laid-down trees")
    ap.add_argument("--no-cold", action="store_true", help="never purge; cold = first touch after laydown")
    ap.add_argument("--run", type=int, help="sample number: write results.<N>.json instead of results.json")
    ap.add_argument("--aggregate", action="store_true", help="median every results*.json into numbers.json + index.html")
    ap.add_argument("--render-only", action="store_true", help="rebuild numbers.json + index.html from results.json")
    args = ap.parse_args()

    if args.aggregate or args.render_only:
        files = sorted(glob.glob(os.path.join(HERE, "results*.json"))) if args.aggregate else [RESULTS]
        runs = [json.load(open(f)) for f in files]
        FSKIT["mount_s"] = statistics.median(r["fskit_mount_s"] for r in runs)
        data = median_merge([r["data"] for r in runs])
        write_html(write_numbers(data, runs[-1]["cold"], len(runs)))
        return

    build()
    os.makedirs(INPUT, exist_ok=True)
    for pay in PAYLOADS:
        src = os.path.join(INPUT, pay)
        if not os.path.isdir(src):
            print(f"generating {pay} ...", file=sys.stderr)
            run([BIN, "gen", src, pay, str(args.seed)])
        for impl in IMPL_ORDER:
            build_tool(os.path.join(src, tool_name(impl)), abs(hash((pay, impl, NONCE))) % (2 ** 31))

    purge_ok = (not args.no_cold) and purge()
    cold_mode = "sudo purge before every cold pass" if purge_ok else "first touch after laydown (no purge)"
    print(f"cold = {cold_mode}", file=sys.stderr)

    shutil.rmtree(WORK, ignore_errors=True)
    skipped = {}
    if not os.path.exists(STAGE):
        skipped["fskit"] = "no stage binary"
    data = {}
    for pay in PAYLOADS:
        src = os.path.join(INPUT, pay)
        files = sum(len(f) for _, _, f in os.walk(src))
        laydown, execr, cold_res, warm_res = {}, {}, {}, {}
        for impl in IMPL_ORDER:
            if impl in skipped:
                continue
            dst = os.path.join(WORK, pay, impl)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            try:
                root, cold_s, warm_s = LAY[impl](src, dst)
            except Exception as e:
                skipped[impl] = "stale appex" if impl == "fskit" else "unavailable"
                print(f"skip {impl}: {e}", file=sys.stderr)
                continue
            laydown[impl] = {"cold": cold_s, "warm": warm_s}
            # Cold straight after laydown, before anything else touches the tree; the exec first
            # launch is a separate cold (a fresh cdhash) and stays so after the read pass.
            if purge_ok:
                purge()
            cold_res[impl] = measure_io(root)
            if purge_ok:
                purge()
            execr[impl] = measure_exec(root, impl)
            warmup(root)
            warm_res[impl] = measure_io(root)
            if impl == "fskit":
                fskit_unmount()
        phases = {"COLD": cold_res, "WARM": warm_res}
        data[pay] = {"files": files, "laydown": laydown, "exec": execr, "phases": phases}
        report(pay, files, laydown, execr, phases)

    out = os.path.join(HERE, f"results.{args.run}.json") if args.run else RESULTS
    with open(out, "w") as f:
        json.dump({"data": data, "skipped": skipped, "cold": cold_mode, "fskit_mount_s": FSKIT.get("mount_s")}, f)
    print(f"wrote {out}", file=sys.stderr)
    write_html(write_numbers(data, cold_mode, 1))
    if not args.keep:
        shutil.rmtree(WORK, ignore_errors=True)


if __name__ == "__main__":
    main()
