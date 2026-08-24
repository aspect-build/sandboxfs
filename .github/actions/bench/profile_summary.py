#!/usr/bin/env python3
"""Turn a Bazel JSON trace profile into a step-summary breakdown.

    profile_summary.py PROFILE SANDBOX RUN ELAPSED_S RESULT_JSON

Writes RESULT_JSON ({sandbox, run, elapsed_s, phases, categories}) and prints a
Markdown breakdown to stdout for $GITHUB_STEP_SUMMARY. Phase wall time comes from
the "build phase marker" events; the category table sums event durations across
threads (so it exceeds wall time under parallelism).
"""
import gzip, json, sys, collections

SKIP_CATS = {"build phase marker", "critical path component"}


def load(path):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rb") as f:
        return json.load(f)


def phases(events):
    marks = sorted(
        ((e["ts"], e["name"]) for e in events if e.get("cat") == "build phase marker"),
        key=lambda m: m[0],
    )
    out = {}
    for (ts, name), (nxt, _) in zip(marks, marks[1:]):
        out[name] = (nxt - ts) / 1e6
    return out


def categories(events):
    tot = collections.Counter()
    for e in events:
        if e.get("ph") == "X" and "dur" in e and e.get("cat") not in SKIP_CATS:
            tot[e["cat"]] += e["dur"]
    return {c: v / 1e6 for c, v in tot.most_common()}


def main():
    prof, sandbox, run, elapsed, out = sys.argv[1:6]
    events = load(prof)["traceEvents"]
    ph, cat = phases(events), categories(events)
    json.dump(
        {"sandbox": sandbox, "run": run, "elapsed_s": float(elapsed), "phases": ph, "categories": cat},
        open(out, "w"),
    )

    p = print
    p(f"### Profile — {sandbox} · run {run}\n")
    p(f"**Elapsed:** {float(elapsed):.3f}s\n")
    p("| phase | wall (s) |")
    p("|---|--:|")
    for name, s in ph.items():
        p(f"| {name} | {s:.3f} |")
    total = sum(cat.values()) or 1.0
    p("\n| category (thread-time) | s | % |")
    p("|---|--:|--:|")
    for name, s in list(cat.items())[:12]:
        p(f"| {name} | {s:.3f} | {s / total * 100:.1f} |")
    p("")


if __name__ == "__main__":
    main()
