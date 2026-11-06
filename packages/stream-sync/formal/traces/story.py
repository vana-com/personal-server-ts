"""Print a TLC counterexample of StreamSync.tla as one line per step.

Usage: python3 story.py trace.json
where trace.json comes from `tlc2.TLC ... -dumpTrace json trace.json`.

Columns: step, action, control chain per connection (A = active row,
T = tombstone), stream heads (version:generation[lines]; C marks
complete), each device's outbox entry, checkpoints.  A line is
pk@origin+run, e.g. x1@run3; seed lines show as x1@seed.
"""
import json
import sys


def ctl(st):
    out = []
    for n, rows in st["ctl"].items():
        name = n or '""'
        out.append(f"{name}:" + ("".join(r["k"] for r in rows) or "-"))
    return " ".join(out)


def line(l):
    pk, rid, _acct, origin = l
    return f"{pk}@{origin}" if origin != "run" else f"{pk}@run{rid}"


def heads(st):
    out = []
    for n, streams in st["hd"].items():
        for s, rows in streams.items():
            for i, h in enumerate(rows, 1):
                ls = ",".join(sorted(line(l) for l in h["lines"]))
                out.append(f"{s}v{i}:g{h['g']}[{ls}]{'C' if h['complete'] else ''}")
    return " ".join(out) or "-"


def entry(e):
    if e["rid"] == 0:
        return "-"
    sts = " ".join(
        f"{s}={e['st'][s]}" + (f"@g{e['g'][s]}" if e["g"][s] else "")
        for s in e["st"]
        if e["st"][s] != "none"
    )
    flags = ("uc " if e["uc"] else "") + ("full" if e["full"] else "incr")
    return f"run{e['rid']} {flags} pks={'+'.join(sorted(e['pks']))} {sts}"


def ckpts(st):
    out = [
        f"{d}:{c['n']}/g{c['g']}/run{c['rid']}"
        for d, c in st["ckpt"].items()
        if c["n"] != "none"
    ]
    return " ".join(out) or "-"


def main():
    trace = json.load(open(sys.argv[1]))["counterexample"]
    print("step | action | control | heads | entries | checkpoints")
    for (_, _), act, (j, st) in trace["action"]:
        args = ",".join(str(v) for v in act.get("context", {}).values())
        entries = "; ".join(f"{d}: {entry(e)}" for d, e in st["ob"].items())
        print(f"{j} | {act['name']}({args}) | {ctl(st)} | {heads(st)} | {entries} | {ckpts(st)}")


main()
