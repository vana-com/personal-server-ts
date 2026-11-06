import json, sys
d = json.load(open(sys.argv[1]))
ce = d["counterexample"]
states = {s[0]: s[1] for s in ce["state"]}
acts = ce["action"]
def heads(st):
    out = []
    for n, ss in st["srow"].items():
        for s, rows in ss.items():
            for i, h in enumerate(rows, 1):
                ls = ",".join(f"k{l[1]}@run{l[2]}" for l in h["lines"])
                out.append(f"{s}v{i}:g{h['g']}[{ls}]{'C' if h['complete'] else ''}")
    return " ".join(out) or "-"
def entry(st, dev):
    e = st["ob"][dev]
    if e["rid"] == 0: return "-"
    sts = " ".join(f"{s}={e['st'][s]}@g{e['g'][s]}" for s in e["st"] if e["st"][s] != "none")
    return f"run{e['rid']} bound={e['bound']} uc={e['uc']} full={e['full']} {sts}"
print(f"{'#':>2} {'action':<22} ctl        | heads | d2 entry | checkpoints | commits")
prev = 1
for a in acts:
    (i, _), act, (j, st) = a[0], a[1], a[2]
    name = act["name"]; ctx = act.get("context", {})
    args = ",".join(str(v) for v in ctx.values())
    ctl = "".join(st["ctl"]["n1"]) or "absent"
    chk = " ".join(f"{k}:{v['n']}/g{v['g']}/run{v['rid']}/{'+'.join(v['streams'])}" for k, v in st["chk"].items() if v["n"] != "none") or "-"
    com = " ".join(f"({c[1]},g{c[2]},run{c[3]})" for c in st["commits"]) or "-"
    print(f"{j:>2} {name+'('+args+')':<22} {ctl:<10} | {heads(st)} | {entry(st,'d2')} | {chk} | {com}")
