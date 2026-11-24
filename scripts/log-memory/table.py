#!/usr/bin/env python3
"""Print the per-step reports of run.sh cases as a table: table.py <jsonl> ..."""
import json, sys
print(f"{'case':10} {'step':12} {'idle':>6} {'peak':>6} {'above':>6} {'ms':>8}  notes")
for path in sys.argv[1:]:
    case = path.rsplit('/', 1)[-1].removesuffix('.jsonl')
    for line in open(path):
        r = json.loads(line)
        n = {k: v for k, v in r['notes'].items() if k != 'log'}
        print(f"{case:10} {r['step']:12} {r['idleMiB']:6} {r['peakMiB']:6} {r['aboveIdleMiB']:6} {r['ms']:8}  {n}")
