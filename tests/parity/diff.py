"""Compares the alerts two `--debug` logs contain (order-insensitive).
Usage: python3 diff.py py.log rs.log [skip-text]"""
import difflib, re, sys

def alerts(path):
    records, cur = [], None
    for line in open(path, encoding='utf-8'):
        m = re.match(r'^(INFO|WARNING|ERROR|DEBUG|CRITICAL):[\w.]+:(.*)', line)
        if m:
            cur = [m.group(2) + '\n']
            records.append(cur)
        elif cur is not None:
            cur.append(line)
    out = []
    for i, r in enumerate(records):
        if r[0].startswith('Alert for ') and i + 1 < len(records):
            out.append(''.join(r) + ''.join(records[i + 1]).rstrip('\n') + '\n')
    return sorted(out)

skip = sys.argv[3] if len(sys.argv) > 3 else None  # optional: ignore alerts whose text contains this
a, b = (list(filter(lambda x: not skip or skip not in x, alerts(f))) for f in sys.argv[1:3])
print(f'{sys.argv[1]}: {len(a)} alerts, {sys.argv[2]}: {len(b)} alerts')
diff = list(difflib.unified_diff(''.join(a).splitlines(), ''.join(b).splitlines(), sys.argv[1], sys.argv[2], lineterm='', n=2))
print('\n'.join(diff[:200]) if diff else 'IDENTICAL')
sys.exit(1 if diff else 0)
