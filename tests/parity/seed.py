"""Writes a deterministic auth-log dataset to Elasticsearch (stdlib only).
Usage: python3 seed.py http://127.0.0.1:19200"""
import json, random, sys, urllib.request
from datetime import datetime, timedelta, timezone

es = sys.argv[1].rstrip('/')
rnd = random.Random(42)
start = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)
users = ['alice', 'bob', 'carol', 'dave', 'eve']
lines = []
for i in range(3000):
    ts = start + timedelta(seconds=i * 2.4 + rnd.random())
    user = rnd.choice(users)
    # eve brute-forces between 09:00 and 09:10
    failed = rnd.random() < (0.9 if user == 'eve' and 3600 <= i * 2.4 < 4200 else 0.05)
    doc = {
        '@timestamp': ts.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        'user': {'name': user},
        'source': {'ip': f'10.0.{rnd.randint(0, 3)}.{rnd.randint(1, 254)}'},
        'event': {'outcome': 'failure' if failed else 'success', 'duration': round(rnd.random() * 3, 3)},
        'host': rnd.choice(['web-1', 'web-2', 'db-1']),
        'tags': ['auth', 'ssh'] if i % 2 else ['auth'],
        'admin': user == 'alice',
        'message': f'login {"failed" if failed else "ok"} for {user}',
    }
    for idx in ('logs-parity', 'daily-parity-2026.10.01'):
        lines.append(json.dumps({'index': {'_index': idx, '_id': f'doc-{i}'}}))
        lines.append(json.dumps(doc))
req = urllib.request.Request(es + '/_bulk?refresh=true', data=('\n'.join(lines) + '\n').encode(),
                             headers={'Content-Type': 'application/x-ndjson'})
resp = json.load(urllib.request.urlopen(req))
print('errors:', resp['errors'], 'docs:', len(resp['items']))
