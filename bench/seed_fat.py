"""Seeds N documents with a realistic fat _source (~1.3 KB) into index bench-fat. stdlib only.
Usage: python3 seed_fat.py http://127.0.0.1:19200 400000"""
import json, random, sys, urllib.request
from datetime import datetime, timedelta, timezone

es, n = sys.argv[1].rstrip('/'), int(sys.argv[2])
rnd = random.Random(7)
start = datetime(2026, 9, 1, tzinfo=timezone.utc)
users = [f'user{i}' for i in range(200)]
agents = ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'] * 3
def req(path, body, ctype='application/json'):
    r = urllib.request.Request(es + path, data=body, headers={'Content-Type': ctype}, method='PUT' if path.startswith('/bench-fat') and '_bulk' not in path else 'POST')
    return json.load(urllib.request.urlopen(r))
try:
    urllib.request.urlopen(urllib.request.Request(es + '/bench-fat', method='DELETE'))
except Exception:
    pass
req('/bench-fat', json.dumps({'settings': {'number_of_shards': 1, 'number_of_replicas': 0, 'refresh_interval': '-1'}}).encode())
batch = []
for i in range(n):
    ts = start + timedelta(seconds=i * 0.65)
    doc = {
        '@timestamp': ts.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        'user': {'name': rnd.choice(users), 'id': rnd.randint(1, 10**6), 'roles': ['a', 'b', 'c']},
        'source': {'ip': f'10.{rnd.randint(0,255)}.{rnd.randint(0,255)}.{rnd.randint(1,254)}', 'port': rnd.randint(1024, 65535), 'geo': {'country': 'FR', 'city': 'Paris', 'lat': 48.85, 'lon': 2.35}},
        'destination': {'ip': f'192.168.{rnd.randint(0,255)}.{rnd.randint(1,254)}', 'port': 443},
        'event': {'outcome': 'failure' if rnd.random() < 0.3 else 'success', 'category': 'authentication', 'action': 'logon', 'duration': rnd.random() * 3, 'dataset': 'auth.log', 'module': 'system'},
        'host': {'name': rnd.choice(['web-1', 'web-2', 'db-1']), 'os': {'name': 'Linux', 'version': '6.8', 'kernel': '6.8.0-45-generic'}, 'architecture': 'x86_64'},
        'http': {'request': {'method': 'POST', 'bytes': rnd.randint(100, 5000)}, 'response': {'status_code': rnd.choice([200, 401, 403])}},
        'user_agent': {'original': rnd.choice(agents)},
        'process': {'name': 'sshd', 'pid': rnd.randint(100, 40000), 'command_line': '/usr/sbin/sshd -D -R'},
        'tags': ['auth', 'ssh', 'prod'],
        'message': 'Authentication event for user %s from %s: %s' % (rnd.choice(users), 'x' * 300, 'y' * 300),
    }
    batch.append(json.dumps({'index': {'_id': f'b{i}'}}))
    batch.append(json.dumps(doc))
    if len(batch) >= 10000:
        r = req('/bench-fat/_bulk', ('\n'.join(batch) + '\n').encode(), 'application/x-ndjson'); assert not r['errors']; batch = []
if batch:
    r = req('/bench-fat/_bulk', ('\n'.join(batch) + '\n').encode(), 'application/x-ndjson'); assert not r['errors']
urllib.request.urlopen(urllib.request.Request(es + '/bench-fat/_refresh', method='POST'))
print('seeded', n)
