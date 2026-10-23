"""Tiny receivers for alerter tests: HTTP on :19300 (any POST) and SMTP on :19325.
Everything received is appended as one JSON line to the file given as argv[1]."""
import json, socketserver, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

out = open(sys.argv[1], 'a', buffering=1)
lock = threading.Lock()

def record(kind, **kw):
    with lock:
        out.write(json.dumps({'kind': kind, 'at': time.time(), **kw}) + '\n')

class Http(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        try:
            body = json.loads(body)
        except ValueError:
            body = body.decode(errors='replace')
        record('http', method=self.command, path=self.path, headers={k.lower(): v for k, v in self.headers.items()}, body=body)
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    do_PUT = do_POST
    def log_message(self, *a): pass

class Smtp(socketserver.StreamRequestHandler):
    def reply(self, line): self.wfile.write((line + '\r\n').encode())
    def handle(self):
        self.reply('220 sink ESMTP')
        msg = {'rcpt': []}
        while True:
            line = self.rfile.readline().decode(errors='replace').rstrip('\r\n')
            if not line: return
            cmd = line.upper()
            if cmd.startswith('EHLO') or cmd.startswith('HELO'): self.reply('250 sink')
            elif cmd.startswith('MAIL FROM'): msg['from'] = line[10:]; self.reply('250 ok')
            elif cmd.startswith('RCPT TO'): msg['rcpt'].append(line[8:]); self.reply('250 ok')
            elif cmd == 'DATA':
                self.reply('354 go')
                data = []
                while True:
                    l = self.rfile.readline().decode(errors='replace')
                    if l.rstrip('\r\n') == '.': break
                    data.append(l)
                record('smtp', **msg, data=''.join(data)); self.reply('250 queued')
            elif cmd == 'QUIT': self.reply('221 bye'); return
            else: self.reply('250 ok')

class S(socketserver.ThreadingTCPServer): allow_reuse_address = True; daemon_threads = True
threading.Thread(target=S(('127.0.0.1', 19325), Smtp).serve_forever, daemon=True).start()
HTTPServer(('127.0.0.1', 19300), Http).serve_forever()
