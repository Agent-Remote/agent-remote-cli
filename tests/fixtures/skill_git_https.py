"""Isolated TLS Git smart-HTTP fixture; never uses a developer's credentials/config."""
import base64
import http.server
import os
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

root, certificate, private_key, port_file = sys.argv[1:]


class GitHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.handle_git()

    def do_POST(self):
        self.handle_git()

    def handle_git(self):
        parsed = urlsplit(self.path)
        if parsed.path.startswith('/redirect.git/'):
            self.send_response(302)
            self.send_header('Location', '/redirect-target')
            self.end_headers()
            return
        if parsed.path == '/redirect-target':
            with open(os.path.join(root, 'redirect-followed'), 'w') as output:
                output.write('followed')
            self.send_error(404)
            return
        expected = 'Basic ' + base64.b64encode(b'fixture:synthetic-password').decode()
        if self.headers.get('Authorization') != expected:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="fixture"')
            self.end_headers()
            return
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1024 * 1024:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        env = dict(os.environ, GIT_PROJECT_ROOT=root, GIT_HTTP_EXPORT_ALL='1',
                   REQUEST_METHOD=self.command, PATH_INFO=parsed.path,
                   QUERY_STRING=parsed.query, CONTENT_TYPE=self.headers.get('Content-Type', ''),
                   CONTENT_LENGTH=str(length), REMOTE_USER='fixture')
        result = subprocess.run(['git', 'http-backend'], input=body, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        headers, sep, payload = result.stdout.partition(b'\r\n\r\n')
        if not sep:
            self.send_error(500)
            return
        status = 200
        pairs = []
        for line in headers.decode().splitlines():
            key, value = line.split(':', 1)
            if key.lower() == 'status':
                status = int(value.strip().split()[0])
            else:
                pairs.append((key, value.strip()))
        self.send_response(status)
        for key, value in pairs:
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), GitHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, private_key)
server.socket = context.wrap_socket(server.socket, server_side=True)
with open(port_file, 'w') as output:
    output.write(str(server.server_address[1]))
server.serve_forever()
