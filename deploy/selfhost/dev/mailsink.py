"""LOCAL TRIAL ONLY: answers Nexus's Resend calls and prints each mail's
recipient, subject and links to stdout instead of sending anything.
Reached as https://api.resend.com only inside compose.dev.yaml."""
import http.server, json, os, re, ssl, sys

# Refuse to stand in for Resend anywhere but the local trial origin.
if os.environ.get("DEV_BASE_URL") != "https://nexus.localtest":
    print("mailsink: refusing to start: BASE_URL in .env must be https://nexus.localtest for the dev overlay", file=sys.stderr, flush=True)
    sys.exit(2)

class Sink(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        try:
            mail = json.loads(body)
            links = sorted(set(re.findall(r"https://[^\s\"'<>]+", mail.get("text", ""))))
            print(json.dumps({"to": mail.get("to"), "subject": mail.get("subject"), "links": links}, ensure_ascii=False), flush=True)
        except ValueError:
            print("mailsink: unreadable body", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"id":"dev-mailsink"}')

    def log_message(self, *args):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/api.resend.com.crt", "/certs/api.resend.com.key")
srv = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Sink)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("mailsink: listening", file=sys.stderr, flush=True)
srv.serve_forever()
