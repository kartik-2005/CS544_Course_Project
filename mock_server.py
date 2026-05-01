import http.server
import socketserver
import os

PORT = 8080
SITES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sites")

# FIX: Session-level target. Every site visit must total exactly this many
# bytes transferred, regardless of how many files it has.
# Set this above the largest possible session: site5 = 10 real files.
# 10 files * largest possible file (~2MB) = ~20MB. Use 30MB as ceiling.
SESSION_TARGET_BYTES = 30 * 1024 * 1024  # 30 MB

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        rel_path = self.path.lstrip('/')

        # Special padding endpoint: client calls this at end of every session
        # with ?need=<bytes> to top up to SESSION_TARGET_BYTES
        if rel_path.startswith("__pad__"):
            try:
                need = int(self.path.split("need=")[1])
            except:
                need = 0
            need = max(0, need)
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-length", str(need))
            self.end_headers()
            # Send in chunks to avoid allocating huge buffer
            chunk = b'0' * 65536
            remaining = need
            while remaining > 0:
                to_send = min(len(chunk), remaining)
                self.wfile.write(chunk[:to_send])
                remaining -= to_send
            return

        full_path = os.path.join(SITES_DIR, rel_path)
        if os.path.isfile(full_path):
            with open(full_path, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.send_header("Content-length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "File Not Found")

    def log_message(self, format, *args): return

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Server serving from {SITES_DIR} at port {PORT}")
        httpd.serve_forever()