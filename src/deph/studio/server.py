"""http.server for the dashboard. No framework, no state.

The page is rebuilt from the .deph file on every request, so edit the file and
hit refresh.
"""

import html
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import parser
from . import build_html


def _error_page(exc: parser.DephSyntaxError) -> str:
    # The message quotes the offending token, which came from the file, so it
    # has to be escaped before it goes anywhere near the response.
    return ("<h1>deph: parse error</h1><pre>%s</pre>"
            "<p>Fix the file and refresh.</p>" % html.escape(str(exc)))


def _make_handler(deph_path: str):
    class StudioHandler(BaseHTTPRequestHandler):
        server_version = "deph-studio"

        def do_GET(self):
            if self.path.split("?", 1)[0] not in ("/", "/index.html"):
                self.send_error(404, "deph studio serves only /")
                return
            csp = None
            try:
                doc = parser.parse_file(deph_path)
                body = build_html(doc).encode("utf-8")
                status = 200
            except parser.DephSyntaxError as e:
                body = _error_page(e).encode("utf-8")
                status = 500
                csp = "default-src 'none'"
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if csp:
                self.send_header("Content-Security-Policy", csp)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    return StudioHandler


def serve(deph_path: str, port: int = 5397, open_browser: bool = True) -> int:
    handler = _make_handler(deph_path)
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError as e:
        print("deph studio: cannot bind 127.0.0.1:%d (%s)" % (port, e))
        return 1
    url = "http://127.0.0.1:%d/" % port
    print("deph studio serving %s at %s (Ctrl-C to stop)" % (deph_path, url))
    if open_browser:
        threading.Timer(0.3, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\ndeph studio: stopped")
    finally:
        httpd.server_close()
    return 0
