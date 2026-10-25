"""Networking for client/server questions: length-prefixed JSON over TCP
sockets and a tiny JSON HTTP API (server + client).  Standard library only.

TCP framing: 4-byte big-endian length + UTF-8 JSON.  (Plain sock.recv(1024)
can split or merge messages - framing fixes the 'multipart message' problem.)
"""
import json
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_MESSAGE = 64 * 1024 * 1024


# ===================================================================== TCP ==
def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    if len(data) > MAX_MESSAGE:
        raise ValueError('message too large')
    sock.sendall(struct.pack('>I', len(data)) + data)


def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('peer closed connection')
        buf += chunk
    return buf


def recv_msg(sock):
    (n,) = struct.unpack('>I', _recv_exact(sock, 4))
    if n > MAX_MESSAGE:
        raise ValueError('message too large')
    obj = json.loads(_recv_exact(sock, n))
    if not isinstance(obj, dict):
        raise ValueError('message must be a JSON object')
    return obj


def serve_tcp(handler, host='127.0.0.1', port=5000, once=False, timeout=30):
    """Run forever (Ctrl+C stops).  handler(request_dict) -> response_dict.
    One client at a time; each connection may send many requests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen()
        print(f'[server] listening on {host}:{port}')
        while True:
            conn, addr = srv.accept()
            print('[server] connection from', addr)
            with conn:
                conn.settimeout(timeout)
                while True:
                    try:
                        req = recv_msg(conn)
                    except (OSError, ValueError):
                        break
                    try:
                        resp = handler(req)
                    except Exception as e:           # report, keep serving
                        resp = {'ok': False, 'error': f'{type(e).__name__}: {e}'}
                    try:
                        send_msg(conn, resp)
                    except (OSError, ValueError):
                        break
            if once:
                return


class TcpClient:
    """Persistent connection: c = TcpClient(host, port); c.call({...})."""

    def __init__(self, host='127.0.0.1', port=5000):
        self.sock = socket.create_connection((host, port), timeout=60)

    def call(self, obj):
        try:
            send_msg(self.sock, obj)
            return recv_msg(self.sock)
        except OSError as e:
            self.close()
            raise ConnectionError(f'connection failed: {e}') from e

    def close(self):
        self.sock.close()


# ==================================================================== HTTP ==
def serve_http(routes, host='127.0.0.1', port=8000, timeout=30):
    """routes: {('GET', '/path'): fn(body_dict, query_dict) -> (status, obj)}.
    Path prefix match: a route '/records/' also receives '/records/42'
    (the remainder is passed as query['_rest'])."""

    class Handler(BaseHTTPRequestHandler):
        def _go(self, method):
            self.connection.settimeout(timeout)
            try:
                url = urllib.parse.urlsplit(self.path)
                path = urllib.parse.unquote(url.path, errors='strict')
                query = dict(urllib.parse.parse_qsl(url.query, keep_blank_values=True,
                                                   max_num_fields=1000))
                fn = routes.get((method, path))
                if fn is None:
                    for (m, p), f in routes.items():
                        if m == method and p.endswith('/') and path.startswith(p):
                            fn, query['_rest'] = f, path[len(p):]
                            break
                if fn is None:
                    status, obj = 404, {'ok': False, 'error': 'no such route'}
                else:
                    lengths = self.headers.get_all('Content-Length', [])
                    if len(lengths) > 1 or self.headers.get('Transfer-Encoding'):
                        raise ValueError('use one Content-Length header without Transfer-Encoding')
                    n = int(lengths[0]) if lengths else 0
                    if n < 0:
                        raise ValueError('Content-Length cannot be negative')
                    if n > MAX_MESSAGE:
                        status, obj = 413, {'ok': False, 'error': 'request body too large'}
                    else:
                        data = self.rfile.read(n)
                        if len(data) != n:
                            raise ValueError('incomplete request body')
                        body = json.loads(data or b'{}')
                        if not isinstance(body, dict):
                            raise ValueError('request body must be a JSON object')
                        status, obj = fn(body, query)
            except TimeoutError:
                status, obj = 408, {'ok': False, 'error': 'request body timed out'}
            except Exception as e:
                status, obj = 400, {'ok': False, 'error': f'{type(e).__name__}: {e}'}
            self.close_connection = True
            data = json.dumps(obj).encode()
            try:
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except OSError:
                pass                            # The client disconnected before the response.

        def do_GET(self):
            self._go('GET')

        def do_POST(self):
            self._go('POST')

        def do_DELETE(self):
            self._go('DELETE')

    srv = ThreadingHTTPServer((host, port), Handler)
    print(f'[api] serving on http://{host}:{port}')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def http_json(method, url, obj=None, timeout=60):
    """-> (status, response_dict).  Never raises on HTTP 4xx/5xx."""
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b'{}')
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')
