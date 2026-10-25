# hash_server.py
import hashlib, socket, struct

def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        part = conn.recv(n - len(buf))
        if not part: raise ConnectionError('closed')
        buf += part
    return buf

port = int(input('Port: '))
with socket.socket() as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port)); srv.listen()
    print('[server] listening on', port)
    while True:
        conn, addr = srv.accept()
        with conn:
            try:
                while True:
                    (n,) = struct.unpack('>I', recv_exact(conn, 4))
                    data = recv_exact(conn, n)
                    digest = hashlib.sha256(data).hexdigest()
                    print(f'[server] {n} bytes from {addr} -> {digest}')
                    conn.sendall(digest.encode())
            except ConnectionError:
                pass                                 # client finished
