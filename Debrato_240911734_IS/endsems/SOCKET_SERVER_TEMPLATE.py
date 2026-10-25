"""Run this file FIRST. Then run SOCKET_CLIENT_TEMPLATE.py in another terminal.
Replace handle() with the server operations your question needs.
Uses built-in modules only. Plain TCP: this example does not encrypt the channel.
"""
import hashlib
import json
import socket
import struct
import sys

HOST = '127.0.0.1'
PORT = 5000


def receive_exact(connection, count):
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise ConnectionError('Connection closed before the message finished')
        data.extend(chunk)
    return bytes(data)


def receive(connection):
    size = struct.unpack('!I', receive_exact(connection, 4))[0]
    if not 0 < size <= 1024 * 1024:
        raise ValueError('Message must be between 1 byte and 1 MiB')
    return json.loads(receive_exact(connection, size))


def send(connection, message):
    data = json.dumps(message).encode()
    connection.sendall(struct.pack('!I', len(data)) + data)


def handle(request):
    # PASTE YOUR SERVER LAB CODE HERE. Input arrives in request.
    if not isinstance(request, dict) or request.get('action') != 'hash':
        raise ValueError('Unknown action')
    message = request['message']
    if not isinstance(message, str):
        raise ValueError('Message must be text')
    return {'ok': True, 'sha256': hashlib.sha256(message.encode()).hexdigest()}


def main(port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, port))
        server.listen()
        print(f'Server ready on {HOST}:{port}', flush=True)
        while True:
            connection, address = server.accept()
            with connection:
                connection.settimeout(15)
                try:
                    response = handle(receive(connection))
                except (ValueError, KeyError, TypeError, OSError) as error:
                    response = {'ok': False, 'error': str(error)}
                try:
                    send(connection, response)
                except OSError:
                    pass


if __name__ == '__main__':
    try:
        main(int(sys.argv[1]) if len(sys.argv) > 1 else PORT)
    except (EOFError, KeyboardInterrupt):
        print('\nServer stopped')
    except (ValueError, OSError) as error:
        print('Server error:', error)
