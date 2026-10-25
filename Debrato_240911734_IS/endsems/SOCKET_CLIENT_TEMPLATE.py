"""Run AFTER SOCKET_SERVER_TEMPLATE.py. Both files run separately.
Replace lab_operation() with client input/encryption needed by your question.
Uses built-in modules only. Plain TCP: this example does not encrypt the channel.
"""
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


def call_server(request, port=PORT):
    with socket.create_connection((HOST, port), timeout=15) as connection:
        data = json.dumps(request).encode()
        if len(data) > 1024 * 1024:
            raise ValueError('Message exceeds 1 MiB')
        connection.sendall(struct.pack('!I', len(data)) + data)
        size = struct.unpack('!I', receive_exact(connection, 4))[0]
        if not 0 < size <= 1024 * 1024:
            raise ValueError('Invalid response length')
        return json.loads(receive_exact(connection, size))


def lab_operation(port):
    # PASTE YOUR CLIENT LAB CODE HERE. Send its result as a JSON dictionary.
    message = input('Message: ')
    result = call_server({'action': 'hash', 'message': message}, port)
    print('Server result:', result)


def main(port=PORT):
    while True:
        print('\n1. Run lab operation\n0. Exit')
        choice = input('Choice: ').strip()
        if choice == '0':
            return
        if choice == '1':
            try:
                lab_operation(port)
            except (ValueError, OSError) as error:
                print('Error:', error)
        else:
            print('Invalid choice')


if __name__ == '__main__':
    try:
        main(int(sys.argv[1]) if len(sys.argv) > 1 else PORT)
    except (EOFError, KeyboardInterrupt):
        print('\nExit')
