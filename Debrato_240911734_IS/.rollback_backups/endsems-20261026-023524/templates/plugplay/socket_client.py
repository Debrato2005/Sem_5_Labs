"""CLIENT entry point. Start socket_server.py in a different terminal first.

python templates/plugplay/socket_client.py --port 5000
python templates/plugplay/socket_client.py --http --port 8000
"""
import argparse
import hashlib
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))  # TOOLKIT-PATH

from protocol import ClientProtocol
from ui import run_ui
from toolkit.net import TcpClient, http_json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--http', action='store_true')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=5000)
    args = p.parse_args()
    conn = None
    try:
        if args.http:
            raw = lambda req: http_json('POST', f'http://{args.host}:{args.port}/call', req)[1]
        else:
            conn = TcpClient(args.host, args.port)
            raw = conn.call
        endpoint = f'{args.http}:{args.host}:{args.port}'.encode()
        pin = 'server_' + hashlib.sha256(endpoint).hexdigest()[:16] + '_pin.pem'
        client = ClientProtocol(raw, pin)
        run_ui(client.call, client.config)
    finally:
        if conn is not None:
            conn.close()


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nExit.')
    except (ValueError, KeyError, OSError) as e:
        print('Connection failed:', e)
        sys.exit(1)
