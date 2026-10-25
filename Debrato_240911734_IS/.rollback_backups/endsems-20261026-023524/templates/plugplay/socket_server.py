"""SERVER entry point. Same app for TCP (default) or HTTP (--http).

python templates/plugplay/socket_server.py --port 5000 --data plugplay_data
python templates/plugplay/socket_server.py --http --port 8000 --data plugplay_data
"""
import argparse
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))  # TOOLKIT-PATH

from menu_app import open_app
from protocol import ServerProtocol
from toolkit.net import serve_http, serve_tcp


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--http', action='store_true')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=5000)
    p.add_argument('--data', default='plugplay_data')
    args = p.parse_args()
    handler = ServerProtocol(open_app(args.data)).handle
    if args.http:
        serve_http({('POST', '/call'): lambda body, query: (200, handler(body))}, args.host, args.port)
    else:
        serve_tcp(handler, args.host, args.port)


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nServer stopped.')
    except (ValueError, OSError) as e:
        print('Cannot start:', e)
        sys.exit(1)
