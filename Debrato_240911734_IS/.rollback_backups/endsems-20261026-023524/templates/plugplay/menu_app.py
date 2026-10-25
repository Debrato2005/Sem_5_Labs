"""Standalone menu. Run: python templates/plugplay/menu_app.py [data_folder]."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))  # TOOLKIT-PATH

from config import CONFIG
from ui import run_ui
from toolkit.records import RecordApp
from toolkit.util import ask_secret


def open_app(folder):
    app = RecordApp(folder, CONFIG)
    if app.keys is None:
        print('First run: set a password for each role. Keep this data folder and its keys together.')
        passwords = {}
        for role in CONFIG['roles']:
            while not passwords.get(role):
                passwords[role] = ask_secret(f'Set {role} password: ')
        app.setup(passwords)
    return app


if __name__ == '__main__':
    try:
        run_ui(open_app(sys.argv[1] if len(sys.argv) > 1 else 'plugplay_data').handle, CONFIG)
    except (EOFError, KeyboardInterrupt):
        print('\nExit.')
    except (ValueError, OSError) as e:
        print('Cannot start:', e)
        sys.exit(1)
