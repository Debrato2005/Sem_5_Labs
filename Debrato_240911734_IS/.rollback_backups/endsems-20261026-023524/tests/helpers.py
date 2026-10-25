"""Test helpers: run a menu program with scripted stdin and capture output."""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def run(script, lines, *args, timeout=300, cwd=None):
    """Run `script` (path relative to endsems/) feeding `lines` to stdin."""
    p = subprocess.run([PY, str(ROOT / script), *map(str, args)],  # absolute paths also work
                       input='\n'.join(lines) + '\n', capture_output=True, text=True,
                       timeout=timeout, cwd=cwd or ROOT,
                       env={**os.environ, 'PYTHONIOENCODING': 'utf-8', 'PYTHONPATH': str(ROOT)})
    return p.stdout + p.stderr


class TempDir:
    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix='istest_')
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]
