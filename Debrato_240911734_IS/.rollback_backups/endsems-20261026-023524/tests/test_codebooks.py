"""Every ```python block in codebooks/*.md and README.md is compiled; blocks are
also EXECUTED in a fresh temp folder with the stdin given by the
<!-- stdin: a | b | c --> marker just above the block.
Markers: <!-- no-run --> (external tools) and <!-- fragment --> (needs variables
from surrounding code) are compiled only.  <!-- server: NAME | stdin... --> starts a
block in the background; the next <!-- client: NAME | stdin... --> runs against it.
{PORT} in stdin is replaced by a free port shared by the pair."""
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.helpers import PY, ROOT, free_port  # noqa: E402

BLOCK = re.compile(r'(?:<!--\s*((?:stdin|server|client):[^>]*?|no-run|fragment)\s*-->\s*\n)?'
                   r'```python\n(.*?)```', re.S)
ENV = {**os.environ, 'PYTHONPATH': str(ROOT), 'PYTHONIOENCODING': 'utf-8'}


def blocks():
    files = sorted((ROOT / 'codebooks').glob('*.md')) + [ROOT / 'README.md', ROOT / 'PLUGPLAY.md']
    for f in files:
        if not f.exists():
            continue
        text = f.read_text(encoding='utf-8')
        for m in BLOCK.finditer(text):
            line = text[:m.start(2)].count('\n') + 1
            yield f.name, line, (m.group(1) or '').strip(), m.group(2)


def _stdin(values, port):
    return '\n'.join(v.strip().replace('{PORT}', str(port)) for v in values) + '\n'


def _write(d, code):
    path = os.path.join(d, 'block.py')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(code)
    return path


def _start_server(code, values):
    port = free_port()
    d = tempfile.mkdtemp()
    proc = subprocess.Popen([PY, _write(d, code)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, cwd=d, env=ENV)
    proc.stdin.write(_stdin(values, port))
    proc.stdin.flush()
    for _ in range(100):                     # wait until it accepts connections
        try:
            socket.create_connection(('127.0.0.1', port), 1).close()
            break
        except OSError:
            time.sleep(0.1)
    return proc, port


class Codebooks(unittest.TestCase):
    def test_blocks(self):
        count, servers = 0, {}
        try:
            for name, line, marker, code in blocks():
                count += 1
                with self.subTest(f'{name}:{line}'):
                    compile(code, f'{name}:{line}', 'exec')
                    if marker in ('no-run', 'fragment'):
                        continue
                    kind, _, rest = marker.partition(':')
                    parts = rest.split('|') if rest.strip() else []
                    if kind == 'server':
                        servers[parts[0].strip()] = _start_server(code, parts[1:])
                        continue
                    proc, port = None, 0
                    if kind == 'client':
                        proc, port = servers.pop(parts[0].strip())
                        parts = parts[1:]
                    with tempfile.TemporaryDirectory() as d:
                        p = subprocess.run([PY, _write(d, code)], input=_stdin(parts, port),
                                           capture_output=True, text=True, cwd=d, timeout=180, env=ENV)
                    out = p.stdout + p.stderr
                    if proc:
                        proc.kill()
                        out += '\n[server output]\n' + proc.communicate()[0]
                    self.assertEqual(p.returncode, 0, f'{name}:{line}\n{out[-1500:]}')
                    self.assertNotIn('Traceback', out, f'{name}:{line}\n{out[-1500:]}')
        finally:
            for proc, _ in servers.values():
                proc.kill()
                proc.communicate()
        self.assertGreater(count, 0)


if __name__ == '__main__':
    unittest.main()
