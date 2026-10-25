"""Reproduce source inventory and Markdown syntax counts without executing archives.

Run from endsems: python audit/audit_material.py
Output: audit/INVENTORY.json. Uses only the standard library.
"""
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
BLOCK = re.compile(r'```python[^\n]*\n(.*?)```', re.S)


def main():
    paths = [p for p in ROOT.rglob('*') if p.is_file()
             and not any(part.startswith('.') or part == '__pycache__' for part in p.relative_to(ROOT).parts)
             and p.suffix in ('.py', '.md')]
    paths += list((ROOT.parent / 'IS').glob('*.pdf')) + list((ROOT.parent / 'IS').glob('*.docx'))
    inventory, active_errors, archive_blocks, archive_errors = [], [], 0, 0
    for p in sorted(paths):
        raw = p.read_bytes()
        relative = p.relative_to(ROOT).as_posix() if ROOT in p.parents else '../IS/' + p.name
        row = {'path': relative, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        archived = relative.startswith('archive/')
        if p.suffix in ('.md', '.py'):
            source = raw.decode('utf-8-sig')
            pieces = list(BLOCK.finditer(source)) if p.suffix == '.md' else []
            errors = []
            for i, block in enumerate(pieces, 1):
                try:
                    ast.parse(block.group(1))
                except SyntaxError as e:
                    errors.append({'block': i, 'line': source[:block.start(1)].count('\n') + 1,
                                   'error': str(e)})
            if p.suffix == '.py':
                try:
                    ast.parse(source)
                except SyntaxError as e:
                    errors.append({'line': e.lineno, 'error': str(e)})
            row.update(python_blocks=len(pieces), syntax_errors=errors)
            if archived:
                archive_blocks += len(pieces)
                archive_errors += len(errors)
            elif errors:
                active_errors.append(relative)
        inventory.append(row)
    report = {'files': inventory, 'archive_python_blocks': archive_blocks,
              'archive_syntax_failures': archive_errors, 'active_syntax_error_files': active_errors}
    (ROOT/'audit'/'INVENTORY.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(f'{len(inventory)} files; archive {archive_errors}/{archive_blocks} Python blocks fail syntax')
    print('Active syntax errors:', active_errors)
    if active_errors:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
