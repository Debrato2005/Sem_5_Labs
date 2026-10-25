"""Make ONE self-contained .py from an answer that imports the toolkit.

    python bundle.py answer.py              -> answer_single.py
    python bundle.py answer.py -o final.py

Supported import form:  from toolkit.<module> import a, b   (also in parentheses)
Lines containing '# TOOLKIT-PATH' (the sys.path bootstrap) are removed.
The needed toolkit modules (and their own toolkit dependencies) are pasted at
the top in dependency order.  Existing output files are never overwritten.
"""
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IMPORT = re.compile(r'^from toolkit\.(\w+) import (\([^)]*\)|[^\n]*)\n?', re.M)


def toolkit_imports(src):
    return [m.group(1) for m in IMPORT.finditer(src)]


def strip(src):
    def aliases(match):
        node = ast.parse(match.group(0)).body[0]
        return ''.join(f'{a.asname} = {a.name}\n' for a in node.names if a.asname)
    src = IMPORT.sub(aliases, src)
    return '\n'.join(l for l in src.splitlines() if '# TOOLKIT-PATH' not in l) + '\n'


def order(modules, seen=None, out=None):
    seen, out = seen if seen is not None else set(), out if out is not None else []
    for m in modules:
        if m in seen:
            continue
        seen.add(m)
        path = ROOT / 'toolkit' / f'{m}.py'
        if not path.exists():
            raise SystemExit(f'unknown toolkit module: {m}')
        order(toolkit_imports(path.read_text(encoding='utf-8')), seen, out)
        out.append(m)
    return out


def top_names(src):
    names = {}
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names[node.name] = ast.dump(node)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names[t.id] = ast.dump(node.value)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = getattr(node, 'module', None) or ''
            for a in node.names:
                names[a.asname or a.name.split('.')[0]] = f'import {mod}.{a.name}'
    return names


def local_helpers(src, folder, seen=None, helper=False):
    """Inline the small, known plugplay adapters, without running their entry guards."""
    seen = set() if seen is None else seen
    lines, prefix = src.splitlines(keepends=True), []
    for node in ast.parse(src).body:
        main_guard = (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                      and isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__'
                      and len(node.test.comparators) == 1
                      and isinstance(node.test.comparators[0], ast.Constant)
                      and node.test.comparators[0].value == '__main__')
        if helper and main_guard:
            for i in range(node.lineno - 1, node.end_lineno):
                lines[i] = ''
        if isinstance(node, ast.ImportFrom) and node.module in ('config', 'ui', 'menu_app', 'protocol'):
            path = folder / (node.module + '.py')
            if not path.exists():
                raise SystemExit(f'missing local helper: {path}')
            if node.module not in seen:
                seen.add(node.module)
                prefix.append(local_helpers(path.read_text(encoding='utf-8'), folder, seen, True))
            for i in range(node.lineno - 1, node.end_lineno):
                lines[i] = ''
    return '\n'.join(prefix) + '\n' + ''.join(lines)


def bundle(answer_path):
    src = Path(answer_path).read_text(encoding='utf-8')
    folder = Path(answer_path).resolve().parent
    if folder == ROOT / 'templates' / 'plugplay':
        src = local_helpers(src, folder)
    top = ast.parse(src)
    for node in ast.walk(top):
        bad_import = isinstance(node, ast.Import) and any(
            a.name == 'toolkit' or a.name.startswith('toolkit.') for a in node.names)
        toolkit_from = isinstance(node, ast.ImportFrom) and (node.module or '').split('.')[0] == 'toolkit'
        if bad_import or (toolkit_from and (node.module == 'toolkit' or node.col_offset != 0
                                            or any(a.name == '*' for a in node.names))):
            raise SystemExit('use top-level "from toolkit.<module> import name" (aliases supported)')
    mods = order(toolkit_imports(src))
    parts, defined = [], {}
    for m in mods:
        body = strip((ROOT / 'toolkit' / f'{m}.py').read_text(encoding='utf-8'))
        for name, dump in top_names(body).items():
            if name in defined and defined[name][1] != dump:
                print(f'WARNING: {name} defined differently in {defined[name][0]} and {m}')
            defined[name] = (m, dump)
        parts.append(f'# {"=" * 30} toolkit/{m}.py {"=" * 30}\n{body}')
    main = strip(src)
    for name, dump in top_names(main).items():
        if name in defined and defined[name][1] != dump:
            print(f'NOTE: answer redefines toolkit name {name!r} (answer version wins)')
    parts.append(f'# {"=" * 30} answer {"=" * 30}\n{main}')
    out = '\n'.join(parts)
    compile(out, 'bundled', 'exec')               # fail loudly on syntax problems
    return out, mods


def main():
    args = sys.argv[1:]
    if not args or args[0] in ('-h', '--help'):
        print(__doc__)
        return
    src = Path(args[0])
    dst = Path(args[args.index('-o') + 1]) if '-o' in args else src.with_name(src.stem + '_single.py')
    if dst.exists():
        raise SystemExit(f'{dst} exists - choose another name with -o')
    out, mods = bundle(src)
    dst.write_text(out, encoding='utf-8')
    print(f'wrote {dst}  (inlined: {", ".join(mods) or "nothing"})')


if __name__ == '__main__':
    main()
