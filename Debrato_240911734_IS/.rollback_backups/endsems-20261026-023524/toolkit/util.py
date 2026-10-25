"""Shared exam helpers: validated input, menus, JSON persistence, encoding, time,
role login (PBKDF2), RBAC, audit log, tamper demo and hex dump.

Every other toolkit module is independent of this one, so any module can be
copied into an answer on its own.  Standard library only.
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal, DecimalException


# ----------------------------------------------------------------- input ---
def ask(prompt, allow_blank=False):
    """Non-blank string (re-prompts)."""
    while True:
        s = input(prompt).strip()
        if s or allow_blank:
            return s
        print('  ! value cannot be blank')


def ask_int(prompt, lo=None, hi=None):
    """Integer within optional [lo, hi] (re-prompts)."""
    while True:
        s = input(prompt).strip()
        try:
            v = int(s, 0) if s.lower().startswith(('0x', '0b', '0o')) else int(s)
        except ValueError:
            print('  ! enter a whole number')
            continue
        if (lo is not None and v < lo) or (hi is not None and v > hi):
            print(f'  ! must be between {lo} and {hi}')
            continue
        return v


def scale_decimal(value, places=2, max_abs=10**100):
    """Convert at most 100 input digits to a bounded scaled integer, exactly.
    No Decimal context rounding. Reject nonzero digits beyond `places`."""
    if type(places) is not int or not 0 <= places <= 8 or type(max_abs) is not int or max_abs < 1:
        raise ValueError('places must be in 0..8 and max_abs must be a positive integer')
    text = str(value).strip()
    if len(text) > 256 or sum(c.isdigit() for c in text) > 100:
        raise ValueError('number input exceeds 100 digits')
    try:
        d = Decimal(text)
        if not d.is_finite():
            raise ValueError('number must be finite')
        sign, digits, exponent = d.as_tuple()
        digits = ''.join(str(v) for v in digits)
        if not digits.strip('0'):
            return 0
        shift = exponent + places
        if shift < 0:
            if -shift > len(digits) or digits[shift:].strip('0'):
                raise ValueError('too many decimal places')
            digits, shift = digits[:shift], 0
        if len(digits) + shift > len(str(max_abs)):
            raise ValueError('number outside scaled bound')
        scaled = int(digits or '0') * 10**shift
        if scaled > max_abs:
            raise ValueError('number outside scaled bound')
        return -scaled if sign else scaled
    except DecimalException:
        raise ValueError('invalid decimal number') from None


def ask_amount(prompt, places=2, lo=0):
    """Decimal money -> scaled int (e.g. 12.50 with places=2 -> 1250). No floats."""
    while True:
        s = input(prompt).strip()
        try:
            scaled = scale_decimal(s, places, max_abs=10**(100 + places))
        except ValueError:
            print(f'  ! enter a number with at most {places} decimal places')
            continue
        if scaled < lo:
            print(f'  ! must be >= {fmt_amount(lo, places)}')
            continue
        return int(scaled)


def fmt_amount(scaled, places=2):
    if type(scaled) is not int or type(places) is not int or not 0 <= places <= 8:
        raise ValueError('scaled amount must be an integer and places must be in 0..8')
    sign = '-' if scaled < 0 else ''
    digits = str(abs(scaled)).zfill(places + 1)
    return sign + (digits[:-places] + '.' + digits[-places:] if places else digits)


def ask_choice(prompt, options):
    """Pick one of options (case-insensitive); returns the canonical option."""
    low = {str(o).lower(): o for o in options}
    while True:
        s = input(f'{prompt} {list(options)}: ').strip().lower()
        if s in low:
            return low[s]
        print('  ! choose one of', list(options))


def ask_yes(prompt):
    return input(prompt + ' [y/n]: ').strip().lower() in ('y', 'yes')


def ask_secret(prompt='Password: '):
    """getpass on a real terminal; plain input when stdin is piped (tests/PyCharm)."""
    return getpass.getpass(prompt) if sys.stdin.isatty() else input(prompt)


def parse_bytes(text, sizes=None):
    """User key/IV text -> bytes.  Accepts 'hex:..', plain hex or plain text.
    With `sizes` (allowed byte lengths) the interpretation that fits wins,
    e.g. '0123456789ABCDEF0123456789ABCDEF' for AES-128 is HEX (16 bytes),
    'A1B2C3D4' for DES is TEXT (8 bytes)."""
    text = text.strip()
    if text.lower().startswith('hex:'):
        out = bytes.fromhex(text[4:])
    else:
        try:
            as_hex = bytes.fromhex(text)
        except ValueError:
            as_hex = None
        as_text = text.encode()
        if sizes is None:
            out = as_text
        elif as_hex is not None and len(as_hex) in sizes:
            out = as_hex
        else:
            out = as_text
    if sizes is not None and len(out) not in sizes:
        raise ValueError(f'need {sorted(sizes)} bytes, got {len(out)} '
                         f'(text) / {len(text) // 2 if len(text) % 2 == 0 else "?"} (hex)')
    return out


def ask_bytes(prompt, sizes=None):
    while True:
        try:
            return parse_bytes(input(prompt), sizes)
        except ValueError as e:
            print('  !', e)


def ask_list(prompt, sep=','):
    return [x.strip() for x in input(prompt).split(sep) if x.strip()]


# ------------------------------------------------------------------ menu ---
HANDLED = (ValueError, KeyError, TypeError, IndexError, OverflowError, OSError,
           ArithmeticError, json.JSONDecodeError)


def menu(title, items):
    """items: list of (label, function). Loops until 0. Errors are printed,
    never crash the program.  Returns when the user picks 0."""
    while True:
        print(f'\n=== {title} ===')
        for i, (label, _) in enumerate(items, 1):
            print(f'  {i}. {label}')
        print('  0. Back/Exit')
        c = input('Choice: ').strip()
        if c == '0':
            return
        if not c.isascii() or not c.isdigit() or not 1 <= int(c) <= len(items):
            print('  ! invalid choice')
            continue
        try:
            items[int(c) - 1][1]()
        except HANDLED as e:
            print(f'  ! ERROR: {type(e).__name__}: {e}')


# ----------------------------------------------------------- persistence ---
def load_json(path, default):
    """Return stored JSON or default ONLY for a missing file. Corruption is an error."""
    try:
        with open(path, encoding='utf-8') as f:
            text = f.read()
        return json.loads(text)
    except FileNotFoundError:
        return default


def save_json(path, obj):
    """Atomic replacement of one JSON file. Callers must lock read-modify-write.

    This is not a transaction across several files or a guarantee against power loss.
    """
    path = os.fspath(path)
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=folder,
                                         prefix='.json-', suffix='.tmp', delete=False) as f:
            tmp = f.name
            json.dump(obj, f, indent=2, allow_nan=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)


def canonical(obj):
    """Deterministic bytes of a dict/list: hash/sign THIS, never str(dict)."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


# -------------------------------------------------------------- encoding ---
def b64e(b):
    return base64.b64encode(b).decode()


def b64d(s):
    return base64.b64decode(s, validate=True)


def int_to_bytes(i):
    return i.to_bytes(max(1, (i.bit_length() + 7) // 8), 'big')


def hexdump(data, width=16):
    """Classic hex dump: offset | hex bytes | printable ASCII."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hx = ' '.join(f'{b:02x}' for b in chunk)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{off:08x}  {hx:<{width * 3}} |{asc}|')
    return '\n'.join(lines) or '(empty)'


def tamper_hex(hex_str, index=0):
    """Flip one bit of one byte of a hex string (for tamper demonstrations)."""
    b = bytearray(bytes.fromhex(hex_str))
    b[index % len(b)] ^= 0x01
    return b.hex()


def tamper_b64(b64_str, index=0):
    b = bytearray(b64d(b64_str))
    b[index % len(b)] ^= 0x01
    return b64e(bytes(b))


# ------------------------------------------------------------------ time ---
def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0)


def now_iso():
    return now_utc().isoformat()


def parse_time(text):
    """'2026-10-26 09:30', '2026-10-26T09:30+05:30', '...Z' -> aware UTC datetime.
    A time without offset is taken as LOCAL time."""
    t = datetime.fromisoformat(text.strip().replace('Z', '+00:00'))
    if t.tzinfo is None:
        t = t.astimezone()                     # assume local zone
    return t.astimezone(timezone.utc)


def ask_time(prompt):
    while True:
        try:
            return parse_time(input(prompt + ' (YYYY-MM-DD HH:MM[+05:30]): '))
        except ValueError as e:
            print('  !', e)


def hour_buckets(start, end, limit=24 * 366):
    """All 'YYYY-MM-DDTHH' hour labels covering [start, end] (for range search)."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError('use timezone-aware times')
    start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    if start > end:
        raise ValueError('start must not be after end')
    t = start.replace(minute=0, second=0, microsecond=0)
    out = []
    while t <= end:
        out.append(t.strftime('%Y-%m-%dT%H'))
        t += timedelta(hours=1)
        if len(out) > limit:
            raise ValueError('time range too large')
    return out


# ----------------------------------------------------- passwords + RBAC ---
def hash_password(password, salt=None, rounds=200_000):
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds)
    return {'salt': salt.hex(), 'hash': dk.hex(), 'rounds': rounds}


def check_password(record, password):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(),
                             bytes.fromhex(record['salt']), record['rounds'])
    return hmac.compare_digest(dk.hex(), record['hash'])


def setup_passwords(roles):
    """Ask a password for each role once; returns {role: hash-record}."""
    out = {}
    for r in roles:
        while True:
            pw = ask_secret(f'Set password for {r}: ')
            if pw:
                break
            print('  ! blank password not allowed')
        out[r] = hash_password(pw)
    return out


def login(passwords, role, attempts=3):
    for _ in range(attempts):
        if check_password(passwords[role], ask_secret(f'{role} password: ')):
            return True
        print('  ! wrong password')
    return False


def allowed(permissions, role, action):
    """RBAC: Access(user, obj) = exists role with HasRole and CanAccess."""
    return action in permissions.get(role, ())


def require(permissions, role, action):
    if not allowed(permissions, role, action):
        raise PermissionError(f'{role} may not {action}')


class AuditLog:
    """JSON-lines event log. File owners can edit/delete it. It is not tamper-evident."""

    def __init__(self, path):
        self.path = path

    def log(self, actor, action, detail=''):
        with open(self.path, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'time': now_iso(), 'actor': actor,
                                'action': action, 'detail': detail}) + '\n')

    def show(self):
        try:
            with open(self.path, encoding='utf-8') as f:
                print(f.read() or '(empty log)')
        except FileNotFoundError:
            print('(empty log)')
