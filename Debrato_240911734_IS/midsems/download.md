python -m pip install --upgrade pip \&\& python -m pip install pycryptodome cryptography numpy sympy matplotlib ecdsa coincurve flask psutil



\########################################################################################################################################################################################################



from Crypto.Cipher import AES, DES, DES3, PKCS1\_OAEP

from Crypto.PublicKey import RSA, ECC, ElGamal

from Crypto.Hash import SHA256

from Crypto.Signature import pkcs1\_15

from Crypto.Util.Padding import pad, unpad

from Crypto.Random import get\_random\_bytes

from Crypto.Util.number import getPrime, inverse



import hashlib      # MD5, SHA1, SHA256

import socket       # client/server

import secrets      # secure randomness

import random

import time

import math          # gcd

import os

import base64

import logging

import json

import sqlite3



\########################################################################################################################################################################################################



python -m venv .venv

source .venv/bin/activate

python -m pip install --upgrade pip

python -m pip install pycryptodome cryptography numpy sympy matplotlib ecdsa coincurve flask psutil



python -c "from Crypto.Cipher import AES, DES, DES3; from Crypto.PublicKey import RSA, ECC; import cryptography, numpy, sympy, matplotlib, ecdsa, flask, psutil; print('IS LAB ENVIRONMENT READY')"



\########################################################################################################################################################################################################

/set verbose

/set parameter num\_ctx 8192



bash -lc 'set -euo pipefail; ROOT="$HOME/qwen-local"; PORT=11435; rm -rf "$ROOT"; mkdir -p "$ROOT"/{ollama,models}; python3 -m venv "$ROOT/.venv"; source "$ROOT/.venv/bin/activate"; python -m pip install -q --upgrade pip zstandard; case "$(uname -m)" in x86\_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; \*) echo "Unsupported architecture: $(uname -m)"; exit 1;; esac; echo "Downloading Ollama..."; curl -fL "https://ollama.com/download/ollama-linux-${ARCH}.tar.zst" -o "$ROOT/ollama.tar.zst"; python -c "import zstandard as z; i=open('\\''$ROOT/ollama.tar.zst'\\'','\\''rb'\\''); o=open('\\''$ROOT/ollama.tar'\\'','\\''wb'\\''); z.ZstdDecompressor().copy\_stream(i,o); i.close(); o.close()"; tar -xf "$ROOT/ollama.tar" -C "$ROOT/ollama"; rm -f "$ROOT/ollama.tar" "$ROOT/ollama.tar.zst"; export PATH="$ROOT/ollama/bin:$PATH" OLLAMA\_MODELS="$ROOT/models" OLLAMA\_HOST="127.0.0.1:$PORT"; nohup "$ROOT/ollama/bin/ollama" serve >"$ROOT/ollama.log" 2>\&1 \& echo $! >"$ROOT/ollama.pid"; for i in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/api/tags" >/dev/null \&\& break; sleep 1; done; curl -sf "http://127.0.0.1:$PORT/api/tags" >/dev/null || { echo "Ollama failed to start:"; cat "$ROOT/ollama.log"; exit 1; }; ollama pull qwen2.5-coder:7b; ollama run qwen2.5-coder:7b'



bash -lc 'ROOT="$HOME/qwen-local"; if \[ -f "$ROOT/ollama.pid" ]; then PID="$(cat "$ROOT/ollama.pid" 2>/dev/null || true)"; if \[ -n "${PID:-}" ] \&\& kill -0 "$PID" 2>/dev/null; then kill "$PID" 2>/dev/null || true; for i in $(seq 1 10); do kill -0 "$PID" 2>/dev/null || break; sleep 0.2; done; kill -9 "$PID" 2>/dev/null || true; fi; fi; rm -rf "$ROOT"; echo "Removed Ollama, Qwen model, temporary venv, model cache, logs, PID file, archives, and qwen-local directory."'

\########################################################################################################################################################################################################

bash -lc 'set -euo pipefail; ROOT="$HOME/qwen-local"; PORT=11435; curl -sf "http://127.0.0.1:$PORT/api/tags" >/dev/null \&\& { echo "Ollama already running on $PORT"; exit 1; }; rm -rf "$ROOT"; mkdir -p "$ROOT"/{ollama,models,home,cache,config,data}; export HOME="$ROOT/home" XDG\_CACHE\_HOME="$ROOT/cache" XDG\_CONFIG\_HOME="$ROOT/config" XDG\_DATA\_HOME="$ROOT/data"; command -v python3 >/dev/null || { echo "python3 missing"; exit 1; }; command -v curl >/dev/null || { echo "curl missing"; exit 1; }; command -v tar >/dev/null || { echo "tar missing"; exit 1; }; python3 -m venv "$ROOT/.venv"; source "$ROOT/.venv/bin/activate"; python -m pip install -q --no-cache-dir --upgrade pip zstandard; case "$(uname -m)" in x86\_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; \*) echo "Unsupported architecture: $(uname -m)"; exit 1;; esac; echo "Downloading Ollama..."; curl -fL "https://ollama.com/download/ollama-linux-${ARCH}.tar.zst" -o "$ROOT/ollama.tar.zst"; python -c "import zstandard as z; i=open('\\''$ROOT/ollama.tar.zst'\\'','\\''rb'\\''); o=open('\\''$ROOT/ollama.tar'\\'','\\''wb'\\''); z.ZstdDecompressor().copy\_stream(i,o); i.close(); o.close()"; tar -xf "$ROOT/ollama.tar" -C "$ROOT/ollama"; rm -f "$ROOT/ollama.tar" "$ROOT/ollama.tar.zst"; export PATH="$ROOT/ollama/bin:$PATH" OLLAMA\_MODELS="$ROOT/models" OLLAMA\_HOST="127.0.0.1:$PORT"; nohup "$ROOT/ollama/bin/ollama" serve >"$ROOT/ollama.log" 2>\&1 \& echo $! >"$ROOT/ollama.pid"; for i in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/api/tags" >/dev/null \&\& break; sleep 1; done; curl -sf "http://127.0.0.1:$PORT/api/tags" >/dev/null || { echo "Ollama failed to start:"; cat "$ROOT/ollama.log"; exit 1; }; ollama pull qwen2.5-coder:14b; ollama run qwen2.5-coder:14b'

bash -lc 'ROOT="$HOME/qwen-local"; export HOME="$ROOT/home" OLLAMA\_MODELS="$ROOT/models" OLLAMA\_HOST="127.0.0.1:11435"; "$ROOT/ollama/bin/ollama" run qwen2.5-coder:14b'



bash -lc 'ROOT="$HOME/qwen-local"; P="$ROOT/ollama/bin/ollama"; if \[ -d "$ROOT" ]; then pkill -TERM -f "$P" 2>/dev/null || true; for i in $(seq 1 50); do pgrep -f "$P" >/dev/null || break; sleep 0.2; done; pkill -KILL -f "$P" 2>/dev/null || true; rm -rf "$ROOT"; fi; echo "Removed temporary Ollama/Qwen installation, model, venv, Ollama keys/config/cache, and application logs."'

\########################################################################################################################################################################################################

"""Analyze this Information Security lab question before coding.



Return ONLY a compact implementation plan, max 20 lines.



For each required operation state:

\- algorithm and exact role

\- user inputs

\- generated values

\- library/API or manual formula

\- execution order

\- success/failure condition



Rules:

\- No hardcoded question-specific values.

\- Use PyCryptodome where it directly supports the operation.

\- Classical ciphers may be implemented manually.

\- AES/DES/3DES: use Crypto.Cipher.

\- RSA encryption: use PKCS1\_OAEP, never RSA key.encrypt()/decrypt().

\- Hashing: use hashlib or Crypto.Hash.

\- ElGamal encryption/decryption: implement textbook equations manually with pow(); do not call ElGamal.encrypt()/decrypt().

\- Do not invent APIs.

\- Preserve exactly the algorithms requested.

\- Everything explicitly supplied in the question must be input().

\- Values naturally generated cryptographically may be generated securely.



QUESTION:

\[PASTE QUESTION]"""
########################################################################################################################################################################################################



"""Using the original question and the plan above, write ONE complete executable Python program.



Output ONLY code.



Rules:

\- Follow the plan exactly.

\- No question-specific hardcoding.

\- All supplied values use input().

\- Keep it short enough to write in a lab exam.

\- Use only real APIs.

\- No placeholders or fake implementations.

\- Correct all bytes/str/int conversions.

\- Correct key sizes, padding, IV/nonce, file modes and modular arithmetic.

\- Verification must occur before any operation that the question says depends on verification.



Silently trace the program from first line to last before answering."""


########################################################################################################################################################################################################



"""Recheck the program above against the original question and plan.



Return ONLY the full corrected code.



Silently fix:

\- nonexistent/obsolete APIs

\- missing requirements

\- hardcoded question values

\- crypto/math errors

\- bytes/str/int errors

\- key/padding/IV errors

\- file I/O errors

\- reversed verification logic

\- operations occurring before required verification

\- broken encryption/decryption inverses

\- placeholders



For PyCryptodome specifically:

\- RSA encryption/decryption must use PKCS1\_OAEP

\- do not use RSA key.encrypt()/decrypt()

\- do not use ElGamal.encrypt()/decrypt()

\- textbook ElGamal uses pow() and modular inverse



Mentally execute the final program top-to-bottom.""""


########################################################################################################################################################################################################



