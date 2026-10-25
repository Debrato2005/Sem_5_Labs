"""Lab 2 - Additional 1
Using DES and AES (128, 192, 256-bit keys) encrypt five different messages with the same key.
 a) consider different modes of operation  b) plot execution time of each technique
 c) compare time taken by the different modes.
To modify: edit MESSAGES / MODES / ALGOS (e.g. add "GCM" / "EAX" for AES), or REPEAT."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

MESSAGES = ["Hello World", "Information Security Lab", "Manipal Institute of Technology",
            "The quick brown fox jumps over the lazy dog" * 4, "A" * 1024]
MODES = ["ECB", "CBC", "CFB", "OFB", "CTR"]
ALGOS = {"DES": ("DES", 8), "AES-128": ("AES", 16), "AES-192": ("AES", 24), "AES-256": ("AES", 32)}
REPEAT = ask("Repetitions per message", 300)

results, rows = {m: {} for m in MODES}, []
for name, (algo, size) in ALGOS.items():
    key = get_random_bytes(size)                           # same key for all five messages
    for mode in MODES:
        total = 0
        for msg in MESSAGES:
            t_enc, t_dec = sym_benchmark(algo, key, msg, mode, REPEAT)
            total += t_enc + t_dec
        results[mode][name] = total * 1e6
        rows.append([name, mode, total * 1e6])

banner("Total encrypt+decrypt time for the 5 messages (microseconds)")
print_table(["Algorithm", "Mode", "Time us"], rows)
plot(results, "Encrypt+decrypt time of 5 messages by mode", "time (us)", "modes_benchmark.png")
plot({a: {m: results[m][a] for m in MODES} for a in ALGOS},
     "Encrypt+decrypt time of 5 messages by algorithm", "time (us)", "algos_benchmark.png")

print("""
Observations:
 * ECB is fastest (no chaining) but leaks patterns - identical blocks give identical ciphertext.
 * CBC needs padding + an IV; encryption is sequential.  CFB/OFB/CTR turn the block cipher
   into a stream cipher (no padding); CTR is parallelisable (fastest on large data / hardware).
 * CFB is slowest here because pycryptodome's default CFB uses 8-bit segments
   (one block encryption per byte); segment_size=128 makes it as fast as OFB.
 * AES-128 < AES-192 < AES-256 in time (10 / 12 / 14 rounds); DES is slower than all AES
   variants despite its weak 56-bit key.""")
