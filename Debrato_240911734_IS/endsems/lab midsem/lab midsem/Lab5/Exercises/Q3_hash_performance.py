"""Lab 5 - Exercise 3
Compare MD5, SHA-1, SHA-256: generate 50-100 random strings, time the hashing, and detect
collisions in the hashed dataset.
To modify: ALGOS (any hashlib name), COUNT, or TRUNCATE (hex chars kept) to see the
collision detector actually find collisions on a deliberately weakened hash."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

ALGOS = ["md5", "sha1", "sha256"]
COUNT = ask("Number of strings (50-100)", random.randint(50, 100))
REPEAT = ask("Repetitions for timing", 200)
data = random_strings(COUNT)
print(f"Dataset: {COUNT} random strings, e.g. {data[:3]}")

rows, chart = [], {}
for algo in ALGOS:
    _, t = timed(lambda: [hash_hex(s, algo) for s in data], repeat=REPEAT)
    coll = find_collisions(data, lambda s: hash_hex(s, algo))
    rows.append([algo.upper(), hashlib.new(algo).digest_size * 8, t * 1e6, t * 1e6 / COUNT, len(coll)])
    chart[algo.upper()] = t * 1e6

banner("Results")
print_table(["Algorithm", "Bits", "Total us", "us / string", "Collisions"], rows)
plot(chart, f"Time to hash {COUNT} strings", "time (us)", "hash_performance.png")

TRUNCATE = 2
weak = find_collisions(data, lambda s: hash_hex(s, "sha256")[:TRUNCATE])
banner(f"Collision detector check: SHA-256 truncated to {TRUNCATE} hex chars (8 bits)")
for h, items in list(weak.items())[:5]:
    print(f"  {h}: {items}")
print(f"  {len(weak)} colliding buckets found -> detector works; full hashes had none.")
print("""
Notes: for short strings all three take well under 1 us each (call overhead dominates);
on large inputs MD5 > SHA-1 > SHA-256 in speed. MD5 (128-bit) and SHA-1 (160-bit) are
broken - practical collisions exist (MD5 2004, SHA-1 SHAttered 2017). SHA-256 is
collision resistant; birthday bound = 2^(n/2) tries for an n-bit hash, so no collisions
are expected in 100 strings for any of them.""")
