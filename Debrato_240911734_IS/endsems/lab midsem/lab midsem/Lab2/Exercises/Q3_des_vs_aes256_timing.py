"""Lab 2 - Exercise 3
Compare encryption and decryption times of DES and AES-256 for
"Performance Testing of Encryption Algorithms". Report the findings.
To modify: add entries to CONFIGS (e.g. "AES-128": ("AES", 16)) or change REPEAT."""
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
from islib import *

msg = ask("Message", "Performance Testing of Encryption Algorithms")
MODE = ask("Mode", "ECB")
REPEAT = ask("Repetitions (averaged)", 10000)
CONFIGS = {"DES": ("DES", 8), "AES-256": ("AES", 32)}

rows, chart = [], {}
for name, (algo, size) in CONFIGS.items():
    key = get_random_bytes(size)
    ct, _ = symmetric(algo, key, msg, MODE)
    t_enc, t_dec = sym_benchmark(algo, key, msg, MODE, REPEAT)
    rows.append([name, size * 8, t_enc * 1e6, t_dec * 1e6, fmt(ct)[:32] + "..."])
    chart[name] = {"encrypt": t_enc * 1e6, "decrypt": t_dec * 1e6}

banner(f"Average time over {REPEAT} runs (microseconds)")
print_table(["Algorithm", "Key bits", "Encrypt us", "Decrypt us", "Ciphertext"], rows)
plot(chart, "DES vs AES-256", "time (us)", "des_vs_aes256.png")

print("""
Findings:
 * AES-256 is usually as fast or faster than DES in software (and uses AES-NI hardware
   instructions on modern CPUs), even though its key is 256 bits vs DES's 56 effective bits.
 * DES works on 64-bit blocks, AES on 128-bit blocks - AES processes twice the data per block.
 * DES's 56-bit key is brute-forceable today; AES-256 is considered secure. Use AES.""")
