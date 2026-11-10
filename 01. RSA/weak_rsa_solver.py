#!/usr/bin/env python3
"""Educational RSA CTF helper: even modulus, shared primes, small factors, near primes.

Use only with challenges or systems you are permitted to test.
No external Python packages required.
"""

import argparse
from math import gcd, isqrt
from pathlib import Path
import re
import socket


def parse_samples(output):
    """Extract N, e, and cyphertext/ciphertext from one or more banners."""
    samples = []
    current = {}
    for line in output.splitlines():
        m = re.search(r"\b(N|e|cyphertext|ciphertext)\s*:\s*(\d+)", line, re.I)
        if not m:
            continue
        key = m.group(1).lower()
        if key == "ciphertext":
            key = "cyphertext"
        current[key] = int(m.group(2))
        if all(k in current for k in ("n", "e", "cyphertext")):
            samples.append((current["n"], current["e"], current["cyphertext"]))
            current = {}
    return samples


def fetch_sample(host, port, timeout=6):
    """Fetch just a challenge's public RSA banner. Does not send commands."""
    chunks = []
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        while sum(map(len, chunks)) < 65536:
            try:
                piece = conn.recv(4096)
            except socket.timeout:
                break
            if not piece:
                break
            chunks.append(piece)
            text = b"".join(chunks).decode("utf-8", errors="replace")
            if parse_samples(text):
                return text
    return b"".join(chunks).decode("utf-8", errors="replace")


def factor_weak_modulus(n, other_moduli, small_limit, fermat_steps):
    """Try fast attacks only; this is NOT general-purpose RSA factoring."""
    if n <= 3:
        return None
    if n % 2 == 0:
        return 2, n // 2, "even N (p = 2)"

    for other in other_moduli:
        if other == n:
            continue
        shared = gcd(n, other)
        if 1 < shared < n:
            return shared, n // shared, "shared prime factor (GCD of two N values)"

    for candidate in range(3, min(isqrt(n), small_limit) + 1, 2):
        if n % candidate == 0:
            return candidate, n // candidate, "small-factor trial division"

    # Fermat's method works when the two prime factors are unusually close.
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(fermat_steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if 1 < p < n and p * q == n:
                return p, q, "Fermat's method (close prime factors)"
        a += 1
    return None


def decrypt(n, e, c, p, q):
    """Standard RSA decryption assuming p, q are distinct primes."""
    if p * q != n or p == q:
        raise ValueError("Factors are not distinct primes in the expected format")
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e has no inverse mod phi; this needs a different approach")
    d = pow(e, -1, phi)
    message_number = pow(c, d, n)
    valid = pow(message_number, e, n) == c % n
    plaintext = message_number.to_bytes(max(1, (message_number.bit_length() + 7) // 8), "big")
    return plaintext, valid


def main():
    p = argparse.ArgumentParser(description="Recover plaintext from weak RSA CTF examples")
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--host", help="CTF server host (requires --port)")
    source.add_argument("--file", help="File containing N/e/cyphertext lines")
    source.add_argument("--n", type=int, help="RSA modulus for manual input")
    p.add_argument("--port", type=int, help="CTF server port")
    p.add_argument("--samples", type=int, default=3, help="Connections to make, default 3")
    p.add_argument("--e", type=int, help="Public exponent with --n")
    p.add_argument("--c", type=int, help="Ciphertext with --n")
    p.add_argument("--small-limit", type=int, default=10001, help="Trial division maximum, default 10001")
    p.add_argument("--fermat-steps", type=int, default=10000, help="Fermat iterations, default 10000")
    args = p.parse_args()

    if args.host:
        if args.port is None or not (0 < args.port < 65536):
            p.error("--host requires a valid --port")
        if args.samples < 1:
            p.error("--samples must be >= 1")
        samples = []
        for i in range(args.samples):
            print(f"[+] Fetching sample {i + 1}/{args.samples} from {args.host}:{args.port}")
            try:
                response = fetch_sample(args.host, args.port)
                parsed = parse_samples(response)
                if not parsed:
                    print("[!] No N/e/cyphertext values found in server response")
                samples.extend(parsed)
            except OSError as exc:
                print(f"[!] Connection failed: {exc}")
    elif args.file:
        samples = parse_samples(Path(args.file).read_text(encoding="utf-8"))
    else:
        if args.e is None or args.c is None:
            p.error("--n requires both --e and --c")
        samples = [(args.n, args.e, args.c)]

    if not samples:
        print("[!] No RSA samples available. Check the host, port, or input format.")
        return 1

    # Remove duplicate banners, but keep separate samples with the same modulus.
    samples = list(dict.fromkeys(samples))
    moduli = [n for n, _, _ in samples]
    successes = 0
    for i, (n, e, c) in enumerate(samples, 1):
        print(f"\n=== RSA sample {i}/{len(samples)} ===")
        print(f"N bits: {n.bit_length()} | e: {e} | N even: {n % 2 == 0}")
        found = factor_weak_modulus(n, moduli, args.small_limit, args.fermat_steps)
        if not found:
            print("[-] No weak factors detected by these methods.")
            print("    Try a different RSA vulnerability; strong RSA is not broken by this tool.")
            continue
        f1, f2, method = found
        print(f"[+] Factorization method: {method}")
        print(f"[+] p: {f1}")
        print(f"[+] q: {f2}")
        try:
            plaintext, valid = decrypt(n, e, c, f1, f2)
        except ValueError as exc:
            print(f"[!] {exc}")
            continue
        print(f"[+] Encryption check: {'PASS' if valid else 'FAIL'}")
        print(f"[+] Raw bytes: {plaintext!r}")
        try:
            message = plaintext.decode("utf-8")
            print(f"[+] Decrypted text: {message}")
            if valid:
                successes += 1
        except UnicodeDecodeError:
            print("[!] Bytes are not UTF-8; inspect bytes above.")
    print(f"\n[+] Verified readable decryptions: {successes}/{len(samples)}")
    return 0 if successes else 2


if __name__ == "__main__":
    raise SystemExit(main())
