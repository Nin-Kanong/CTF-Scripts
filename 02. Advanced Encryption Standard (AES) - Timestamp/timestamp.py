#!/usr/bin/env python3
"""Reusable timestamp-derived AES key recovery helper for authorized CTF challenges.

Requires: pip install cryptography
No remote actions: TCP mode only reads a challenge banner; it never sends data.
"""

import argparse
import base64
import hashlib
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_PREFIXES = ("academy{", "picoCTF{", "flag{", "CTF{", "HTB{", "THM{")


def parse_timestamp(value):
    """Accept a Unix timestamp or ISO-8601 date (UTC assumed if unspecified)."""
    value = str(value).strip()
    if re.fullmatch(r"\d{9,12}", value):
        return int(value)
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError as exc:
        raise ValueError("Timestamp must be Unix seconds or ISO-8601, e.g. 2026-09-23T12:00:00Z") from exc


def parse_banner(text):
    """Extract optional values from a plain-text CTF file or TCP banner."""
    fields = {}
    patterns = {
        "timestamp": [r"(?:timestamp|time\s*hint|around|at\s*time)\s*(?:\(UTC\))?\s*[:=]?\s*(\d{9,12})\b"],
        "ciphertext": [r"(?:ciphertext|cyphertext|encrypted\s*message|encrypted\s*flag|\bct\b)\s*(?:\((?:hex|base64|b64)\))?\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]+)"],
        "iv": [r"\biv\s*(?:\(hex\))?\s*[:=]\s*['\"]?([0-9a-fA-F]+)"],
    }
    for name, choices in patterns.items():
        for pattern in choices:
            found = re.search(pattern, text, re.IGNORECASE)
            if found:
                fields[name] = found.group(1)
                break
    if "ciphertext" not in fields:
        lines = [x.strip() for x in text.splitlines() if x.strip()]
        if len(lines) == 1 and re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", lines[0]):
            fields["ciphertext"] = lines[0]
    return fields


def read_banner(host, port, timeout, limit=65536):
    """Connect once and receive public challenge text, without sending commands."""
    data = bytearray()
    with socket.create_connection((host, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        while len(data) < limit:
            try:
                chunk = conn.recv(min(4096, limit - len(data)))
            except socket.timeout:
                break
            if not chunk:
                break
            data.extend(chunk)
            fields = parse_banner(data.decode("utf-8", errors="replace"))
            if "timestamp" in fields and "ciphertext" in fields:
                break
    return data.decode("utf-8", errors="replace")


def decode_bytes(value, encoding):
    """Accept hex, 0x-prefixed hex, or base64 ciphertext."""
    cleaned = re.sub(r"\s+", "", value).strip("'\"")
    if encoding == "auto":
        encoding = "hex" if re.fullmatch(r"(?:0x)?(?:[0-9a-fA-F]{2})+", cleaned) else "base64"
    if encoding == "hex":
        return bytes.fromhex(cleaned.removeprefix("0x"))
    if encoding == "base64":
        cleaned += "=" * (-len(cleaned) % 4)
        return base64.b64decode(cleaned, altchars=b"-_", validate=True)
    raise ValueError("Unknown ciphertext encoding")


def timestamp_input_bytes(timestamp, fmt):
    if fmt == "decimal":
        return str(timestamp).encode("ascii")
    if fmt == "little8":
        return timestamp.to_bytes(8, "little", signed=False)
    if fmt == "big8":
        return timestamp.to_bytes(8, "big", signed=False)
    raise ValueError(f"Unknown timestamp format: {fmt}")


def derive_key(timestamp, algorithm, length, fmt):
    raw = timestamp_input_bytes(timestamp, fmt)
    digest = hashlib.new(algorithm, raw).digest()
    if length > len(digest):
        raise ValueError(f"{algorithm} provides {len(digest)} bytes; cannot derive a {length}-byte key")
    return digest[:length]


def decrypt(ciphertext, key, mode, iv):
    cipher_mode = modes.ECB() if mode == "ecb" else modes.CBC(iv)
    dec = Cipher(algorithms.AES(key), cipher_mode).decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    if not padded:
        return None
    pad_len = padded[-1]
    if not 1 <= pad_len <= 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return padded[:-pad_len]  # PKCS#7 unpadding


def candidate_offsets(window, step):
    """Try the hint first, then timestamps progressively farther away."""
    yield 0
    for distance in range(step, window + 1, step):
        yield distance
        yield -distance


def interactive_input(args):
    print("\nTimestamp AES CTF Solver — interactive mode")
    print("  1) Paste a timestamp and ciphertext")
    print("  2) Read message.txt")
    print("  3) Connect to a CTF server and read its banner")
    choice = input("Choose [1/2/3, default 1]: ").strip() or "1"
    if choice == "1":
        args.time = input("Unix timestamp (or ISO-8601 UTC): ").strip()
        args.ciphertext = input("Ciphertext (hex or base64): ").strip()
    elif choice == "2":
        args.file = input("File path [message.txt]: ").strip() or "message.txt"
    elif choice == "3":
        args.host = input("CTF host: ").strip()
        args.port = int(input("CTF port: ").strip())
    else:
        raise ValueError("Choose 1, 2, or 3")
    custom_window = input(f"Time window in seconds [{args.window}]: ").strip()
    if custom_window:
        args.window = int(custom_window)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Recover AES-ECB/CBC plaintext when the key comes from a guessable Unix timestamp.",
        epilog=(
            "Examples:\n"
            "  python3 timestamp.py                            # interactive\n"
            "  python3 timestamp.py --file message.txt\n"
            "  python3 timestamp.py --time 1790147507 --ciphertext 6ef9...\n"
            "  python3 timestamp.py --host example.ctf --port 12345\n"
            "  python3 timestamp.py --file message.txt --window 3600 --prefix 'academy{'\n"
            "  python3 timestamp.py --file message.txt --mode cbc --iv HEX_IV\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", help="Read timestamp and ciphertext from a challenge text file")
    source.add_argument("--host", help="Read a public CTF challenge banner via TCP (requires --port)")
    parser.add_argument("--port", type=int, help="TCP port for --host")
    parser.add_argument("--timeout", type=float, default=4.0, help="Socket timeout in seconds (default: 4)")
    parser.add_argument("--time", "--timestamp", dest="time", help="Unix seconds or ISO-8601 timestamp")
    parser.add_argument("--ciphertext", "--ct", dest="ciphertext", help="Ciphertext hex or base64")
    parser.add_argument("--encoding", choices=("auto", "hex", "base64"), default="auto")
    parser.add_argument("--window", type=int, default=600, help="Search ± seconds around timestamp (default: 600)")
    parser.add_argument("--step", type=int, default=1, help="Search stride in seconds (default: 1)")
    parser.add_argument("--hash", dest="hash_name", choices=("sha256", "sha1", "sha512", "md5"), default="sha256",
                        help="Hash used to derive AES key (default: sha256)")
    parser.add_argument("--key-length", type=int, choices=(16, 24, 32), default=16, help="AES key length in bytes (default: 16)")
    parser.add_argument("--time-format", choices=("decimal", "little8", "big8"), default="decimal",
                        help="How timestamp is hashed: decimal text or 8-byte binary (default: decimal)")
    parser.add_argument("--mode", choices=("ecb", "cbc"), default="ecb", help="AES mode (default: ecb)")
    parser.add_argument("--iv", help="16-byte IV as 32 hex digits (required for CBC unless provided in file)")
    parser.add_argument("--prefix", action="append", help="Recognize a flag prefix, e.g. --prefix 'academy{' (repeatable)")
    parser.add_argument("--show-candidates", action="store_true", help="Show up to 5 other printable, valid-padding results")
    parser.add_argument("--output", help="Write recovered text to this file")
    parser.add_argument("--verbose", action="store_true", help="Show progress during a long search")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if (argv is None and len(sys.argv) == 1) or argv == []:
        interactive_input(args)
    if args.window < 0 or args.step <= 0 or args.timeout <= 0:
        parser.error("--window must be >= 0; --step and --timeout must be > 0")
    if args.host and (args.port is None or not 1 <= args.port <= 65535):
        parser.error("--host requires --port in range 1..65535")
    if args.port is not None and not args.host:
        parser.error("--port requires --host")

    fields = {}
    if args.file:
        fields = parse_banner(Path(args.file).read_text(encoding="utf-8"))
        print(f"[+] Read file: {args.file}")
    elif args.host:
        print(f"[+] Connecting to {args.host}:{args.port} (banner read only)")
        fields = parse_banner(read_banner(args.host, args.port, args.timeout))

    time_value = args.time or fields.get("timestamp")
    cipher_value = args.ciphertext or fields.get("ciphertext")
    if not time_value or not cipher_value:
        parser.error("Need timestamp and ciphertext: use --file, --host/--port, or --time and --ciphertext")

    ts = parse_timestamp(time_value)
    ciphertext = decode_bytes(cipher_value, args.encoding)
    if not ciphertext or len(ciphertext) % 16:
        parser.error("AES ciphertext must be nonempty and a multiple of 16 bytes")
    iv = None
    if args.mode == "cbc":
        iv_text = args.iv or fields.get("iv")
        if not iv_text:
            parser.error("CBC mode requires --iv (32 hex digits), or an IV in the input file")
        iv = bytes.fromhex(iv_text.removeprefix("0x"))
        if len(iv) != 16:
            parser.error("CBC IV must be exactly 16 bytes (32 hex digits)")
    if args.key_length > hashlib.new(args.hash_name).digest_size:
        parser.error(f"{args.hash_name} digest is too short for {args.key_length}-byte AES key")

    prefixes = tuple(args.prefix or DEFAULT_PREFIXES)
    print(f"[+] Hint timestamp: {ts} ({datetime.fromtimestamp(ts, timezone.utc).isoformat()})")
    print(f"[+] Ciphertext length: {len(ciphertext)} bytes | AES-{args.key_length * 8}-{args.mode.upper()}")
    print(f"[+] Key: {args.hash_name}(timestamp as {args.time_format})[:{args.key_length}]")
    print(f"[+] Searching {ts - args.window} to {ts + args.window} UTC seconds, step {args.step}")

    tested = 0
    candidate_count = 0
    for delta in candidate_offsets(args.window, args.step):
        t = ts + delta
        if t < 0:
            continue
        key = derive_key(t, args.hash_name, args.key_length, args.time_format)
        plaintext = decrypt(ciphertext, key, args.mode, iv)
        tested += 1
        if args.verbose and tested % 10000 == 0:
            print(f"[*] Tested {tested:,} timestamps ...")
        if plaintext is None:
            continue
        try:
            decoded = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if any(prefix in decoded for prefix in prefixes):
            print("\n[+] FLAG / PLAINTEXT FOUND")
            print(f"[+] Timestamp: {t} (offset {delta:+d} seconds)")
            print(f"[+] Key (hex): {key.hex()}")
            print(f"[+] Decrypted: {decoded}")
            if args.output:
                Path(args.output).write_text(decoded + "\n", encoding="utf-8")
                print(f"[+] Saved to: {args.output}")
            return 0
        if args.show_candidates and candidate_count < 5 and decoded.isprintable():
            print(f"[?] Other valid-padding candidate at {t}: {decoded[:140]!r}")
            candidate_count += 1
    print(f"\n[-] No recognized flag found after {tested:,} candidate timestamps.")
    print("    Check the correct ciphertext, timestamp, mode, key derivation, and flag prefix.")
    print("    Try a wider --window or --show-candidates if the hint is approximate.")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
