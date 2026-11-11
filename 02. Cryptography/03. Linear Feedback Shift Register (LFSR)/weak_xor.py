#!/usr/bin/env python3
"""Configurable weak-LFSR / XOR cryptography solver for authorized CTF labs.

Default matches picoCTF Academy "shift registers" (8-bit LFSR).
Requires only Python 3.9+ standard library.

Examples:
  python3 script.py
  python3 script.py output.txt
  python3 script.py -c 30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9
  python3 script.py -f output.txt --prefix 'academy{'
  python3 script.py -f output.txt --taps 7,5,4,3 --width 8
  python3 script.py -f output.txt --mode auto --auto
  python3 script.py -f output.txt --tap-search 4 --prefix 'academy{'
  python3 script.py -f output.txt --mode bit --bit-index 0 --bit-order msb
  python3 script.py -f output.txt --mode single-byte
"""

import argparse
import base64
import itertools
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TAPS = (7, 5, 4, 3)
FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,32}\{[ -~]{3,160}\}")


@dataclass(frozen=True)
class Variant:
    mode: str
    direction: str = "right"
    emit: str = "after"
    bit_order: str = "msb"
    bit_index: int = 0


@dataclass
class Result:
    score: float
    plaintext: bytes
    seed: int
    taps: tuple
    variant: Variant
    printable: float
    matching_seeds: list = field(default_factory=list)


def integer(value):
    """Interpret a decimal number or a 0x-prefixed hexadecimal number."""
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def parse_taps(spec, width):
    try:
        taps = tuple(int(p.strip(), 0) for p in spec.split(","))
    except ValueError as exc:
        raise ValueError("--taps must be comma-separated bit positions, e.g. 7,5,4,3") from exc
    if not taps or len(set(taps)) != len(taps) or any(t < 0 or t >= width for t in taps):
        raise ValueError(f"--taps needs unique positions between 0 and {width - 1}")
    return taps


def parse_tap_search(spec, width):
    try:
        if "-" in spec:
            a, b = (int(i) for i in spec.split("-", 1))
            counts = range(a, b + 1)
        else:
            counts = [int(spec)]
    except ValueError as exc:
        raise ValueError("--tap-search must be e.g. 4 or 1-4") from exc
    counts = tuple(counts)
    if not counts or min(counts) < 1 or max(counts) > width:
        raise ValueError(f"--tap-search counts must be from 1 to {width}")
    return [t for n in counts for t in itertools.combinations(range(width), n)]


def load_ciphertext(args):
    if args.ciphertext is not None:
        data = args.ciphertext.encode("utf-8")
    else:
        filepath = args.file or args.source or "output.txt"
        try:
            if filepath == "-":
                data = sys.stdin.buffer.read()
            else:
                data = Path(filepath).read_bytes()
        except OSError as exc:
            raise ValueError(f"Cannot read {filepath!r}: {exc}") from exc

    if args.format == "raw":
        return data
    if args.format == "base64":
        try:
            return base64.b64decode(data.strip(), validate=True)
        except Exception as exc:
            raise ValueError("Not valid base64 ciphertext") from exc

    # Most CTF outputs contain ASCII hex, with or without whitespace/0x.
    stripped = re.sub(rb"\s+", b"", data)
    if stripped.lower().startswith(b"0x"):
        stripped = stripped[2:]
    is_hex = bool(stripped) and len(stripped) % 2 == 0 and bool(re.fullmatch(rb"[0-9a-fA-F]+", stripped))
    if args.format == "hex" or is_hex:
        if not is_hex:
            raise ValueError("Expected even-length hexadecimal data (try --format raw)")
        return bytes.fromhex(stripped.decode("ascii"))
    if args.format == "auto":
        return data
    raise ValueError("Invalid ciphertext format")


def transition(state, width, taps, direction):
    # LFSR feedback is XOR of the tapped bits (bit 0 is the LSB).
    fb = 0
    for bit in taps:
        fb ^= (state >> bit) & 1
    if direction == "right":
        return (state >> 1) | (fb << (width - 1))
    return ((state << 1) | fb) & ((1 << width) - 1)


def decrypt_lfsr(ciphertext, seed, width, taps, variant, byte_offset=0, skip=0):
    state = seed
    for _ in range(skip):
        state = transition(state, width, taps, variant.direction)
    out = bytearray()

    if variant.mode == "state":
        for c in ciphertext:
            if variant.emit == "after":
                state = transition(state, width, taps, variant.direction)
            ks = (state >> byte_offset) & 0xFF
            out.append(c ^ ks)
            if variant.emit == "before":
                state = transition(state, width, taps, variant.direction)
    else:  # bit mode; build 1 keystream byte from 8 consecutive output bits
        for c in ciphertext:
            ks = 0
            for i in range(8):
                if variant.emit == "after":
                    state = transition(state, width, taps, variant.direction)
                bit = (state >> variant.bit_index) & 1
                pos = (7 - i) if variant.bit_order == "msb" else i
                ks |= bit << pos
                if variant.emit == "before":
                    state = transition(state, width, taps, variant.direction)
            out.append(c ^ ks)

    return bytes(out)


def decrypt_single_byte(ciphertext, key):
    return bytes(c ^ key for c in ciphertext)


def printable_ratio(b):
    return sum(32 <= x < 127 or x in (9, 10, 13) for x in b) / max(1, len(b))


def evaluate(pt):
    ratio = printable_ratio(pt)
    score = ratio * 100.0
    flags = list(FLAG_RE.finditer(pt))
    if flags:
        score += 80
        if any(m.start() == 0 and m.end() == len(pt) for m in flags):
            score += 35
    if pt.startswith((b"picoCTF{", b"academy{", b"flag{", b"FLAG{", b"CTF{", b"HTB{", b"DUCTF{")):
        score += 90
    if pt.count(b"{") == 1 and pt.count(b"}") == 1:
        score += 15
    if b"_" in pt:
        score += 5
    return score, ratio


def candidate_ok(pt, args):
    if args.prefix is not None and not pt.startswith(args.prefix.encode()):
        return False
    if args.suffix is not None and not pt.endswith(args.suffix.encode()):
        return False
    if args.contains is not None and args.contains.encode() not in pt:
        return False
    if args.crib is not None:
        crib = args.crib.encode()
        off = args.offset
        if pt[off:off + len(crib)] != crib:
            return False
    if args.regex is not None and re.search(args.regex.encode(), pt) is None:
        return False
    if not args.all and printable_ratio(pt) < args.min_printable:
        return False
    return True


def make_variants(args):
    modes = ("state", "bit", "single-byte") if args.mode == "auto" else (args.mode,)
    variants = []
    for mode in modes:
        if mode == "single-byte":
            variants.append(Variant(mode))
            continue
        directions = ("right", "left") if args.auto else (args.direction,)
        emits = ("after", "before") if args.auto else (args.emit,)
        bit_orders = ("msb", "lsb") if args.auto and mode == "bit" else (args.bit_order,)
        indexes = (0, args.width - 1) if args.auto and mode == "bit" else (args.bit_index,)
        for direction, emit, order, bit_index in itertools.product(directions, emits, bit_orders, indexes):
            variants.append(Variant(mode, direction, emit, order, bit_index))
    # Preserve order while removing duplicate variants (e.g., width = 1).
    return list(dict.fromkeys(variants))


def as_text(pt):
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        return repr(pt)


def build_parser():
    p = argparse.ArgumentParser(
        description="Brute-force weak LFSR XOR keystreams and single-byte XOR (CTF use).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    inputs = p.add_argument_group("ciphertext input")
    inputs.add_argument("source", nargs="?", help="Path to ciphertext; defaults to ./output.txt")
    group = inputs.add_mutually_exclusive_group()
    group.add_argument("-c", "--ciphertext", help="Ciphertext string (hex by default)")
    group.add_argument("-f", "--file", help="Ciphertext file (text hex or raw)")
    inputs.add_argument("--format", choices=("auto", "hex", "raw", "base64"), default="auto")

    lfsr = p.add_argument_group("LFSR and keystream")
    lfsr.add_argument("--width", type=int, default=8, help="LFSR state size in bits")
    lfsr.add_argument("--taps", default="7,5,4,3", help="Feedback bit positions (LSB = 0)")
    lfsr.add_argument("--tap-search", metavar="N_OR_RANGE", help="Try feedback tap combinations: 4 or 1-4")
    lfsr.add_argument("--mode", choices=("state", "bit", "single-byte", "auto"), default="state",
                      help="state = XOR register bytes; bit = XOR packed output bits; single-byte = 1-byte key")
    lfsr.add_argument("--direction", choices=("right", "left"), default="right")
    lfsr.add_argument("--emit", choices=("after", "before"), default="after",
                      help="Output keystream before or after each LFSR update")
    lfsr.add_argument("--byte-offset", type=int, default=0,
                      help="For state mode, use state bits [offset:offset+8]")
    lfsr.add_argument("--bit-index", type=int, default=0,
                      help="For bit mode, output this register bit")
    lfsr.add_argument("--bit-order", choices=("msb", "lsb"), default="msb",
                      help="For bit mode, pack output bits most- or least-significant first")
    lfsr.add_argument("--skip", type=int, default=0, help="Discard this many initial LFSR steps")
    lfsr.add_argument("--seed", type=integer, help="Test one initial state, e.g. 162 or 0xA2")
    lfsr.add_argument("--auto", action="store_true",
                      help="Try both shift directions and both pre/post output conventions; in bit mode also both bit ends/orders")
    lfsr.add_argument("--force", action="store_true", help="Allow searches above safety work limits")

    filt = p.add_argument_group("plaintext filters and output")
    filt.add_argument("--prefix", help="Require plaintext to start with this, e.g. 'academy{'")
    filt.add_argument("--suffix", help="Require plaintext to end with this")
    filt.add_argument("--contains", help="Require plaintext to contain this")
    filt.add_argument("--crib", help="Require a known plaintext substring at --offset")
    filt.add_argument("--offset", type=int, default=0, help="Byte offset of --crib")
    filt.add_argument("--regex", help="Require plaintext to match this Python regex")
    filt.add_argument("--min-printable", type=float, default=0.85,
                      help="Only keep mostly printable candidates (0..1)")
    filt.add_argument("--top", type=int, default=10, help="Show best N candidates; 0 shows all")
    filt.add_argument("--all", action="store_true", help="Keep also non-printable plaintexts")
    filt.add_argument("--save", help="Save highest-ranked decrypted plaintext as raw bytes")
    filt.add_argument("--json", action="store_true", help="Print machine-readable JSON instead of a report")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.source and (args.file or args.ciphertext):
        parser.error("Use the positional input path OR -f/-c, not both")
    if not 2 <= args.width <= 64:
        parser.error("--width must be from 2 to 64 bits")
    if not 0 <= args.bit_index < args.width:
        parser.error("--bit-index must be inside the state width")
    if args.byte_offset < 0 or args.skip < 0 or args.offset < 0:
        parser.error("Offsets and --skip must be nonnegative")
    if not 0 <= args.min_printable <= 1 or args.top < 0:
        parser.error("--min-printable must be 0..1 and --top must be >= 0")
    if args.seed is not None and not 0 <= args.seed < (1 << args.width):
        parser.error("--seed is outside the chosen register width")
    try:
        ct = load_ciphertext(args)
        tapsets = parse_tap_search(args.tap_search, args.width) if args.tap_search else [parse_taps(args.taps, args.width)]
        if args.regex is not None:
            re.compile(args.regex.encode())
    except (ValueError, re.error) as exc:
        parser.error(str(exc))
    if not ct:
        parser.error("Ciphertext is empty")

    variants = make_variants(args)
    lfsr_variants = [v for v in variants if v.mode != "single-byte"]
    single_variants = [v for v in variants if v.mode == "single-byte"]
    if lfsr_variants and args.seed is None and args.width > 24:
        parser.error("Brute forcing more than 24 bits is impractical; specify --seed")
    if lfsr_variants and args.seed is None and args.width > 16 and not args.force:
        parser.error("Brute forcing >16 state bits may take a long time. Use --seed or --force")
    seeds = [args.seed] if args.seed is not None else range(1 << args.width)
    seed_count = len(seeds)
    step_factor = sum(8 if v.mode == "bit" else 1 for v in lfsr_variants)
    cost = len(ct) * seed_count * len(tapsets) * step_factor
    if cost > 60_000_000 and not args.force:
        parser.error(f"Estimated {cost:,} LFSR steps. Narrow --mode/--tap-search or pass --force")

    checked = 0
    best_by_plaintext = {}
    # Process all tried configurations, keeping only promising candidates.
    for v in single_variants:
        for key in range(256):
            pt = decrypt_single_byte(ct, key)
            checked += 1
            if not candidate_ok(pt, args):
                continue
            score, ratio = evaluate(pt)
            result = Result(score, pt, key, (), v, ratio)
            old = best_by_plaintext.get(pt)
            if old is None or old.score < score:
                best_by_plaintext[pt] = result

    for taps in tapsets:
        for v in lfsr_variants:
            for seed in seeds:
                pt = decrypt_lfsr(ct, seed, args.width, taps, v, args.byte_offset, args.skip)
                checked += 1
                if not candidate_ok(pt, args):
                    continue
                score, ratio = evaluate(pt)
                result = Result(score, pt, seed, taps, v, ratio)
                old = best_by_plaintext.get(pt)
                if old is None or old.score < score:
                    result.matching_seeds = [seed]
                    best_by_plaintext[pt] = result
                elif old.taps == taps and old.variant == v and len(old.matching_seeds) < 32:
                    if seed not in old.matching_seeds:
                        old.matching_seeds.append(seed)

    results = sorted(best_by_plaintext.values(), key=lambda r: (-r.score, -r.printable, r.seed))
    shown = results if args.top == 0 else results[:args.top]
    if args.save and results:
        try:
            Path(args.save).write_bytes(results[0].plaintext)
        except OSError as exc:
            parser.error(f"Cannot write --save file: {exc}")

    if args.json:
        print(json.dumps({
            "ciphertext_bytes": len(ct), "candidates_tested": checked,
            "candidates_retained": len(results),
            "results": [{
                "score": round(r.score, 2), "plaintext": as_text(r.plaintext),
                "plaintext_hex": r.plaintext.hex(), "seed": r.seed,
                "seed_hex": hex(r.seed), "matching_seeds": r.matching_seeds, "taps": r.taps,
                "mode": r.variant.mode, "direction": r.variant.direction,
                "emit": r.variant.emit, "bit_order": r.variant.bit_order,
                "bit_index": r.variant.bit_index,
            } for r in shown],
        }, indent=2))
        return 0 if results else 1

    print(f"[+] Loaded {len(ct)} ciphertext bytes")
    print(f"[+] Checked {checked:,} key/configuration candidates")
    print(f"[+] Retained {len(results):,} matching candidate plaintexts")
    if not results:
        print("[-] No candidates matched. Try --all --top 20, --mode auto --auto, --tap-search 4,")
        print("    or adjust --width, --taps, --prefix, --bit-index and --emit.")
        return 1
    for index, r in enumerate(shown, 1):
        print(f"\n[#{index}] Score {r.score:.1f} | printable {r.printable:.0%}")
        print(f"     PLAINTEXT: {as_text(r.plaintext)}")
        if r.variant.mode == "single-byte":
            print(f"     XOR key: {r.seed} ({r.seed:#04x})")
        else:
            if len(r.matching_seeds) > 1:
                seed_label = ", ".join(f"{s} ({s:#x})" for s in r.matching_seeds)
                print(f"     Equivalent seeds: {seed_label}")
            else:
                print(f"     Seed: {r.seed} ({r.seed:#x})")
            print(f"     Taps: {','.join(map(str, r.taps))}")
            print(f"     Mode: {r.variant.mode} | shift: {r.variant.direction} | emit: {r.variant.emit}")
            if r.variant.mode == "bit":
                print(f"     Output bit: {r.variant.bit_index} | pack: {r.variant.bit_order}")
        if index == 1 and args.save:
            print(f"     Saved: {args.save}")
    print("\n[!] Check the flag prefix and actual encryption source before submitting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
