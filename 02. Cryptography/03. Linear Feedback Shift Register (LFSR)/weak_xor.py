#!/usr/bin/env python3
"""weak_xor.py - CTF XOR and linear-feedback shift register toolkit.

Developer: k4n0ng
Version: 2.0.0
License: MIT
Python: 3.9+ (standard library only)

Designed for CTFs, puzzles, and authorized research. It is NOT a universal
cipher solver. See `python3 weak_xor.py --examples` and `--help`.

Keystream conventions:
* A Fibonacci LFSR is an integer state with bit 0 at its least-significant end.
* Feedback = XOR of the selected (0-based) tap positions.
* Right shift: (state >> 1) | (feedback << (width - 1)).
* Left shift: ((state << 1) | feedback) & ((1 << width) - 1).
* State mode emits 8 register bits per ciphertext byte, with one transition
  before/after each byte. Bit mode emits 8 successive selected bits per byte.
"""
from __future__ import annotations

import argparse
import base64
import itertools
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = "2.0.0"
__author__ = "k4n0ng"
DEFAULT_TAPS = (7, 5, 4, 3)
FLAG_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]{1,32}\{[\x20-\x7e]{1,200}\}")
KNOWN_FLAG_PREFIXES = (b"academy{", b"picoCTF{", b"flag{", b"FLAG{", b"CTF{", b"HTB{", b"DUCTF{", b"actf{")
MAX_WORK = 60_000_000  # rough LFSR keystream steps for brute-force
MAX_LINEAR_VARIANTS = 2500  # tap combinations * LFSR output variants
EXAMPLES = r"""
weak_xor.py v2.0 - CTF quick start (developer: k4n0ng)

  Original academy 8-bit LFSR puzzle:
    python3 weak_xor.py -c 30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9 --prefix 'academy{'

  File, hexadecimal, raw bytes or base64:
    python3 weak_xor.py -f output.txt --format auto
    python3 weak_xor.py -f secret.bin --format raw --mode single-byte
    python3 weak_xor.py -c SGVsbG8= --format base64 --mode single-byte

  Search variants and taps (8-bit challenge):
    python3 weak_xor.py -f output.txt --mode auto --auto --prefix 'flag{'
    python3 weak_xor.py -f output.txt --tap-search 1-4 --prefix 'academy{'

  Known state (works for wide LFSRs too):
    python3 weak_xor.py -f output.txt --width 32 --taps 31,21,1,0 --seed 0x12345678

  Solve an UNKNOWN wide LFSR seed by GF(2) algebra, without brute force:
    python3 weak_xor.py -f output.txt --mode state --width 32 --taps 31,21,1,0 --attack linear --crib 'known plaintext here' --offset 0

  Recover arbitrary *linear bit* keystream from a known plaintext prefix:
    python3 weak_xor.py -f output.txt --mode bit --attack bm --prefix 'a long known plaintext prefix'

  Repeating-key XOR (known 3-byte key or guessed key):
    python3 weak_xor.py -f output.txt --mode repeating --key ICE
    python3 weak_xor.py -f output.txt --mode repeating --key-size 3 --prefix 'flag{'
    python3 weak_xor.py -f output.txt --mode repeating --max-key-size 20

  Read the results as JSON, save candidate, run built-in tests:
    python3 weak_xor.py -f output.txt --mode auto --json
    python3 weak_xor.py -f output.txt --prefix 'flag{' --save recovered.bin
    python3 weak_xor.py --self-test

Tips:
  --prefix and --crib are also used to create known-keystream equations.
  --attack linear needs correct LFSR taps and sufficient known plaintext.
  --attack bm needs an adequately long contiguous known plaintext from byte 0,
  a linear bit keystream, and the correct --bit-order; its result is provisional.
  --auto explores multiple conventions; it does not detect arbitrary encryption.
"""


@dataclass(frozen=True)
class Variant:
    mode: str
    direction: str = "right"
    emit: str = "after"
    bit_order: str = "msb"
    bit_index: int = 0


@dataclass
class Candidate:
    plaintext: bytes
    score: float
    printable: float
    method: str
    variant: Variant
    seed: Optional[int] = None
    taps: Tuple[int, ...] = ()
    key: Optional[bytes] = None
    details: Dict[str, object] = field(default_factory=dict)
    matching_seeds: List[int] = field(default_factory=list)


class Collector:
    """Deduplicate candidates; cap retained candidates unless --top 0."""
    def __init__(self, top: int, force: bool = False) -> None:
        self.items: Dict[bytes, Candidate] = {}
        self.top = top
        self.cap = max(1000, top * 30) if top else (1_000_000 if force else 100_000)
        self.checked = 0

    def add(self, candidate: Candidate) -> None:
        self.checked += 1
        old = self.items.get(candidate.plaintext)
        if old is None or candidate.score > old.score:
            self.items[candidate.plaintext] = candidate
        elif (old.seed is not None and candidate.seed is not None and
              old.variant == candidate.variant and old.taps == candidate.taps and
              len(old.matching_seeds) < 32 and candidate.seed not in old.matching_seeds):
            old.matching_seeds.append(candidate.seed)
        if len(self.items) > self.cap:
            if self.top == 0:
                raise ValueError("Too many candidates for --top 0; add --prefix or use --top N / --force")
            best = sorted(self.items.values(), key=lambda x: (-x.score, -x.printable))[:max(self.top * 10, 400)]
            self.items = {c.plaintext: c for c in best}

    def results(self) -> List[Candidate]:
        return sorted(self.items.values(), key=lambda x: (-x.score, -x.printable, x.method))


def integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def parse_taps(spec: str, width: int) -> Tuple[int, ...]:
    try:
        taps = tuple(int(x.strip(), 0) for x in spec.split(","))
    except ValueError as exc:
        raise ValueError("--taps must be comma-separated 0-based positions, e.g. 7,5,4,3") from exc
    if not taps or len(set(taps)) != len(taps) or any(x < 0 or x >= width for x in taps):
        raise ValueError(f"--taps must contain unique positions from 0 through {width - 1}")
    return taps


def parse_tap_search(spec: str, width: int) -> List[Tuple[int, ...]]:
    try:
        if "-" in spec:
            parts = spec.split("-")
            if len(parts) != 2:
                raise ValueError
            start, end = (int(x) for x in parts)
            if start > end:
                raise ValueError
            counts = range(start, end + 1)
        else:
            counts = (int(spec),)
    except ValueError as exc:
        raise ValueError("--tap-search must be e.g. 4 or 1-4") from exc
    if min(counts) < 1 or max(counts) > width:
        raise ValueError(f"--tap-search counts must lie between 1 and {width}")
    total = sum(math.comb(width, n) for n in counts)
    if total > 200_000:
        raise ValueError(f"--tap-search would create {total:,} sets (memory limit 200,000); narrow the search")
    return [t for n in counts for t in itertools.combinations(range(width), n)]


def decode_input(data: bytes, encoding: str) -> bytes:
    stripped = re.sub(rb"\s+", b"", data)
    hex_value = stripped[2:] if stripped.lower().startswith(b"0x") else stripped
    looks_hex = bool(hex_value) and len(hex_value) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", hex_value) is not None
    if encoding == "hex" or (encoding == "auto" and looks_hex):
        if not looks_hex:
            raise ValueError("Invalid hex input: expected an even number of hex digits")
        return bytes.fromhex(hex_value.decode("ascii"))
    if encoding == "base64":
        try:
            return base64.b64decode(stripped, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("Invalid base64 data") from exc
    return data


def read_ciphertext(args: argparse.Namespace) -> bytes:
    if args.ciphertext is not None:
        data = args.ciphertext.encode("utf-8")
    else:
        name = args.file or args.source or "output.txt"
        try:
            data = sys.stdin.buffer.read() if name == "-" else Path(name).read_bytes()
        except OSError as exc:
            raise ValueError(f"Cannot read ciphertext file {name!r}: {exc}") from exc
    return decode_input(data, args.format)


def transition(state: int, width: int, taps: Sequence[int], direction: str) -> int:
    feedback = 0
    for tap in taps:
        feedback ^= (state >> tap) & 1
    if direction == "right":
        return (state >> 1) | (feedback << (width - 1))
    return ((state << 1) | feedback) & ((1 << width) - 1)


def crypt_lfsr(data: bytes, seed: int, width: int, taps: Sequence[int], variant: Variant,
               byte_offset: int = 0, skip: int = 0) -> bytes:
    state = seed
    for _ in range(skip):
        state = transition(state, width, taps, variant.direction)
    result = bytearray()
    for c in data:
        if variant.mode == "state":
            if variant.emit == "after":
                state = transition(state, width, taps, variant.direction)
            k = (state >> byte_offset) & 255
            if variant.emit == "before":
                state = transition(state, width, taps, variant.direction)
        elif variant.mode == "bit":
            k = 0
            for i in range(8):
                if variant.emit == "after":
                    state = transition(state, width, taps, variant.direction)
                k |= ((state >> variant.bit_index) & 1) << (7 - i if variant.bit_order == "msb" else i)
                if variant.emit == "before":
                    state = transition(state, width, taps, variant.direction)
        else:
            raise ValueError(f"Invalid LFSR variant: {variant.mode}")
        result.append(c ^ k)
    return bytes(result)


def crypt_repeating(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("XOR key cannot be empty")
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def printable_ratio(data: bytes) -> float:
    return sum(32 <= x <= 126 or x in (9, 10, 13) for x in data) / max(1, len(data))


def english_score(data: bytes) -> float:
    """Heuristic for ranking: not a proof that a plaintext is correct."""
    score = 0.0
    for ch in data:
        if ch in (9, 10, 13):
            score += 0.7
        elif ch == 32:
            score += 2.3
        elif 65 <= ch <= 90 or 97 <= ch <= 122:
            score += 1.5
            if chr(ch).lower() in "etaoinshrdlu":
                score += 0.25
        elif ch in b"0123456789_{}-.,:!?@/":
            score += 0.9
        elif 32 <= ch <= 126:
            score += 0.2
        else:
            score -= 7
    return score / max(1, len(data))


def evaluate(pt: bytes, args: argparse.Namespace) -> Tuple[float, float]:
    ratio = printable_ratio(pt)
    score = 100 * ratio + 25 * english_score(pt)
    matches = list(FLAG_RE.finditer(pt))
    if matches:
        score += 115
        if any(m.start() == 0 and m.end() == len(pt) for m in matches):
            score += 75
    if pt.startswith(KNOWN_FLAG_PREFIXES):
        score += 100
    if pt.count(b"{") == 1 and pt.count(b"}") == 1:
        score += 18
    if b"_" in pt:
        score += 5
    # Weak preference for shorter repeating keys when plausibility ties.
    return score, ratio


def candidate_ok(pt: bytes, args: argparse.Namespace) -> bool:
    if args.prefix is not None and not pt.startswith(args.prefix.encode("utf-8")):
        return False
    if args.suffix is not None and not pt.endswith(args.suffix.encode("utf-8")):
        return False
    if args.contains is not None and args.contains.encode("utf-8") not in pt:
        return False
    if args.crib is not None:
        crib = args.crib.encode("utf-8")
        if pt[args.offset: args.offset + len(crib)] != crib:
            return False
    if args.regex is not None and re.search(args.regex.encode("utf-8"), pt) is None:
        return False
    return args.all or printable_ratio(pt) >= args.min_printable


def known_bytes(ct: bytes, args: argparse.Namespace) -> Dict[int, int]:
    """Build byte-offset -> known plaintext value, with conflict detection."""
    mapping: Dict[int, int] = {}
    chunks: List[Tuple[int, bytes, str]] = []
    if args.prefix:
        chunks.append((0, args.prefix.encode("utf-8"), "--prefix"))
    if args.suffix:
        raw = args.suffix.encode("utf-8")
        chunks.append((len(ct) - len(raw), raw, "--suffix"))
    if args.crib:
        chunks.append((args.offset, args.crib.encode("utf-8"), "--crib"))
    for start, value, source in chunks:
        if start < 0 or start + len(value) > len(ct):
            raise ValueError(f"{source} is longer than available ciphertext at its offset")
        for i, b in enumerate(value):
            index = start + i
            if index in mapping and mapping[index] != b:
                raise ValueError("Conflicting known plaintext: --prefix/--suffix/--crib disagree")
            mapping[index] = b
    return mapping


def make_variants(args: argparse.Namespace) -> List[Variant]:
    modes = ("state", "bit", "single-byte", "repeating") if args.mode == "auto" else (args.mode,)
    variants: List[Variant] = []
    for mode in modes:
        if mode in ("single-byte", "repeating"):
            variants.append(Variant(mode))
            continue
        for direction, emit, bit_order, bit_index in itertools.product(
            ("right", "left") if args.auto else (args.direction,),
            ("after", "before") if args.auto else (args.emit,),
            ("msb", "lsb") if args.auto and mode == "bit" else (args.bit_order,),
            (0, args.width - 1) if args.auto and mode == "bit" else (args.bit_index,),
        ):
            variants.append(Variant(mode, direction, emit, bit_order, bit_index))
    return list(dict.fromkeys(variants))


def collect_plaintext(ct: bytes, pt: bytes, variant: Variant, method: str,
                      args: argparse.Namespace, results: Collector,
                      seed: Optional[int] = None, taps: Sequence[int] = (),
                      key: Optional[bytes] = None, details: Optional[Dict[str, object]] = None) -> None:
    if not candidate_ok(pt, args):
        return
    score, ratio = evaluate(pt, args)
    if key is not None:
        score -= 0.07 * len(key)
    results.add(Candidate(pt, score, ratio, method, variant, seed, tuple(taps), key,
                          details or {}, [seed] if seed is not None else []))


def brute_single_byte(ct: bytes, variant: Variant, args: argparse.Namespace,
                      results: Collector) -> int:
    count = 0
    for key in range(256):
        pt = crypt_repeating(ct, bytes([key]))
        collect_plaintext(ct, pt, variant, "single-byte brute-force", args, results, key=bytes([key]))
        count += 1
    return count


def brute_lfsr(ct: bytes, tapsets: Sequence[Tuple[int, ...]], variants: Sequence[Variant],
               args: argparse.Namespace, results: Collector) -> int:
    seeds = (args.seed,) if args.seed is not None else range(1 << args.width)
    count = 0
    for taps in tapsets:
        for variant in variants:
            for seed in seeds:
                pt = crypt_lfsr(ct, seed, args.width, taps, variant, args.byte_offset, args.skip)
                collect_plaintext(ct, pt, variant, "LFSR seed search", args, results,
                                  seed=seed, taps=taps)
                count += 1
    return count


def symbolic_step(bits: List[int], taps: Sequence[int], direction: str) -> List[int]:
    fb = 0
    for t in taps:
        fb ^= bits[t]
    return bits[1:] + [fb] if direction == "right" else [fb] + bits[:-1]


def gf2_solve(equations: Sequence[Tuple[int, int]], width: int) -> Optional[Tuple[int, int, List[int]]]:
    """Find a particular seed and free-variable basis for A*seed = b over GF(2).

    Returns (particular_solution, rank, nullspace_basis); None if inconsistent.
    """
    pivots: Dict[int, Tuple[int, int]] = {}
    for mask, target in equations:
        target &= 1
        while mask:
            col = (mask & -mask).bit_length() - 1
            if col not in pivots:
                pivots[col] = (mask, target)
                break
            pivot_mask, rhs = pivots[col]
            mask ^= pivot_mask
            target ^= rhs
        if not mask and target:
            return None

    free_cols = [i for i in range(width) if i not in pivots]

    def back_substitute(free_assignment: int, homogeneous: bool) -> int:
        answer = free_assignment
        for col in sorted(pivots, reverse=True):
            row_mask, rhs = pivots[col]
            value = (0 if homogeneous else rhs) ^ ((row_mask & answer).bit_count() & 1)
            if value:
                answer |= 1 << col
            else:
                answer &= ~(1 << col)
        return answer

    particular = back_substitute(0, False)
    basis = [back_substitute(1 << col, True) for col in free_cols]
    return particular, len(pivots), basis


def make_equations(ct: bytes, known: Dict[int, int], width: int,
                   taps: Sequence[int], variant: Variant, byte_offset: int, skip: int) -> List[Tuple[int, int]]:
    """Every emitted keystream bit is a linear expression in the seed bits."""
    symbols = [1 << bit for bit in range(width)]
    for _ in range(skip):
        symbols = symbolic_step(symbols, taps, variant.direction)
    equations: List[Tuple[int, int]] = []
    last_byte = max(known) if known else -1
    for byte_index in range(last_byte + 1):
        if variant.mode == "state":
            if variant.emit == "after":
                symbols = symbolic_step(symbols, taps, variant.direction)
            masks = [symbols[byte_offset + bit] if byte_offset + bit < width else 0 for bit in range(8)]
            if variant.emit == "before":
                symbols = symbolic_step(symbols, taps, variant.direction)
        elif variant.mode == "bit":
            masks = [0] * 8
            for n in range(8):
                if variant.emit == "after":
                    symbols = symbolic_step(symbols, taps, variant.direction)
                pos = 7 - n if variant.bit_order == "msb" else n
                masks[pos] = symbols[variant.bit_index]
                if variant.emit == "before":
                    symbols = symbolic_step(symbols, taps, variant.direction)
        else:
            raise ValueError("GF(2) equations require state or bit mode")
        if byte_index in known:
            ks = ct[byte_index] ^ known[byte_index]
            equations.extend((mask, (ks >> bit) & 1) for bit, mask in enumerate(masks))
    return equations


def linear_lfsr(ct: bytes, known: Dict[int, int], tapsets: Sequence[Tuple[int, ...]],
                variants: Sequence[Variant], args: argparse.Namespace,
                results: Collector) -> int:
    if not known:
        raise ValueError("--attack linear requires known plaintext: --prefix, --suffix, or --crib with --offset")
    checked = 0
    for taps in tapsets:
        for variant in variants:
            eqs = make_equations(ct, known, args.width, taps, variant, args.byte_offset, args.skip)
            solution = gf2_solve(eqs, args.width)
            checked += 1
            if solution is None:
                continue
            seed, rank, basis = solution
            # Exhaust only small free-variable spaces. Large ones are reported as
            # underdetermined; pretending a unique answer would be misleading.
            if len(basis) <= args.max_free_bits:
                assignment = 0
                previous_gray = 0
                for i in range(1 << len(basis)):
                    gray = i ^ (i >> 1)
                    if i:
                        changed = gray ^ previous_gray
                        assignment ^= basis[(changed & -changed).bit_length() - 1]
                    previous_gray = gray
                    candidate_seed = seed ^ assignment
                    pt = crypt_lfsr(ct, candidate_seed, args.width, taps, variant,
                                    args.byte_offset, args.skip)
                    collect_plaintext(ct, pt, variant, "GF(2) seed recovery", args, results,
                                      seed=candidate_seed, taps=taps,
                                      details={"rank": rank, "free_bits": len(basis),
                                               "unique": len(basis) == 0})
            else:
                pt = crypt_lfsr(ct, seed, args.width, taps, variant, args.byte_offset, args.skip)
                collect_plaintext(ct, pt, variant, "GF(2) seed recovery (underdetermined)",
                                  args, results, seed=seed, taps=taps,
                                  details={"rank": rank, "free_bits": len(basis),
                                           "unique": False, "warning": "One of many possible seeds"})
    return checked


def berlekamp_massey(sequence: Sequence[int]) -> Tuple[int, List[int]]:
    """Minimal binary linear recurrence; C[j] is coefficient of s[n-j]."""
    length = len(sequence)
    if not length:
        raise ValueError("Need a non-empty bit sequence for Berlekamp-Massey")
    c = [0] * (length + 1)
    b = [0] * (length + 1)
    c[0] = b[0] = 1
    L = 0
    last_update = -1
    for n, value in enumerate(sequence):
        discrepancy = value
        for j in range(1, L + 1):
            discrepancy ^= c[j] & sequence[n - j]
        if discrepancy:
            previous_c = c[:]
            shift = n - last_update
            for j in range(length + 1 - shift):
                c[j + shift] ^= b[j]
            if 2 * L <= n:
                L = n + 1 - L
                b = previous_c
                last_update = n
    return L, c[:L + 1]


def bits_from_bytes(data: bytes, bit_order: str) -> List[int]:
    return [((byte >> (7 - i if bit_order == "msb" else i)) & 1) for byte in data for i in range(8)]


def bytes_from_bits(bits: Sequence[int], bit_order: str) -> bytes:
    out = bytearray()
    for pos in range(0, len(bits), 8):
        chunk = bits[pos:pos + 8]
        if len(chunk) != 8:
            raise ValueError("Bitstream length must be divisible by 8")
        value = 0
        for j, bit in enumerate(chunk):
            value |= bit << (7 - j if bit_order == "msb" else j)
        out.append(value)
    return bytes(out)


def bm_attack(ct: bytes, known: Dict[int, int], args: argparse.Namespace,
              results: Collector) -> int:
    contiguous = bytearray()
    for index in range(len(ct)):
        if index not in known:
            break
        contiguous.append(ct[index] ^ known[index])
    if len(contiguous) < 2:
        raise ValueError("--attack bm needs a contiguous known-plaintext prefix from offset 0 (at least 2 bytes)")
    checked = 0
    orders = ("msb", "lsb") if args.auto else (args.bit_order,)
    for order in orders:
        known_bits = bits_from_bytes(bytes(contiguous), order)
        degree, polynomial = berlekamp_massey(known_bits)
        checked += 1
        if degree > args.bm_max_complexity:
            continue
        if degree == 0 and any(known_bits):
            continue
        # For short samples, high-complexity recurrences may just be overfitting.
        stream = known_bits[:]
        for n in range(len(stream), 8 * len(ct)):
            next_bit = 0
            for lag in range(1, degree + 1):
                next_bit ^= polynomial[lag] & stream[n - lag]
            stream.append(next_bit)
        keystream = bytes_from_bits(stream, order)
        pt = bytes(a ^ b for a, b in zip(ct, keystream))
        variant = Variant("bit", bit_order=order)
        collect_plaintext(ct, pt, variant, "Berlekamp-Massey bitstream recovery", args, results,
                          details={"linear_complexity": degree,
                                   "connection_polynomial": [i for i, c in enumerate(polynomial) if c],
                                   "known_bits": len(known_bits),
                                   "warning": ("Insufficient evidence for confident prediction"
                                               if len(known_bits) < 2 * degree + 8 else
                                               "Recovered linear recurrence; verify against challenge code")})
    return checked


def column_keys(column: bytes, count: int) -> List[int]:
    ranked = sorted(((english_score(bytes(c ^ k for c in column)), k) for k in range(256)),
                    reverse=True)
    return [k for _, k in ranked[:count]]


def repeating_attack(ct: bytes, known: Dict[int, int], variant: Variant,
                     args: argparse.Namespace, results: Collector) -> int:
    if args.key is not None or args.key_hex is not None:
        key = args.key.encode("utf-8") if args.key is not None else bytes.fromhex(args.key_hex)
        if not key:
            raise ValueError("Explicit repeating XOR key cannot be empty")
        pt = crypt_repeating(ct, key)
        collect_plaintext(ct, pt, variant, "known repeating XOR key", args, results, key=key)
        return 1

    key_sizes = [args.key_size] if args.key_size else range(1, min(args.max_key_size, len(ct)) + 1)
    checked = 0
    for length in key_sizes:
        forced: Dict[int, int] = {}
        valid = True
        for index, plain_byte in known.items():
            position = index % length
            byte = ct[index] ^ plain_byte
            if position in forced and forced[position] != byte:
                valid = False
                break
            forced[position] = byte
        if not valid:
            continue
        cols: List[List[int]] = []
        for j in range(length):
            if j in forced:
                cols.append([forced[j]])
            else:
                column = ct[j::length]
                cols.append(column_keys(column, args.column_top))
        beam: List[Tuple[bytes, float]] = [(b"", 0.0)]
        for j, alternatives in enumerate(cols):
            column = ct[j::length]
            beam = sorted(
                ((partial + bytes([key]), quality + english_score(bytes(c ^ key for c in column)) * len(column))
                 for partial, quality in beam for key in alternatives),
                key=lambda pair: -pair[1],
            )[:args.beam]
        for key, _ in beam:
            pt = crypt_repeating(ct, key)
            collect_plaintext(ct, pt, variant, "repeating XOR key search", args, results, key=key,
                              details={"key_size": length})
            checked += 1
    return checked


def as_text(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return repr(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="weak_xor.py",
        description="CTF XOR / LFSR solver, by k4n0ng. Brute-force weak XOR, recover linear LFSR states, and infer bitstream recurrences.",
        epilog="Run --examples for ready-to-copy commands. No external Python packages needed.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__} (developer: {__author__})")
    parser.add_argument("--examples", action="store_true", help="Show a detailed usage cookbook and exit")
    parser.add_argument("--self-test", action="store_true", help="Run internal mathematical smoke tests and exit")
    inputs = parser.add_argument_group("input")
    inputs.add_argument("source", nargs="?", help="Ciphertext file (default: ./output.txt)")
    mutex = inputs.add_mutually_exclusive_group()
    mutex.add_argument("-c", "--ciphertext", help="Ciphertext directly as hex/base64/raw text")
    mutex.add_argument("-f", "--file", help="Input file; use - for stdin")
    inputs.add_argument("--format", choices=("auto", "hex", "raw", "base64"), default="auto",
                        help="Auto detects hex, otherwise treats input as raw")

    lfsr = parser.add_argument_group("LFSR and attack selection")
    lfsr.add_argument("--mode", choices=("state", "bit", "single-byte", "repeating", "auto"), default="state",
                      help="State byte XOR, packed bit XOR, single-byte XOR, repeating XOR, or try all")
    lfsr.add_argument("--attack", choices=("auto", "brute", "linear", "bm"), default="auto",
                      help="Auto chooses small brute-force or large GF(2) known-plaintext recovery; bm requires bit mode")
    lfsr.add_argument("--width", type=int, default=8, help="Number of LFSR state bits")
    lfsr.add_argument("--taps", default="7,5,4,3", help="0-based feedback bit positions (bit 0 = LSB)")
    lfsr.add_argument("--tap-search", metavar="N_OR_RANGE", help="Enumerate feedback tap sets, e.g. 4 or 1-4")
    lfsr.add_argument("--direction", choices=("right", "left"), default="right")
    lfsr.add_argument("--emit", choices=("after", "before"), default="after",
                      help="Emit output after/before updating the LFSR")
    lfsr.add_argument("--byte-offset", type=int, default=0,
                      help="State mode: lowest register bit used in the XOR output byte")
    lfsr.add_argument("--bit-index", type=int, default=0, help="Bit mode: register bit used for each output bit")
    lfsr.add_argument("--bit-order", choices=("msb", "lsb"), default="msb", help="Bit mode: output bit packing order")
    lfsr.add_argument("--skip", type=int, default=0, help="Initial LFSR clock steps to discard")
    lfsr.add_argument("--seed", type=integer, help="Known LFSR initial state, decimal or 0xhex")
    lfsr.add_argument("--auto", action="store_true", help="Try both directions, emit conventions, and bit ends/orders")
    lfsr.add_argument("--max-free-bits", type=int, default=10,
                      help="Linear recovery: enumerate at most 2**N free-variable assignments")
    lfsr.add_argument("--bm-max-complexity", type=int, default=256,
                      help="Reject Berlekamp-Massey hypotheses above this degree")
    lfsr.add_argument("--force", action="store_true", help="Override estimated-work and search limits")

    repeat = parser.add_argument_group("repeating XOR")
    key = repeat.add_mutually_exclusive_group()
    key.add_argument("--key", help="Known UTF-8 repeating XOR key")
    key.add_argument("--key-hex", help="Known repeating XOR key in hex")
    repeat.add_argument("--key-size", type=int, help="Try one repeating-key length")
    repeat.add_argument("--max-key-size", type=int, default=20, help="Largest repeating-key length to try")
    repeat.add_argument("--column-top", type=int, default=3, help="Candidate key bytes per column")
    repeat.add_argument("--beam", type=int, default=40, help="Keep this many promising repeating-key prefixes")

    filters = parser.add_argument_group("known plaintext, filtering and output")
    filters.add_argument("--prefix", help="Require plaintext prefix; also contributes known plaintext for algebra")
    filters.add_argument("--suffix", help="Require plaintext suffix; also contributes known plaintext for algebra")
    filters.add_argument("--contains", help="Require substring anywhere in plaintext")
    filters.add_argument("--crib", help="Known plaintext bytes at --offset; enables GF(2) recovery")
    filters.add_argument("--offset", type=int, default=0, help="Byte offset of --crib")
    filters.add_argument("--regex", help="Require plaintext match against this Python regular expression")
    filters.add_argument("--min-printable", type=float, default=0.85, help="Minimum readable character fraction [0..1]")
    filters.add_argument("--top", type=int, default=10, help="Print top N candidates, 0 = all (can be large)")
    filters.add_argument("--all", action="store_true", help="Allow non-printable plaintext candidates")
    filters.add_argument("--save", help="Write best candidate plaintext as raw bytes")
    filters.add_argument("--json", action="store_true", help="Output structured JSON for other tools")
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.source is not None and (args.file or args.ciphertext is not None):
        parser.error("Choose positional source OR -f / -c, not both")
    if not 2 <= args.width <= 256:
        parser.error("--width must be 2..256")
    if not 0 <= args.bit_index < args.width or not 0 <= args.byte_offset < args.width:
        parser.error("--bit-index / --byte-offset must be inside state width")
    if args.skip < 0 or args.offset < 0:
        parser.error("--skip and --offset must be nonnegative")
    if args.skip > 1_000_000 and not args.force:
        parser.error("Large --skip needs --force")
    if args.top < 0 or not 0 <= args.min_printable <= 1:
        parser.error("--top must be >=0 and --min-printable must be between 0 and 1")
    if args.max_free_bits < 0 or args.max_free_bits > 20:
        parser.error("--max-free-bits must be in 0..20")
    if args.bm_max_complexity < 1:
        parser.error("--bm-max-complexity must be positive")
    if args.max_key_size < 1 or args.beam < 1 or not 1 <= args.column_top <= 256:
        parser.error("--max-key-size / --beam must be positive and --column-top must be 1..256")
    if args.key_size is not None and args.key_size < 1:
        parser.error("--key-size must be positive")
    if args.seed is not None and not 0 <= args.seed < 1 << args.width:
        parser.error("--seed is outside selected --width")
    if args.attack == "bm" and args.mode not in ("bit", "auto"):
        parser.error("--attack bm requires --mode bit or --mode auto")
    if args.attack == "linear" and args.mode in ("single-byte", "repeating"):
        parser.error("--attack linear requires --mode state, --mode bit, or --mode auto")
    if args.key_hex is not None:
        try:
            if not bytes.fromhex(args.key_hex):
                parser.error("--key-hex cannot be empty")
        except ValueError:
            parser.error("--key-hex must contain valid hexadecimal bytes")
    if args.key == "":
        parser.error("--key cannot be empty")
    if args.regex is not None:
        try:
            re.compile(args.regex.encode("utf-8"))
        except re.error as exc:
            parser.error(f"Invalid --regex: {exc}")


def candidate_to_dict(candidate: Candidate) -> Dict[str, object]:
    return {
        "plaintext": as_text(candidate.plaintext),
        "plaintext_hex": candidate.plaintext.hex(),
        "score": round(candidate.score, 2),
        "printable": round(candidate.printable, 4),
        "method": candidate.method,
        "mode": candidate.variant.mode,
        "direction": candidate.variant.direction,
        "emit": candidate.variant.emit,
        "bit_order": candidate.variant.bit_order,
        "bit_index": candidate.variant.bit_index,
        "seed": candidate.seed,
        "seed_hex": hex(candidate.seed) if candidate.seed is not None else None,
        "matching_seeds": candidate.matching_seeds,
        "taps": list(candidate.taps),
        "key_hex": candidate.key.hex() if candidate.key is not None else None,
        "key_display": as_text(candidate.key) if candidate.key is not None else None,
        "details": candidate.details,
    }


def print_results(ct: bytes, attempts: int, results: List[Candidate],
                  args: argparse.Namespace) -> None:
    shown = results if args.top == 0 else results[:args.top]
    if args.json:
        print(json.dumps({"developer": __author__, "version": __version__,
                          "ciphertext_bytes": len(ct), "candidates_tested": attempts,
                          "candidates_retained": len(results),
                          "results": [candidate_to_dict(r) for r in shown]}, indent=2))
        return
    print(f"[k4n0ng] weak_xor.py v{__version__} | {len(ct)} ciphertext bytes")
    print(f"[+] Checked {attempts:,} seeds/keys/configurations; retained {len(results):,} candidates")
    if not results:
        print("[-] No matching plaintext. Check algorithm, input encoding, taps, width and crib.")
        print("[?] Try --examples; --mode auto --auto; --tap-search 1-4; or a longer --crib.")
        return
    for index, c in enumerate(shown, 1):
        print(f"\n[{index}] score={c.score:.2f} printable={c.printable:.0%} via {c.method}")
        print(f"    plaintext: {as_text(c.plaintext)}")
        if c.key is not None:
            print(f"    xor key: {as_text(c.key)} (hex={c.key.hex()})")
        if c.seed is not None:
            print(f"    seed: {c.seed} (0x{c.seed:x}); taps: {','.join(map(str, c.taps))}")
            print(f"    mode={c.variant.mode} direction={c.variant.direction} emit={c.variant.emit}")
            if c.variant.mode == "bit":
                print(f"    bit-index={c.variant.bit_index} bit-order={c.variant.bit_order}")
            if len(c.matching_seeds) > 1:
                print(f"    equivalent observed seeds: {', '.join(hex(s) for s in c.matching_seeds)}")
        if c.details:
            print("    details: " + ", ".join(f"{k}={v}" for k, v in c.details.items()))
    if args.save:
        print(f"\n[+] Best candidate written to: {args.save}")
    print("\n[!] Heuristics can produce false positives. Verify the flag and source code.")


def internal_self_test() -> None:
    """Fast smoke checks; comprehensive tests live in test_weak_xor.py."""
    assert crypt_repeating(crypt_repeating(b"test message", b"ICE"), b"ICE") == b"test message"
    v = Variant("state")
    pt = b"academy{self_test}"
    ct = crypt_lfsr(pt, 0xA2, 8, DEFAULT_TAPS, v)
    assert crypt_lfsr(ct, 0xA2, 8, DEFAULT_TAPS, v) == pt
    bits = bits_from_bytes(b"\xa3\xf0", "msb")
    assert bytes_from_bits(bits, "msb") == b"\xa3\xf0"
    for width in (8, 16):
        taps = (width - 1, 2, 1, 0)
        vv = Variant("bit", direction="left", emit="before", bit_index=width - 1, bit_order="lsb")
        seed = (1 << width) - 37
        sample = crypt_lfsr(b"known plaintext for test", seed, width, taps, vv)
        mapping = {i: b for i, b in enumerate(b"known plaintext for test")}
        solution = gf2_solve(make_equations(sample, mapping, width, taps, vv, 0, 0), width)
        assert solution is not None
        recovered, _, basis = solution
        assert crypt_lfsr(sample, recovered, width, taps, vv) == b"known plaintext for test"
        assert len(basis) < width
    print(f"[+] weak_xor.py v{__version__} internal self-tests passed (developer: {__author__})")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.examples:
        print(EXAMPLES)
        return 0
    if args.self_test:
        internal_self_test()
        return 0
    validate_args(args, parser)
    try:
        ct = read_ciphertext(args)
        if not ct:
            raise ValueError("Ciphertext is empty")
        known = known_bytes(ct, args)
        if args.key_size and args.key_size > len(ct):
            raise ValueError("--key-size cannot be longer than the ciphertext")
        variants = make_variants(args)
        lfsr_variants = [v for v in variants if v.mode in ("state", "bit")]
        tapsets = (parse_tap_search(args.tap_search, args.width) if args.tap_search else
                   [parse_taps(args.taps, args.width)]) if lfsr_variants else []
        single_variants = [v for v in variants if v.mode == "single-byte"]
        repeating_variants = [v for v in variants if v.mode == "repeating"]
        if args.attack == "bm" and not any(v.mode == "bit" for v in lfsr_variants):
            raise ValueError("--attack bm needs --mode bit or auto")

        methods: List[str] = []
        if lfsr_variants:
            if args.attack == "bm":
                methods.append("bm")
            elif args.seed is not None:
                methods.append("brute")
            elif args.attack == "linear":
                methods.append("linear")
            elif args.attack == "brute":
                methods.append("brute")
            else:
                methods.append("brute" if args.width <= 16 else "linear" if known else "none")

        if "none" in methods:
            if args.mode == "auto":
                methods.remove("none")  # Other XOR attacks may still work.
                print("[!] Wide LFSR search skipped: supply known plaintext (--crib/--prefix) to recover the seed.", file=sys.stderr)
            else:
                raise ValueError("Unknown LFSR seed >16 bits: supply --seed, or --prefix/--crib for GF(2) recovery")
        if "brute" in methods and args.seed is None and args.width > 24:
            raise ValueError("Brute-force >24-bit LFSR seed is disabled; use --attack linear plus --crib")
        if "brute" in methods and args.seed is None and args.width > 16 and not args.force:
            raise ValueError("Brute-force >16 bits needs --force; prefer --attack linear with --crib")
        if "brute" in methods:
            seed_count = 1 if args.seed is not None else (1 << args.width)
            step_factor = sum(8 if v.mode == "bit" else 1 for v in lfsr_variants)
            cost = seed_count * len(tapsets) * (len(ct) * step_factor + args.skip)
            if cost > MAX_WORK and not args.force:
                raise ValueError(f"Estimated {cost:,} LFSR operations exceed limit {MAX_WORK:,}; narrow search or --force")
        if "linear" in methods and len(tapsets) * len(lfsr_variants) > MAX_LINEAR_VARIANTS and not args.force:
            raise ValueError(f"GF(2) tap/convention combinations exceed {MAX_LINEAR_VARIANTS:,}; narrow --tap-search or --force")

        results = Collector(args.top, args.force)
        checked = 0
        if args.attack == "bm":
            checked += bm_attack(ct, known, args, results)
        else:
            if "brute" in methods:
                checked += brute_lfsr(ct, tapsets, lfsr_variants, args, results)
            if "linear" in methods:
                checked += linear_lfsr(ct, known, tapsets, lfsr_variants, args, results)
        for variant in single_variants:
            checked += brute_single_byte(ct, variant, args, results)
        for variant in repeating_variants:
            checked += repeating_attack(ct, known, variant, args, results)
        ordered = results.results()
        if args.save and ordered:
            try:
                Path(args.save).write_bytes(ordered[0].plaintext)
            except OSError as exc:
                raise ValueError(f"Cannot write output file {args.save!r}: {exc}") from exc
        print_results(ct, checked, ordered, args)
        return 0 if ordered else 1
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        if isinstance(exc, KeyboardInterrupt):
            print("\n[!] Interrupted by user", file=sys.stderr)
            return 130
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
