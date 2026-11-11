#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""k4n0ng's standalone Weak RSA Toolkit: Franklin-Reiter related-message attack.

Offline, dependency-free CTF helper. It is NOT a general-purpose RSA breaker.

Given unpadded textbook RSA encryptions under the same (n, e):
    c1 = m1**e mod n
    c2 = m2**e mod n
    m2 = a*m1 + b (mod n)
recover m1 and m2 by taking a polynomial GCD modulo n.

Quick start:
    python3 weak_rsa.py --help
    python3 weak_rsa.py               # auto-load output.txt or prompt
    python3 weak_rsa.py --interactive # enter/paste lab values
    python3 weak_rsa.py -f output.txt
    python3 weak_rsa.py -f output.txt --identify
    python3 weak_rsa.py -f lab.txt -e 5 --a 7 --b 1337
    python3 weak_rsa.py -f lab.txt -e 3 --search-b=-20:20
    python3 weak_rsa.py --search-e 3,5,17 --search-b 10
    python3 weak_rsa.py --self-test

Author: k4n0ng
Version: 2.0.0
Single-file tool: Python standard library only
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

__version__ = "2.0.0"
__author__ = "k4n0ng"
DEFAULT_E = 17
DEFAULT_MAX_E = 128
DEFAULT_MAX_ATTEMPTS = 5000
FLAG_PATTERN = re.compile(rb"[A-Za-z][A-Za-z0-9_-]{0,30}\{[^\x00\r\n{}]{1,300}\}")


class WeakRSAError(Exception):
    """An invalid input or an inapplicable attack, with a helpful message."""


class NonUnitError(WeakRSAError):
    """A non-invertible coefficient modulo the composite RSA modulus."""

    def __init__(self, coefficient: int, n: int):
        self.coefficient = coefficient
        self.factor = math.gcd(coefficient, n)
        super().__init__(
            f"Coefficient not invertible modulo n (gcd = {self.factor})."
        )


def number(value: str | int) -> int:
    """Parse signed decimal or hexadecimal integer (0x...)."""
    if isinstance(value, int):
        return value
    value = value.strip().replace("_", "")
    if not re.fullmatch(r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)", value):
        raise ValueError(f"not an integer: {value!r}")
    sign = -1 if value.startswith("-") else 1
    part = value.lstrip("+-")
    return sign * int(part, 16 if part.lower().startswith("0x") else 10)


def parse_range(value: str) -> tuple[int, int]:
    """10 -> (-10,10), or -5:8 -> (-5,8), inclusive."""
    try:
        if ":" in value:
            left, right = value.split(":", 1)
            start, stop = number(left), number(right)
        else:
            size = number(value)
            if size < 0:
                raise ValueError("radius must be nonnegative")
            start, stop = -size, size
        if start > stop:
            raise ValueError("range start exceeds range end")
        return start, stop
    except ValueError as ex:
        raise argparse.ArgumentTypeError(
            f"expected R or START:END (e.g., 10 or -5:8): {ex}"
        ) from ex


def poly_trim(coefficients: list[int]) -> list[int]:
    while coefficients and coefficients[-1] == 0:
        coefficients.pop()
    return coefficients


def inv_mod(coefficient: int, n: int) -> int:
    try:
        return pow(coefficient, -1, n)
    except ValueError as ex:
        raise NonUnitError(coefficient, n) from ex


def poly_rem(dividend: list[int], divisor: list[int], n: int) -> list[int]:
    """Compute remainder of low-degree-first polynomials over Z/nZ.

    Requires an invertible leading coefficient in divisor. If it is not a unit,
    the coefficient sometimes leaks a factor of n; caller may use that factor.
    """
    if not divisor:
        raise WeakRSAError("Cannot divide by the zero polynomial")
    remainder = dividend[:]
    inverse_lead = inv_mod(divisor[-1], n)
    while len(remainder) >= len(divisor):
        offset = len(remainder) - len(divisor)
        scale = remainder[-1] * inverse_lead % n
        if scale:
            for index, term in enumerate(divisor):
                position = offset + index
                remainder[position] = (remainder[position] - scale * term) % n
        poly_trim(remainder)
    return remainder


def poly_gcd(first: list[int], second: list[int], n: int,
             verbose: bool = False) -> list[int]:
    """Monic polynomial GCD when Euclidean divisions are well-defined."""
    a = poly_trim(first[:])
    b = poly_trim(second[:])
    step = 0
    while b:
        if verbose:
            print(f"    [gcd {step}] degrees: {len(a)-1}, {len(b)-1}")
        a, b = b, poly_rem(a, b, n)
        step += 1
    if not a:
        raise WeakRSAError("Both polynomials are zero; cannot extract a root")
    inverse = inv_mod(a[-1], n)
    return [coefficient * inverse % n for coefficient in a]


def make_polynomials(c1: int, c2: int, n: int, e: int,
                     a: int, b: int) -> tuple[list[int], list[int]]:
    """f(x)=x^e-c1, g(x)=(a*x+b)^e-c2, both modulo n."""
    f = [(-c1) % n] + [0] * (e - 1) + [1]
    a %= n
    b %= n
    # Iterative binomial powers avoids recomputing expensive modular powers.
    apow = [1] * (e + 1)
    bpow = [1] * (e + 1)
    for k in range(1, e + 1):
        apow[k] = apow[k - 1] * a % n
        bpow[k] = bpow[k - 1] * b % n
    g = [math.comb(e, k) * apow[k] * bpow[e - k] % n
         for k in range(e + 1)]
    g[0] = (g[0] - c2) % n
    return f, poly_trim(g)


def recover_with_factor(c1: int, c2: int, n: int, e: int,
                        a: int, b: int, factor: int) -> tuple[int, int]:
    """Fallback for standard RSA semiprimes when a coefficient reveals a factor.

    Even here, every candidate is re-encrypted and checked against both ciphers.
    """
    if not (1 < factor < n) or n % factor:
        raise WeakRSAError("Noninvertible coefficient gave no proper factor of n")
    p, q = factor, n // factor
    if p == q:
        raise WeakRSAError("Equal-prime RSA modulus requires a separate phi model")
    # This phi formula assumes distinct primes (normal RSA semiprime).
    phi = (p - 1) * (q - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError as ex:
        raise WeakRSAError("Cannot invert e modulo presumed phi(n)") from ex
    m1, m2 = pow(c1, d, n), pow(c2, d, n)
    if m2 != (a * m1 + b) % n:
        raise WeakRSAError("Factor fallback does not satisfy the given relation")
    return m1, m2


@dataclass(frozen=True)
class RSAInput:
    c1: int
    c2: int
    n: int
    e: int
    difference: int | None = None  # m1 - m2


@dataclass(frozen=True)
class Recovery:
    m1: int
    m2: int
    a: int
    b: int
    method: str


def recover(data: RSAInput, a: int, b: int,
            verbose: bool = False) -> Recovery:
    """Attempt Franklin-Reiter and verify BOTH recovered messages."""
    if data.n < 3 or data.e < 2:
        raise WeakRSAError("n must be >= 3 and e must be >= 2")
    if not (0 <= data.c1 < data.n and 0 <= data.c2 < data.n):
        raise WeakRSAError("Expected 0 <= c1,c2 < n")
    f, g = make_polynomials(data.c1, data.c2, data.n, data.e, a, b)
    try:
        common = poly_gcd(f, g, data.n, verbose)
        if len(common) != 2:
            raise WeakRSAError(
                f"Polynomial GCD has degree {len(common)-1}, not 1. "
                "This affine relationship did not uniquely recover a plaintext."
            )
        m1 = -common[0] % data.n
        m2 = (a * m1 + b) % data.n
        method = "Franklin-Reiter polynomial GCD"
    except NonUnitError as ex:
        if verbose:
            print("    [!] Noninvertible polynomial coefficient: testing factor recovery")
        m1, m2 = recover_with_factor(data.c1, data.c2, data.n,
                                    data.e, a, b, ex.factor)
        method = "nonunit coefficient -> RSA factor fallback"
    if data.difference is not None and m1 - m2 != data.difference:
        raise WeakRSAError("Recovered messages contradict the supplied m1-m2 difference")
    if pow(m1, data.e, data.n) != data.c1:
        raise WeakRSAError("Recovered m1 failed RSA re-encryption verification")
    if pow(m2, data.e, data.n) != data.c2:
        raise WeakRSAError("Recovered m2 failed RSA re-encryption verification")
    if m2 != (a * m1 + b) % data.n:
        raise WeakRSAError("Recovered messages failed affine relation verification")
    return Recovery(m1=m1, m2=m2, a=a, b=b, method=method)


def as_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def readable(payload: bytes) -> str:
    # Don't put control characters into the terminal.
    return payload.decode("utf-8", "backslashreplace").encode(
        "unicode_escape"
    ).decode("ascii").replace("\\\\", "\\")


def flag_candidates(payload: bytes) -> list[str]:
    return [m.decode("ascii", "replace")
            for m in FLAG_PATTERN.findall(payload)]


ALIASES: dict[str, set[str]] = {
    "c1": {"c1", "ciphertext", "ciphertext1", "ciphertext_1", "ct1", "ct_1"},
    "c2": {"c2", "ciphertext2", "ciphertext_2", "ct2", "ct_2"},
    "n": {"n", "modulus", "mod"},
    "e": {"e", "exponent", "public_exponent"},
    "difference": {"difference", "delta", "m1_minus_m2", "message_difference"},
    "a": {"a", "multiplier"},
    "b": {"b", "offset"},
}


def normalized_key(key: str) -> str | None:
    key = key.strip().lower().replace(" ", "_")
    if re.fullmatch(r"message_*-_+message_fixed", key) or key == "message-message_fixed":
        return "difference"
    for canonical, names in ALIASES.items():
        if key in names:
            return canonical
    return None


def read_fields(path: str, mode: str,
                line_order: str) -> dict[str, int]:
    """Read raw integer lines, labeled key/value text or a JSON object."""
    try:
        raw = sys.stdin.read() if path == "-" else Path(path).read_text("utf-8-sig")
    except OSError as ex:
        raise WeakRSAError(f"Cannot read input {path!r}: {ex}") from ex
    return parse_fields(raw, mode, line_order)


def parse_fields(raw: str, mode: str,
                 line_order: str) -> dict[str, int]:
    """Parse lab-provided text, JSON, or numeric lines already in memory."""
    if not raw.strip():
        raise WeakRSAError("Input is empty")
    chosen = mode
    if chosen == "auto":
        chosen = "json" if raw.lstrip().startswith("{") else "text"

    if chosen == "json":
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError) as ex:
            raise WeakRSAError(f"Invalid JSON input: {ex}") from ex
        if not isinstance(obj, dict):
            raise WeakRSAError("JSON input must be an object containing c1, c2, n")
        fields = {}
        for key, value in obj.items():
            target = normalized_key(key)
            if target and isinstance(value, (str, int)) and not isinstance(value, bool):
                try:
                    fields[target] = number(value)
                except ValueError as ex:
                    raise WeakRSAError(f"JSON field {key!r}: {ex}") from ex
        return fields

    if mode not in ("auto", "lines", "labeled"):
        raise WeakRSAError("Unknown input format")
    lines = [line.strip() for line in raw.splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    if chosen == "text":
        chosen = "lines" if all(re.fullmatch(
            r"[+-]?(?:0[xX][0-9a-fA-F]+|\d+)", token)
            for line in lines for token in re.split(r"[,\s]+", line) if token) else "labeled"

    if chosen == "lines":
        tokens = [token for line in lines
                  for token in re.split(r"[,\s]+", line) if token]
        names = [normalized_key(x) for x in line_order.split(",")]
        if any(name is None for name in names) or len(set(names)) != len(names):
            raise WeakRSAError("Invalid or duplicate fields in --line-order")
        if line_order == "c1,c2,difference,n":
            if len(tokens) == 2:
                names = ["c1", "c2"]  # supply n with -n
            elif len(tokens) == 3:
                names = ["c1", "c2", "n"]  # supply relation with --b
            elif len(tokens) == 5:
                names = ["c1", "c2", "difference", "n", "e"]
        if len(tokens) != len(names):
            raise WeakRSAError(
                f"Input has {len(tokens)} integers but --line-order specifies "
                f"{len(names)} fields; use --line-order c1,c2,n, for example"
            )
        try:
            return {name: number(value) for name, value in zip(names, tokens)}
        except ValueError as ex:
            raise WeakRSAError(str(ex)) from ex

    fields: dict[str, int] = {}
    for line in lines:
        match = re.fullmatch(r"\s*([\w -]+?)\s*(?:=|:)\s*"
                             r"([+-]?(?:0[xX][0-9a-fA-F]+|\d+))\s*", line)
        if not match:
            continue
        key = normalized_key(match.group(1))
        if key:
            fields[key] = number(match.group(2))
    if not fields:
        raise WeakRSAError(
            "No supported values found. Use 4 numeric lines, key=value, "
            "or JSON with c1/c2/n."
        )
    return fields


def interactive_fields(mode: str, line_order: str) -> dict[str, int]:
    """Guided TTY entry, including multi-line paste from a lab output."""
    print("\n[?] No output.txt needed: enter your CTF challenge values.")
    print("    [1] Paste lab output (3/4 numeric lines, labels, or JSON)")
    print("    [2] Enter fields one by one")
    try:
        selection = input("    Choose [1/2] (default 1): ").strip() or "1"
    except EOFError as ex:
        raise WeakRSAError("Interactive input ended; use -f output.txt instead") from ex
    if selection == "2":
        fields: dict[str, int] = {}
        prompts = (
            ("c1", "First ciphertext c1"),
            ("c2", "Second ciphertext c2"),
            ("n", "RSA modulus N"),
            ("difference", "Known m1 - m2 (blank if unknown)"),
            ("e", "Exponent e (blank defaults to 17)"),
            ("a", "Multiplier a (blank defaults to 1)"),
            ("b", "Offset b (blank infers from difference)"),
        )
        for key, label in prompts:
            try:
                raw = input(f"    {label}: ").strip()
            except EOFError as ex:
                raise WeakRSAError(f"Interactive input ended while reading {key}") from ex
            if raw:
                try:
                    fields[key] = number(raw)
                except ValueError as ex:
                    raise WeakRSAError(f"Invalid {key}: {ex}") from ex
        return fields
    if selection != "1":
        raise WeakRSAError("Choose 1 (paste) or 2 (individual fields)")
    print("    Paste the contents of output.txt; press ENTER on an empty line")
    print("    (or enter END) when finished. Input order defaults to:")
    print("    c1, c2, (m1 - m2), N")
    lines: list[str] = []
    while True:
        try:
            line = input("    > ")
        except EOFError:
            if lines:
                break
            raise WeakRSAError("No lab values received")
        if line.strip().upper() == "END" or (not line.strip() and lines):
            break
        if line.strip():
            lines.append(line)
    return parse_fields("\n".join(lines), mode, line_order)


def parse_exponents(raw: str) -> list[int]:
    """Accept a comma-separated list of RSA public exponents."""
    try:
        values = [number(item) for item in raw.split(",")]
    except ValueError as ex:
        raise argparse.ArgumentTypeError(str(ex)) from ex
    if not values or any(x < 2 for x in values):
        raise argparse.ArgumentTypeError("provide exponents >= 2, e.g. 3,5,17")
    return list(dict.fromkeys(values))


def inspect_source(path: Path) -> None:
    """Show source-code indicators; not proof of a cryptographic weakness."""
    try:
        source = path.read_text("utf-8-sig")
    except (OSError, UnicodeError) as ex:
        raise WeakRSAError(f"Cannot read challenge source {path}: {ex}") from ex
    print(f"\n[+] Source indicators: {path}")
    clues = [
        ("Raw pow(..., e, n) RSA expressions", r"\bpow\s*\("),
        ("Multiple message variables", r"(?:message_fixed|message2|m2|ciphertext2|ct2)"),
        ("Difference between messages", r"(?:\bdifference\b|\bdelta\b|\bMessage\s*-\s*Message_fixed\b)"),
        ("RSA-OAEP (attack generally not applicable)", r"\bOAEP\b"),
    ]
    for label, pattern in clues:
        print(f"    {'[yes]' if re.search(pattern, source, re.I) else '[no] '} {label}")
    print("    This is heuristic code inspection, not proof of exploitability.")


def get_choice(cli: int | None, fields: dict[str, int], key: str,
               default: int | None = None) -> int | None:
    return cli if cli is not None else fields.get(key, default)


def make_b_candidates(args: argparse.Namespace, fields: dict[str, int],
                      a: int) -> list[int]:
    delta = get_choice(args.difference, fields, "difference")
    b = get_choice(args.b, fields, "b")
    if b is not None and delta is not None and a == 1 and b != -delta:
        raise WeakRSAError(
            f"Conflicting relations: b={b} but m1-m2={delta} implies b={-delta}."
        )
    if b is None and delta is not None:
        if a != 1:
            raise WeakRSAError(
                "m1-m2 alone determines b only for a=1; supply --b when a != 1"
            )
        b = -delta
    if args.search_b is None:
        if b is None:
            raise WeakRSAError(
                "Missing relation: supply --b, --difference, a 4-line "
                "output.txt, or --search-b."
            )
        return [b]
    start, stop = args.search_b
    if stop - start + 1 > args.max_attempts:
        raise WeakRSAError(f"Search would try {stop-start+1} offsets, exceeding --max-attempts; narrow --search-b")
    candidates = list(range(start, stop + 1))
    if b is not None and b not in candidates:
        candidates.insert(0, b)
    elif b is not None:
        candidates.remove(b)
        candidates.insert(0, b)
    return candidates


def make_a_candidates(args: argparse.Namespace, fields: dict[str, int]) -> list[int]:
    a = get_choice(args.a, fields, "a", 1)
    if args.search_a is None:
        return [a]
    start, stop = args.search_a
    if stop - start + 1 > args.max_attempts:
        raise WeakRSAError(f"Search would try {stop-start+1} multipliers, exceeding --max-attempts; narrow --search-a")
    candidates = list(range(start, stop + 1))
    if a in candidates:
        candidates.remove(a)
    candidates.insert(0, a)
    return candidates


def matches_filters(recovery: Recovery, prefix: str | None,
                    contains: str | None) -> bool:
    messages = (as_bytes(recovery.m1), as_bytes(recovery.m2))
    if prefix and not any(msg.startswith(prefix.encode()) for msg in messages):
        return False
    if contains and not any(contains.encode() in msg for msg in messages):
        return False
    return True


def diagnostic(data: RSAInput, as_list: list[int], bs: list[int]) -> None:
    print("\n[+] Identification report")
    print(f"    Public modulus: {data.n.bit_length()} bits")
    print(f"    Public exponent: {data.e}")
    print("    Ciphertexts:      two values with one public (n,e) supplied")
    if data.difference is not None:
        print(f"    Known m1 - m2:   {data.difference}")
    print(f"    Candidate a:     {len(as_list)} value(s)")
    print(f"    Candidate b:     {len(bs)} value(s)" if bs else
          "    Candidate b:     unknown (need --b, --difference, or --search-b)")
    print("    Likely family:   Textbook RSA related-message / Franklin-Reiter")
    print("    Validation:      recovery must pass TWO RSA re-encryption checks")
    print("    Caveat:          source code must confirm raw RSA without OAEP padding")


def print_recovery(data: RSAInput, result: Recovery, show_hex: bool) -> list[str]:
    one, two = as_bytes(result.m1), as_bytes(result.m2)
    flags = list(dict.fromkeys(flag_candidates(one) + flag_candidates(two)))
    print("\n[+] RECOVERY SUCCESSFUL")
    print(f"    Method:         {result.method}")
    print(f"    Relation:       m2 = ({result.a})*m1 + ({result.b}) mod n")
    print("    Verification:   PASSED (both ciphertexts re-encrypted correctly)")
    print(f"    Message 1:      {readable(one)}")
    print(f"    Message 2:      {readable(two)}")
    if show_hex:
        print(f"    Message 1 hex:  {one.hex()}")
        print(f"    Message 2 hex:  {two.hex()}")
    for flag in flags:
        print(f"\n[FLAG] {flag}")
    if not flags:
        print("[!] No ASCII flag pattern automatically detected; inspect plaintexts")
    return flags


def export_result(data: RSAInput, result: Recovery,
                  flags: list[str], save_dir: Path | None,
                  json_out: Path | None) -> None:
    one, two = as_bytes(result.m1), as_bytes(result.m2)
    metadata: dict[str, Any] = {
        "developer": __author__, "tool": "weak_rsa.py", "version": __version__,
        "attack": result.method, "verified": True,
        "public_key": {"n": str(data.n), "e": data.e},
        "ciphertexts": {"c1": str(data.c1), "c2": str(data.c2)},
        "relation": {"a": result.a, "b": result.b, "m1_minus_m2": str(result.m1 - result.m2)},
        "message1": {"decimal": str(result.m1), "hex": one.hex(), "text": readable(one)},
        "message2": {"decimal": str(result.m2), "hex": two.hex(), "text": readable(two)},
        "flags": flags,
        "note": "Big-endian integer conversion cannot reconstruct unspecified leading zero bytes.",
    }
    if save_dir is not None:
        save_dir.mkdir(parents=True, exist_ok=True)
        (save_dir / "message1.bin").write_bytes(one)
        (save_dir / "message2.bin").write_bytes(two)
        (save_dir / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
        print(f"[+] Wrote plaintexts and result.json to {save_dir}")
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(metadata, indent=2) + "\n")
        print(f"[+] Wrote JSON report to {json_out}")


def self_test() -> None:
    """Deterministic internal correctness tests, no third-party packages."""
    print("[+] Running built-in tests")
    p, q = (2**127 - 1), (2**61 - 1)  # known Mersenne primes
    n = p * q
    cases = [
        (3, 1, 7, 123456789),
        (5, 7, 1337, 987654321),
        (17, 1, -3, 123456789012345678901),
        (17, 2, 37, 998877665544332211),
    ]
    for e, a, b, m1 in cases:
        m2 = (a * m1 + b) % n
        data = RSAInput(pow(m1, e, n), pow(m2, e, n), n, e)
        result = recover(data, a, b)
        if (result.m1, result.m2) != (m1, m2):
            raise WeakRSAError(f"Self-test failed for e={e}, a={a}, b={b}")
        print(f"    [PASS] e={e}, a={a}, b={b}")
    assert number("0x11") == 17
    assert parse_range("10") == (-10, 10)
    assert parse_range("-2:3") == (-2, 3)
    assert parse_exponents("3,5,17") == [3, 5, 17]
    assert parse_fields("12 34 56", "auto", "c1,c2,difference,n") == {
        "c1": 12, "c2": 34, "n": 56
    }
    assert parse_fields("1 2 -3 97 17", "auto", "c1,c2,difference,n") == {
        "c1": 1, "c2": 2, "difference": -3, "n": 97, "e": 17
    }
    assert parse_fields('''{"c1":"12","c2":"34","n":"97","difference":"-3"}''',
                        "auto", "c1,c2,difference,n")["difference"] == -3
    assert as_bytes(int.from_bytes(b"academy{test}", "big")) == b"academy{test}"
    print("[+] All built-in tests passed")


def create_parser() -> argparse.ArgumentParser:
    examples = """EXAMPLES (run from the challenge directory):
  python3 weak_rsa.py                         # one command (file or prompt)
  python3 weak_rsa.py --interactive           # paste/enter lab data
  python3 weak_rsa.py --help
  python3 weak_rsa.py -f output.txt
  python3 weak_rsa.py -f output.txt --identify
  python3 weak_rsa.py -f output.txt --prefix 'academy{' --save recovered
  python3 weak_rsa.py -f lab.txt -e 5 --a 7 --b 1337
  python3 weak_rsa.py -f lab.txt -e 3 --search-b=10
  python3 weak_rsa.py -f lab.txt -e 3 --search-b=-5:10
  cat output.txt | python3 weak_rsa.py --paste
  python3 weak_rsa.py --data '12 34' -n 55 --b 3
  python3 weak_rsa.py -f lab.txt --search-e 3,5,17 --search-b 8
  python3 weak_rsa.py --inspect-source chall.py
  python3 weak_rsa.py -f lab.txt --line-order c1,c2,n,difference
  python3 weak_rsa.py --c1 123 --c2 456 -n 789 -e 3 --b 1
  python3 weak_rsa.py --self-test

ATTACK: c1 = m1^e mod n; c2 = m2^e mod n; m2 = a*m1 + b (mod n)
        In 4-line picoCTF input: line 3 is m1 - m2, so b = -line3.
        In particular, m1 - m2 = -3 means b = +3.

LIMITS: This is NOT a general RSA cracker. Needs same RSA (n,e), raw
        unpadded textbook RSA, known/small affine relation, and manageable e.
"""
    parser = argparse.ArgumentParser(
        prog="weak_rsa.py",
        description="k4n0ng | Weak RSA Related-Messages Cryptanalysis Toolkit",
        epilog=examples,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file_pos", nargs="?", metavar="INPUT_FILE",
                        help="Optional positional file, e.g. python3 weak_rsa.py output.txt")
    parser.add_argument("-f", "--file", default=None, metavar="FILE",
                        help="Ciphertext input (default: output.txt); '-' reads stdin")
    parser.add_argument("-i", "--interactive", action="store_true",
                        help="Ask for ciphertexts, modulus, relation, and exponent")
    parser.add_argument("--paste", action="store_true",
                        help="Read lab data from standard input; for piping or Ctrl-D paste")
    parser.add_argument("--data", metavar="TEXT",
                        help="Supply all lab data as one quoted string")
    parser.add_argument("--inspect-source", type=Path, metavar="CHALL.PY",
                        help="Show source-code indicators of textbook related-message RSA")
    parser.add_argument("--input-format", choices=["auto", "lines", "labeled", "json"],
                        default="auto", help="File format (default: auto)")
    parser.add_argument("--line-order", default="c1,c2,difference,n",
                        help="Order of unlabeled integer fields (default: c1,c2,difference,n)")
    parser.add_argument("--c1", type=number, help="First ciphertext, decimal or 0xhex")
    parser.add_argument("--c2", type=number, help="Second ciphertext, decimal or 0xhex")
    parser.add_argument("-n", "--modulus", type=number, help="RSA modulus n")
    parser.add_argument("-e", "--exponent", type=number,
                        help=f"Public exponent e (default {DEFAULT_E}, unless in input)")
    parser.add_argument("--search-e", type=parse_exponents, metavar="E1,E2,...",
                        help="Try multiple small RSA exponents, e.g. 3,5,17")
    parser.add_argument("--a", type=number, help="Affine multiplier a (default 1)")
    parser.add_argument("--b", type=number, help="Affine offset b in m2=a*m1+b mod n")
    parser.add_argument("--difference", "--delta", type=number,
                        help="Known plaintext difference m1 - m2 (NOT m2 - m1)")
    parser.add_argument("--search-b", type=parse_range, metavar="R|MIN:MAX",
                        help="Search offsets -R..R or MIN..MAX (inclusive)")
    parser.add_argument("--search-a", type=parse_range, metavar="MIN:MAX",
                        help="Search small affine multipliers; also includes default a=1")
    parser.add_argument("--prefix", help="Require either plaintext to begin with this text")
    parser.add_argument("--contains", help="Require either plaintext to contain this text")
    parser.add_argument("--save", type=Path, metavar="DIR",
                        help="Write message1.bin, message2.bin and result.json")
    parser.add_argument("--json-out", type=Path, metavar="FILE",
                        help="Write machine-readable verified result JSON")
    parser.add_argument("--show-hex", action="store_true", help="Print plaintexts as hex")
    parser.add_argument("--all", action="store_true",
                        help="Display multiple verified recoveries instead of stopping at first")
    parser.add_argument("--max-results", type=int, default=10,
                        help="Maximum displayed recoveries when --all (default 10)")
    parser.add_argument("--identify", action="store_true",
                        help="Analyze structure without executing the attack")
    parser.add_argument("--verbose", action="store_true", help="Print polynomial GCD degrees")
    parser.add_argument("--max-exponent", type=int, default=DEFAULT_MAX_E,
                        help=f"Safety limit for exponent e (default {DEFAULT_MAX_E})")
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS,
                        help=f"Safety limit for (a,b) combinations (default {DEFAULT_MAX_ATTEMPTS})")
    parser.add_argument("--self-test", action="store_true", help="Run built-in deterministic checks")
    parser.add_argument("--version", action="version",
                        version=f"k4n0ng weak_rsa.py {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    print(f"\n{'=' * 62}\n  k4n0ng | WEAK RSA CRYPTANALYSIS TOOLKIT\n"
          f"  Franklin-Reiter | Standalone Python | Offline CTF\n{'=' * 62}")
    try:
        if args.self_test:
            self_test()
            return 0
        if args.max_attempts < 1 or args.max_exponent < 2 or args.max_results < 1:
            raise WeakRSAError("--max-attempts and --max-results must be >= 1; --max-exponent >= 2")
        if args.all and args.json_out is not None:
            raise WeakRSAError("--all and --json-out cannot be combined; use --save DIR")
        if args.file is not None and args.file_pos is not None:
            raise WeakRSAError("Choose either positional INPUT_FILE or -f FILE, not both")
        if sum(bool(x) for x in (args.data is not None, args.paste, args.interactive)) > 1:
            raise WeakRSAError("Choose only one of --data, --paste, and --interactive")
        if args.inspect_source is not None:
            inspect_source(args.inspect_source)

        # The no-argument command tries output.txt; if absent, guide the
        # student interactively instead of throwing an unhelpful FileNotFoundError.
        filename = args.file if args.file is not None else args.file_pos
        cli_complete = all(x is not None for x in (args.c1, args.c2, args.modulus))
        if args.data is not None:
            fields = parse_fields(args.data, args.input_format, args.line_order)
        elif args.paste:
            if sys.stdin.isatty():
                print("[?] Paste lab input; finish with Ctrl-D (Linux/macOS).")
            fields = read_fields("-", args.input_format, args.line_order)
        elif args.interactive:
            if not sys.stdin.isatty():
                raise WeakRSAError("--interactive requires a terminal. Pipe with --paste instead")
            fields = interactive_fields(args.input_format, args.line_order)
        elif filename is not None:
            fields = read_fields(filename, args.input_format, args.line_order)
        elif cli_complete:
            fields = {}
        elif Path("output.txt").is_file():
            print("[+] Automatically loading ./output.txt")
            fields = read_fields("output.txt", args.input_format, args.line_order)
        elif sys.stdin.isatty():
            if args.inspect_source is not None:
                print("[+] Source inspection complete (no ciphertext supplied)")
                return 0
            fields = interactive_fields(args.input_format, args.line_order)
        else:
            if args.inspect_source is not None:
                print("[+] Source inspection complete (no ciphertext supplied)")
                return 0
            raise WeakRSAError(
                "No output.txt found and no RSA values provided. Use -f FILE, "
                "--data TEXT, --paste, or --c1/--c2/-n; run --help for examples."
            )

        c1 = get_choice(args.c1, fields, "c1")
        c2 = get_choice(args.c2, fields, "c2")
        n = get_choice(args.modulus, fields, "n")
        e = get_choice(args.exponent, fields, "e", DEFAULT_E)
        missing = [label for label, value in (("c1", c1), ("c2", c2), ("n", n))
                   if value is None]
        if missing:
            raise WeakRSAError(f"Missing required fields: {', '.join(missing)}")
        if n < 3 or not (0 <= c1 < n and 0 <= c2 < n):
            raise WeakRSAError("Invalid RSA data: require n>=3 and 0<=c1,c2<n")
        exponents = [e] + [x for x in (args.search_e or []) if x != e]
        if any(x < 2 or x > args.max_exponent for x in exponents):
            raise WeakRSAError(
                f"Candidate exponent exceeds supported bounds 2..{args.max_exponent}. "
                "Polynomials of large degree may be impractically expensive."
            )

        delta = get_choice(args.difference, fields, "difference")
        data = RSAInput(c1, c2, n, e, delta)
        a_candidates = make_a_candidates(args, fields)
        if len(a_candidates) > 1 and delta is not None and get_choice(args.b, fields, "b") is None:
            raise WeakRSAError(
                "A plain m1-m2 difference describes a=1. To search other a "
                "values, supply an explicit --b and omit the difference field."
            )
        if args.identify:
            try:
                b_candidates = make_b_candidates(args, fields, a_candidates[0])
            except WeakRSAError as ex:
                if "Missing relation" not in str(ex):
                    raise
                b_candidates = []
        else:
            b_candidates = make_b_candidates(args, fields, a_candidates[0])
        total = len(exponents) * len(a_candidates) * len(b_candidates)
        if total > args.max_attempts:
            raise WeakRSAError(
                f"Search would try {total} combinations (limit {args.max_attempts}). "
                "Narrow --search-e/--search-a/--search-b or adjust --max-attempts."
            )
        print(f"[+] RSA modulus: {n.bit_length()} bits | exponent(s): {', '.join(map(str, exponents))}")
        print(f"[+] Candidate affine relations: {len(a_candidates) * len(b_candidates)}")
        print(f"[+] Maximum attack attempts: {total}")
        if args.identify:
            diagnostic(data, a_candidates, b_candidates)
            return 0

        last_error: str = "No candidate satisfied the required relation"
        attempted = 0
        found = 0
        seen: set[tuple[int, int]] = set()
        for candidate_e in exponents:
            candidate_data = RSAInput(c1, c2, n, candidate_e, delta)
            for a in a_candidates:
                for b in b_candidates:
                    attempted += 1
                    if args.verbose:
                        print(f"[*] Attempt {attempted}/{total}: e={candidate_e}, a={a}, b={b}")
                    try:
                        result = recover(candidate_data, a, b, verbose=args.verbose)
                        if not matches_filters(result, args.prefix, args.contains):
                            last_error = "Recovered plaintext did not match --prefix/--contains"
                            continue
                    except WeakRSAError as ex:
                        last_error = str(ex)
                        continue
                    if (result.m1, result.m2) in seen:
                        continue
                    seen.add((result.m1, result.m2))
                    flags = print_recovery(candidate_data, result, args.show_hex)
                    # For --all, give each separate result a separate export directory.
                    save_path = (args.save / f"candidate_{found+1:03d}"
                                 if args.all and args.save else args.save)
                    json_path = (args.json_out if not args.all else None)
                    export_result(candidate_data, result, flags, save_path, json_path)
                    found += 1
                    if not args.all or found >= args.max_results:
                        print(f"[+] Attempts: {attempted}/{total} | verified matches: {found}")
                        return 0
        if found:
            print(f"[+] Attempts: {attempted}/{total} | verified matches: {found}")
            return 0
        raise WeakRSAError(
            f"No verified plaintext after {attempted} attempt(s). "
            f"Last issue: {last_error}. Check e, input order, a, b, and padding."
        )
    except (WeakRSAError, OSError, UnicodeError, ValueError) as ex:
        print(f"[-] {ex}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
