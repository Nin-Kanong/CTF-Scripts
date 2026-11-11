# Weak RSA — Franklin–Reiter Related-Message Attack

**Developer:** [k4n0ng](https://github.com/Nin-Kanong)  
**Project:** [CTF-Scripts](https://github.com/Nin-Kanong/CTF-Scripts)  
**Script:** `weak_rsa.py` | **Version:** 2.0.0 | **Python:** 3.10+  
**Category:** Cryptography / RSA / CTF

A **single-file, offline, dependency-free Python toolkit** for demonstrating and exploiting the **Franklin–Reiter related-message weakness in textbook (unpadded) RSA**. It recovers two plaintexts encrypted with the **same RSA public key** when they follow a known affine relation, or a relation that can be found within a **small, bounded search**.

> **Scope:** This is **not** a universal RSA cracker. It does not break properly randomized RSA-OAEP and does not recover arbitrary, unrelated RSA messages.

## 1. Vulnerability: what is weak?

The attack is named **Franklin–Reiter Related-Message Attack**, a form of **related-message cryptanalysis against textbook RSA**. The issue is encrypting mathematically related messages **without secure randomized padding**, under the **same** modulus `n` and public exponent `e`.

```python
c1 = pow(m1, e, n)
c2 = pow(m2, e, n)
# Known relationship: m2 = a*m1 + b (mod n)
```

The public exponent may be small enough for practical polynomial computations (for instance `3`, `5`, or `17` in CTFs).

The attack constructs polynomials over `Z/nZ`:

```text
f(x) = x^e - c1

g(x) = (a*x+b)^e - c2
```

A **linear polynomial GCD** can reveal `m1`; the tool then derives `m2` and **verifies both by RSA re-encryption**. If a polynomial division finds a coefficient with no modular inverse, the program can sometimes extract an RSA factor and try a fallback.

### What kinds of weakness can this script handle?

| Weakness / case | Supported? | Notes |
|---|---|---|
| **Franklin–Reiter related-message RSA** | ✅ | Primary attack; two unpadded RSA ciphertexts, same `(n,e)` |
| **Known plaintext difference** | ✅ | `m1 - m2 = delta`; set `--difference delta` |
| **Known affine relation** | ✅ | `m2 = a*m1 + b (mod n)`; set `--a` and `--b` |
| **Small unknown additive offset** | ✅ | Search a limited `b` range using `--search-b` |
| **Small unknown affine multiplier** | ✅ | Search a limited `a` range using `--search-a` |
| **Unknown exponent from a short candidate list** | ✅ | `--search-e 3,5,17` |
| **Occasional factor leak from non-invertible coefficient** | ⚠️ | Only in special polynomial-GCD failure cases |
| **General factorization / common-modulus attack** | ❌ | Different weaknesses, not a general RSA toolbox |
| **Håstad broadcast, Wiener's attack, Boneh–Durfee** | ❌ | Need dedicated methods |
| **RSA-OAEP / appropriately randomized padding** | ❌ | This related-message attack does not apply in the same way |
| **Weak XOR / LFSR** | ❌ | Different cryptographic algorithm |

## 2. Download `weak_rsa.py` (Kali Linux)

**GitHub source:** [Open weak_rsa.py](https://github.com/Nin-Kanong/CTF-Scripts/blob/main/02.%20Cryptography/04.%20Weak%20RSA/weak_rsa.py)

Use `wget` (copy the entire command):

```bash
wget -O weak_rsa.py "https://raw.githubusercontent.com/Nin-Kanong/CTF-Scripts/main/02.%20Cryptography/04.%20Weak%20RSA/weak_rsa.py"
```

Or use `curl`:

```bash
curl -fL "https://raw.githubusercontent.com/Nin-Kanong/CTF-Scripts/main/02.%20Cryptography/04.%20Weak%20RSA/weak_rsa.py" -o weak_rsa.py
```

Then check and run:

```bash
python3 --version
python3 weak_rsa.py --help
python3 weak_rsa.py --self-test
python3 weak_rsa.py -f output.txt
```

**Requires:** Python 3.10+; no `pip install` needed. If you prefer your browser, open the GitHub source link, select **Raw**, and save as `weak_rsa.py`.

## 3. Quick start: one-line commands

Put the script next to your challenge's `output.txt`, or specify the path with `-f`.

```bash
python3 weak_rsa.py                              # auto-load ./output.txt or prompt
python3 weak_rsa.py -f output.txt                # file input
python3 weak_rsa.py --interactive                # paste/enter challenge values
python3 weak_rsa.py --help                       # full command reference
python3 weak_rsa.py --self-test                  # built-in tests
```

For the picoCTF **Related Messages** example, `output.txt` contains **four large integers**:

```text
line 1: c1 = encrypted original message
line 2: c2 = encrypted corrected message
line 3: difference = m1 - m2 (e.g. -3)
line 4: n = RSA modulus
```

**Important sign convention:** `m1 - m2 = -3` means `m2 = m1 + 3` (that is, `b = 3`). In this challenge, the public exponent is `e = 17`, which is also the script's default. For other labs, set the **actual** exponent.

**Verified sample result:**

```text
[+] RSA modulus: 2048 bits | exponent(s): 17
[+] Candidate affine relations: 1
[+] RECOVERY SUCCESSFUL
    Method:         Franklin-Reiter polynomial GCD
    Relation:       m2 = (1)*m1 + (3) mod n
    Verification:   PASSED (both ciphertexts re-encrypted correctly)
    Message 1:      academy{m3ssage_w1th_typ0z
    Message 2:      academy{m3ssage_w1th_typ0}
[FLAG] academy{m3ssage_w1th_typ0}
```

## 4. Command reference

| Task | Command |
|---|---|
| Full help | `python3 weak_rsa.py --help` |
| Version | `python3 weak_rsa.py --version` |
| Interactive values | `python3 weak_rsa.py -i` |
| Specify input file | `python3 weak_rsa.py -f lab.txt` |
| Inspect challenge source heuristically | `python3 weak_rsa.py --inspect-source chall.py` |
| Identify parameters without attacking | `python3 weak_rsa.py -f lab.txt --identify` |
| Change exponent | `python3 weak_rsa.py -f lab.txt -e 5` |
| Known additive offset `m2=m1+7` | `python3 weak_rsa.py -f lab.txt -e 3 --b 7` |
| Known difference `m1-m2=-3` | `python3 weak_rsa.py -f lab.txt --difference=-3` |
| Known affine relation `m2=7*m1+1337` | `python3 weak_rsa.py -f lab.txt -e 5 --a 7 --b 1337` |
| Search offsets from `-10` to `10` | `python3 weak_rsa.py -f lab.txt -e 3 --search-b 10` |
| Search offsets from `-5` to `20` | `python3 weak_rsa.py -f lab.txt -e 3 --search-b=-5:20` |
| Search small affine multipliers | `python3 weak_rsa.py -f lab.txt -e 5 --search-a 2:7 --b 1337` |
| Try small public exponents | `python3 weak_rsa.py -f lab.txt --search-e 3,5,17` |
| Filter by flag prefix | `python3 weak_rsa.py -f output.txt --prefix 'academy{'` |
| Filter by substring | `python3 weak_rsa.py -f output.txt --contains 'academy{'` |
| Display plaintext bytes as hex | `python3 weak_rsa.py -f output.txt --show-hex` |
| Save binary plaintexts + JSON | `python3 weak_rsa.py -f output.txt --save recovered` |
| Export machine-readable JSON | `python3 weak_rsa.py -f output.txt --json-out result.json` |
| Show polynomial-GCD progress | `python3 weak_rsa.py -f output.txt --verbose` |
| Display multiple verified candidates | `python3 weak_rsa.py -f lab.txt --all --max-results 10` |
| Run deterministic built-in tests | `python3 weak_rsa.py --self-test` |

### Enter challenge parameters manually, without a file

```bash
python3 weak_rsa.py --interactive
```

Choose to **paste the lab output** or **enter the RSA values one by one**. You can also pass the values on the command line:

```bash
python3 weak_rsa.py --c1 <CIPHERTEXT_1> --c2 <CIPHERTEXT_2> -n <MODULUS> -e 17 --b 3
```

The placeholders above are instructions: replace `<...>` with decimal or `0x` hexadecimal integers; don't type the literal angle brackets. Another convenient way to pipe values is:

```bash
cat output.txt | python3 weak_rsa.py --paste
```

## 5. Accepted input formats

### A. Unlabeled text (picoCTF-style)

```text
CIPHERTEXT_1
CIPHERTEXT_2
-3
MODULUS
```

Each uppercase item represents a number from the challenge. The default order is `c1,c2,difference,n`. For a different order:

```bash
python3 weak_rsa.py -f lab.txt --line-order c1,c2,n,difference
```

### B. Labeled text

```text
c1 = 123456789
c2 = 987654321
n = 1122334455
e = 17
difference = -3
```

These example numbers illustrate formatting only; they are **not** a valid recoverable RSA instance. Use your lab's values.

### C. JSON

```json
{
  "c1": "123456789",
  "c2": "987654321",
  "n": "1122334455",
  "e": 17,
  "a": 1,
  "b": 3
}
```

Run:

```bash
python3 weak_rsa.py -f challenge.json --input-format json
```

## 6. Practical limits

- **Same key required:** Both ciphertexts must use the same `(n, e)`.
- **Textbook RSA required:** Randomized OAEP padding defeats this specific mathematical relationship in the usual setting.
- **Affine relation required:** The solver is specialized for `m2 = a*m1 + b (mod n)` and bounded searches for its parameters.
- **Small or manageable exponent:** It defaults to a maximum exponent of **128**. RSA exponent `65537` is typically unsuitable for this direct polynomial method.
- **Limited brute-force range:** It defaults to at most **5,000 candidate `(a,b)` combinations**; customize `--max-attempts` carefully.
- **No guarantee:** A non-linear GCD, invalid data, different RSA keys, or a missing usable relation can prevent plaintext recovery.
- **Verification matters:** A successful recovery is checked using `pow(m1, e, n) == c1` and `pow(m2, e, n) == c2`.

## 7. Troubleshooting

| Symptom | What to check |
|---|---|
| `output.txt` not found | Run in the challenge directory or give an absolute path via `-f` |
| No verified message | Check `c1`, `c2`, `n`, exponent, relation sign, and whether RSA is padded |
| Wrong difference sign | `--difference` means **m1 minus m2**, while `--b` means **m2 minus a*m1** |
| Search exceeds limit | Narrow ranges or increase `--max-attempts` after reviewing cost |
| RSA exponent rejected | Inspect `--max-exponent`; very large exponents may be computationally impractical |
| Need to inspect supported arguments | Run `python3 weak_rsa.py --help` |

## 8. GitHub layout

```text
CTF-Scripts/
└── 02. Cryptography/
    └── 04. Weak RSA/
        ├── weak_rsa.py
        └── README.md
```

**Suggested commit message:** `Document k4n0ng Weak RSA Franklin-Reiter toolkit`

## 9. References

- [Franklin–Reiter related-message attack / Low-Exponent RSA with Related Messages](https://users.ece.cmu.edu/~reiter/papers/1996/Eurocrypt.pdf)
- [Dan Boneh — Twenty Years of Attacks on the RSA Cryptosystem](https://crypto.stanford.edu/~dabo/papers/RSA-survey.pdf)

---

**Developer:** k4n0ng · For authorized CTF, educational and security-research use.
