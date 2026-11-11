# CTF Weak LFSR / XOR Solver


**Developer:** `k4n0ng`  

**Requires:** Python 3.9+; standard library only (no pip install).

`script.py` is a parameterized brute-force solver for CTFs based on **small linear feedback shift registers** and byte-XOR or bit-XOR keystreams. It also tries single-byte XOR.



---


### Download:
````shell
wget -O weak_xor.py "https://raw.githubusercontent.com/Nin-Kanong/CTF-Scripts/main/02.%20Cryptography/03.%20Linear%20Feedback%20Shift%20Register%20%28LFSR%29/weak_xor.py"
````

---


## Identify
````
30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9
````


In this if script give us script like ``script.py`` and it content:
````py
key = bytes_to_long(get_random_bytes(126))
````
This creates a large key. But look at the next important line:
````
lfsr = key & 0xFF
````

````mermaid
flowchart TD
    %% Input
    A["🔑 <b>Original Key</b><br/>1008 bits (126 bytes)"]
    
    %% The flaw
    B["⚠️ <b>Vulnerability</b><br/>Only the lowest 8 bits are retained"]
    
    %% Result
    C["🔓 <b>Effective Initial State</b><br/>8 bits (256 possible states)"]
    
    %% Conclusion
    D["❌ <b>Weak Cipher</b><br/>Brute-forceable in seconds"]

    %% Connections
    A --> B
    B --> C
    C --> D

    %% Styling
    classDef key fill:#3b82f6,stroke:#1e3a8a,stroke-width:2px,color:#fff;
    classDef flaw fill:#ef4444,stroke:#991b1b,stroke-width:2px,color:#fff;
    classDef state fill:#f59e0b,stroke:#b45309,stroke-width:2px,color:#fff;
    classDef weak fill:#64748b,stroke:#334155,stroke-width:2px,color:#fff;

    class A key;
    class B flaw;
    class C state;
    class D weak;
````



Next, the encryption performs:
````py
output.append(p ^ ks)
````


### Identify other common XOR attacks

**Single-byte XOR:**
````py
key = 42ciphertext = bytes(p ^ key for p in plaintext)
````
**Detection**: One byte is reused for every character. Try all 256 possible keys.


**Repeating-key XOR**:
````
key = b"SECRET"ciphertext = bytes(    p ^ key[i % len(key)]    for i, p in enumerate(plaintext))
````
**Detection**: The key cycles repeatedly. Known-plaintext attacks or frequency analysis may recover it.


**Weak LFSR XOR**:
````
lfsr = key & 0xFFfor p in plaintext:    lfsr = steplfsr(lfsr)    ciphertext.append(p ^ lfsr)
````
**Detection**: An 8-bit initial state generates the keystream. Brute-force all initial states.


---

## Start immediately

Put `script.py` and the CTF-provided `output.txt` in the same directory, then run:

```bash
python3 script.py
```

We can pass the ciphertext in these ways:

```bash
python3 script.py                    # automatically reads ./output.txt
python3 script.py output.txt
python3 script.py -f output.txt
python3 script.py -c 30cbb50e507774fdafd01e0bfdbc38d5eadf92991cdd347064e37444e517d661cea9
cat output.txt | python3 script.py -  # read from stdin
```


---


## Capabilities

| Feature | Usage | Requirements and limits |
| --- | --- | --- |
| Single-byte XOR search | `--mode single-byte` | Tries 256 keys |
| Repeating-key XOR, known key | `--mode repeating --key ICE` or `--key-hex 494345` | Explicit key |
| Repeating-key XOR, unknown key | `--mode repeating --key-size 3` or `--max-key-size 20` | Statistical guesses; short flags benefit from known prefix |
| Small LFSR brute force | `--mode state` or `--mode bit` | Default 8-bit; known taps, direction, and output model |
| Wide LFSR known seed | `--width 64 --seed 0x... --taps ...` | Exact model parameters |
| GF(2) seed recovery | `--attack linear --crib 'known plaintext'` | Correct taps, enough independent known bits |
| Berlekamp–Massey | `--mode bit --attack bm --prefix 'long known prefix'` | Linear bitstream and contiguous known prefix at byte zero |
| Unknown small-register taps | `--tap-search 1-4` | Combinatorial; search/memory guardrails |
| Conventional output variants | `--auto`, `--direction`, `--emit`, `--bit-order` | Limited known conventions, not arbitrary generators |
| File conversion and filtering | `--format`, `--prefix`, `--regex`, `--json`, `--save` | Ranking is heuristic |


## Useful options


## Ciphertext input formats

For a hex ciphertext in `output.txt`:

```bash
python3 weak_xor.py -f output.txt --prefix 'academy{'
```

For *raw binary* data:

```bash
python3 weak_xor.py -f encrypted.bin --format raw --mode single-byte
```

For base64 text:

```bash
python3 weak_xor.py -f encrypted.b64 --format base64 --mode repeating
```

From stdin:

```bash
cat output.txt | python3 weak_xor.py -f -
```

By default `--format auto` detects valid hex, and otherwise treats the input as raw bytes. It does **not** automatically decode base64; specify `--format base64`.

## 8-bit LFSR variants and tap search

```bash
python3 weak_xor.py -f samples/01_8bit_state.txt --prefix 'academy{'
python3 weak_xor.py -f samples/02_8bit_bit.txt --mode bit --prefix 'academy{'
python3 weak_xor.py -f output.txt --mode auto --auto --prefix 'flag{'
python3 weak_xor.py -f output.txt --tap-search 1-4 --prefix 'academy{'
```

`--mode auto` tries multiple families; `--auto` tries multiple register direction and emission conventions. They are two different switches.

## 32-bit LFSR, unknown seed, known plaintext

```bash
python3 weak_xor.py -f samples/05_32bit_state_linear.txt \
  --width 32 --taps 31,21,1,0 --attack linear \
  --prefix 'I know this first part of the plaintext, but NOT'
```

You can instead specify known text at an arbitrary byte offset:

```bash
python3 weak_xor.py -f output.txt --width 32 --taps 31,21,1,0 \
  --mode bit --attack linear --crib 'some known text' --offset 12
```

This technique uses GF(2) linear algebra to solve register-state equations. When constraints do not uniquely specify the initial state, `free_bits` and `unique` indicate that several seeds are possible. More known plaintext or assumptions may be needed.

## Linear bitstream recovery without taps

```bash
python3 weak_xor.py -f samples/06_16bit_bm.txt \
  --mode bit --attack bm \
  --prefix 'This is a known and lengthy prefix!'
```

Berlekamp–Massey fits a minimal binary linear recurrence to the known keystream bits. It can predict future bits **if the observed stream really follows that recurrence**. Short known sequences can overfit; confirm the results.

## Single-byte and repeating-key XOR

```bash
python3 weak_xor.py -f samples/03_single_byte.txt --mode single-byte --prefix 'flag{'
python3 weak_xor.py -f samples/04_repeating_key.txt --mode repeating --key-size 3 --prefix 'flag{'
python3 weak_xor.py -f output.txt --mode repeating --max-key-size 25 --top 15
python3 weak_xor.py -f output.txt --mode repeating --key ICE
```

A sufficiently long known prefix can reveal all bytes of a short repeating XOR key. Without it, candidate ranking is statistical and may fail, particularly on short challenge flags.



### Use with .bin
````
python3 weak_xor.py -f encrypted.bin --format raw --mode repeating --key-size 4 --prefix 'THM{'
````


---

## How to translate CTF source into options

| CTF program characteristic | Option |
| --- | --- |
| `state = key & 0xff` | `--width 8` |
| `b7 ^ b5 ^ b4 ^ b3` | `--taps 7,5,4,3` |
| `(feedback << 7) \| (state >> 1)` | `--direction right` |
| `(state << 1) \| feedback` | `--direction left` |
| update register, *then* use state as keystream | `--emit after --mode state` |
| use state, *then* update | `--emit before --mode state` |
| one output bit per register step | `--mode bit` |
| output bit is least significant bit | `--bit-index 0` |
| a register is initially advanced several steps | `--skip N` |
| output is in hex | `--format hex` (or `auto`) |

**Limitations:** This is a family-specific brute-force tool, not a solver for every cipher, polynomial, or CTF. It does not automatically solve non-linear feedback generators, AES, RSA, arbitrary repeated-XOR key lengths, or large LFSR state spaces. If the plaintext is compressed or encrypted in another layer, you may need to adapt it. The ``--auto`` mode is heuristic, not an exhaustive search across all possible designs. For larger state spaces, linear-algebra reconstruction from known plaintext is usually preferable.
