# CTF Weak LFSR / XOR Solver

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


## Useful options

### Current challenge: known parameters

```bash
python3 script.py -f output.txt --width 8 --taps 7,5,4,3 --direction right --emit after --mode state --prefix 'academy{'
```

### Initial state or output mechanism unknown

```bash
python3 script.py -f output.txt --mode auto --auto
```

This checks state-as-byte, bit-output, and single-byte XOR. For the LFSR configurations, it tries shift directions and output before or after the update; for bit-output it also tries bit ordering and end bit selection.

### Unknown feedback tap positions, but four taps in an 8-bit LFSR

```bash
python3 script.py -f output.txt --tap-search 4 --width 8 --prefix 'academy{'
```

### Unknown count of feedback taps (one through four)

```bash
python3 script.py -f output.txt --tap-search 1-4 --width 8 --prefix 'academy{'
```

### 12-bit LFSR, and keystream taken from bits 4..11

```bash
python3 script.py -f output.txt --width 12 --taps 11,8,6,2 --byte-offset 4
```

### Bit-output LFSR

```bash
python3 script.py -f output.txt --mode bit --width 8 --taps 7,5,4,3 --bit-index 7 --bit-order msb
```

### One-byte XOR key used for all bytes

```bash
python3 script.py -f output.txt --mode single-byte
```

### Ciphertext is a raw binary file

```bash
python3 script.py -f encrypted.bin --format raw
```

### Filter by a known plaintext / flag prefix

```bash
python3 script.py -f output.txt --prefix 'picoCTF{'
python3 script.py -f output.txt --contains 'admin'
python3 script.py -f output.txt --crib 'CTF{' --offset 4
python3 script.py -f output.txt --regex 'academy\\{.*\\}'
```

### Export best candidate as raw bytes / machine-readable JSON

```bash
python3 script.py -f output.txt --save recovered.bin
python3 script.py -f output.txt --json --top 5
```

### See *all* plaintext candidates (including non-printable ones)

```bash
python3 script.py -f output.txt --all --top 0
```

### Get all options

```bash
python3 script.py --help
```

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
