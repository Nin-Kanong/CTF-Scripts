<h1 align="center"> Timestamp AES CTF Solver </h1>


A reusable Python 3 command-line and interactive tool for **authorized CTF challenges** that derive AES keys from guessable Unix timestamps.

## Requirements

- Python 3.10+ (for `str.removeprefix`)
- [`cryptography`](https://pypi.org/project/cryptography/)

On Kali Linux (inside a venv):

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install cryptography
python3 -c 'from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes; print("AES ready")'
```

> Note: Importing `AES` directly from `cryptography.hazmat.primitives.ciphers` is **not** correct; use `algorithms.AES`.

## Quick start

Put `timestamp.py` and `message.txt` in the same directory.

```bash
python3 timestamp.py --help
python3 timestamp.py                          # interactive, asks for inputs
python3 timestamp.py --file message.txt
python3 timestamp.py --file message.txt --window 3600
python3 timestamp.py --file message.txt --output flag.txt
```

Direct manual input:

```bash
python3 timestamp.py --time 1790147507 --ciphertext 6ef9b7a5c1c336425793f8cdae5b40ba536bf8768fc2db67a9c8f86b94a59db2
```

Read a noninteractive CTF service banner that provides public timestamp and ciphertext (no commands are sent):

```bash
python3 timestamp.py --host YOUR_AUTHORIZED_CTF_HOST --port 12345
```

Windows PowerShell:

```powershell
python .\timestamp.py --help
python .\timestamp.py --file .\message.txt
```

## Input file format

`message.txt` may contain:

```text
Hint: The encryption was done around 1790147507 UTC
Ciphertext (hex): 6ef9b7a5c1c336425793f8cdae5b40ba536bf8768fc2db67a9c8f86b94a59db2
```

Also recognizes `Timestamp:`, `Ciphertext:`, and `IV (hex):`. To use a file with only raw hex ciphertext, supply `--time` too.

## Options

| Option | Meaning |
|---|---|
| `--file PATH` | Read timestamp/ciphertext from text file |
| `--host HOST --port PORT` | Connect once to an authorized CTF service and read its banner |
| `--time UNIX` | Unix time in seconds or ISO 8601 time; overrides file/banner |
| `--ciphertext VALUE` | Hex or Base64 ciphertext; overrides file/banner |
| `--window 600` | Try timestamps ±600 seconds from the hint |
| `--step 1` | Timestamp search stride in seconds |
| `--hash sha256` | Key derivation hash (`sha256`, `sha1`, `sha512`, `md5`) |
| `--key-length 16` | AES key length in bytes (`16`, `24`, `32`) |
| `--time-format decimal` | Hash decimal timestamp text (default), or `little8` / `big8` binary timestamps |
| `--mode ecb` | AES ECB (default) or `cbc` |
| `--iv HEX` | Required for CBC when not in file |
| `--encoding auto` | Auto-detect ciphertext hex or base64 |
| `--prefix 'academy{'` | Recognize your challenge flag prefix; can be repeated |
| `--show-candidates` | Display up to five other printable valid-padding candidates |
| `--output flag.txt` | Save recovered plaintext |
| `--verbose` | Display progress during long searches |

## How the default attack works

For each timestamp `t` near the hint:

```python
key = sha256(str(t).encode()).digest()[:16]
plaintext = AES_ECB_decrypt(ciphertext, key)
plaintext = PKCS7_unpad(plaintext)
```

If valid padding and a known flag prefix appear, the solver shows the key, timestamp, and plaintext.

## When this does NOT work

- AES keys generated with secure randomness (rather than a predictable timestamp)
- Different key derivation methods not supported by the provided options
- Encrypted data using authenticated modes such as GCM
- CBC ciphertext without the correct IV
- Servers requiring an interactive login or handshake before sending values
- Ciphertexts that have padding conventions other than PKCS#7

## Test result

Using `timestamp_message_example.txt`, output includes:

```text
[+] Timestamp: 1790147507 (offset +0 seconds)
[+] Key (hex): 6d403a058418fe39105c422bb3c8e85e
[+] Decrypted: academy{sa3S_sEc9t_99162e4b}
```

## Security reminder

Use this tool only on CTF puzzles, local labs, and systems you are authorized to test. Real applications should use random keys and modern authenticated encryption, such as AES-GCM.
