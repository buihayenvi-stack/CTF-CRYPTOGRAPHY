#!/usr/bin/env python3
"""
Demo tích hợp 3 challenge:
 1) Reused XOR keystream (crib-dragging demo)
 2) RSA attacks:
     - Cube root attack (textbook RSA, e = 3)
     - Fermat factorization (weak primes)
     - Coppersmith: placeholder + explanation (needs SageMath)
 3) Padding oracle demo (Paddown) - simplified local demo using a vulnerable service

Chạy: python demo_ctf_challenges.py
"""
from __future__ import annotations
import binascii
import math
import random
import sys

# -------------------------
# Utils
# -------------------------
def hexify(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def integer_nthroot(x: int, n: int):
    """Return (root, exact) where root = floor(x**(1/n)) and exact True if root**n == x.
    Pure Python integer nth root via binary search.
    """
    if x < 0:
        raise ValueError("negative")
    if x == 0:
        return (0, True)
    lo, hi = 1, 1 << ((x.bit_length() + n - 1) // n + 1)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        p = pow(mid, n)
        if p == x:
            return (mid, True)
        if p < x:
            lo = mid
        else:
            hi = mid
    return (lo, pow(lo, n) == x)

# -------------------------
# 1) Reused XOR keystream
# -------------------------
def demo_reused_xor():
    print("\n" + "="*60)
    print("1) Reused XOR keystream (crib-dragging demo)")
    print("="*60 + "\n")

    key = b'supersecretkeystream'  # WARNING: reused key -> vulnerable
    messages = [
        b'The password is: swordfish',
        b'Contact admin at: admin@example.com',
        b'Today is a sunny day',
    ]
    cts = [strxor(m, key) for m in messages]
    print("Ciphertexts (hex):")
    for i, ct in enumerate(cts):
        print(f"ct{i+1}: {hexify(ct)}")

    # XOR of ct1 and ct2 cancels key -> p1 ^ p2
    x = strxor(cts[0], cts[1])
    print("\nct1 ^ ct2 (hex):", hexify(x))

    # Suppose we guess start of message2 ("Contact admin at: ")
    guess = b'Contact admin at: '
    recovered = strxor(x[:len(guess)], guess)
    print("\nCrib-guessing demo:")
    print("Guess for start of message2:", guess)
    print("Recovered start of message1:", recovered)
    print("\nNotes:")
    print("- Khi keystream được tái sử dụng trong stream cipher/XOR, ct1 ^ ct2 = p1 ^ p2.")
    print("- Từ p1 ^ p2 có thể thử 'cribs' (từ/cụm từ phổ biến) để phục hồi plaintext.")


# -------------------------
# 2) RSA attacks
# -------------------------
# Sample (toy) data (như trong challenge)
N_cube = 32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123930386017358561357722606590881485368019786079970631431826013503651109330042280712669114707894822093419346390932977456644021951065222954004833857494691216455623974016355439963640097631214074322761166716682375158526932596852989277804180699980320057816909302957737609582153067553939928285055050284319797898055421319756611
e_cube = 3
ciphertext_list = [300763, 592704, 343000, 1860867, 1030301, 1728000, 912673, 1295029,
                   1404928, 1259712, 1030301, 857375, 1061208, 1259712, 912673, 1092727,
                   857375, 1061208, 1367631, 1481544, 857375, 970299, 1601613, 941192,
                   1030301, 857375, 1481544, 1367631, 1367631, 1560896, 1953125]

def cube_root_attack(ciphertexts, e=3):
    """For textbook RSA where m^e < N, ciphertext = m^e, so integer nth root recovers m."""
    plaintexts = []
    for c in ciphertexts:
        root, exact = integer_nthroot(c, e)
        if exact:
            plaintexts.append(root)
        else:
            raise ValueError(f"Cannot compute exact {e}-th root for c={c}")
    return plaintexts

def decode_flag_from_ints(ints):
    """If the ints are small bytes (toy), try to convert to bytes for a human-readable flag."""
    # In this demo ciphertext_list are small ints representing small bytes; pack them:
    try:
        b = bytes(int(x) & 0xFF for x in ints)
        return b.decode('ascii', errors='replace')
    except Exception as e:
        return f"[decode error: {e}]"

def fermat_factor(N, max_iters=10_000_000):
    """Simple Fermat factorization - works when p and q are close."""
    a = math.isqrt(N)
    if a*a < N:
        a += 1
    it = 0
    while it < max_iters:
        b2 = a*a - N
        if b2 >= 0:
            b = math.isqrt(b2)
            if b*b == b2:
                return (a - b, a + b)
        a += 1
        it += 1
    return (None, None)

def demo_rsa_attacks():
    print("\n" + "="*60)
    print("2) RSA attacks: cube-root (textbook), Fermat demo, Coppersmith note")
    print("="*60 + "\n")

    # Cube-root demo
    print("-> Cube-root attack (textbook RSA, e=3):")
    try:
        plaintext_ints = cube_root_attack(ciphertext_list, e_cube)
        print("Recovered integers (m):", plaintext_ints[:20], "...")
        decoded = decode_flag_from_ints(plaintext_ints)
        print("Decoded (toy) bytes ->", decoded)
    except Exception as ex:
        print("Cube-root attack failed:", ex)

    # Fermat demo (use a small, intentionally weak N for demonstration)
    print("\n-> Fermat factorization demo (may be slow for huge N).")
    # For demo, construct a weak N by selecting two close primes:
    p = 10007
    q = 10009
    demoN = p * q
    print(f"Demo weak N = p*q with p={p}, q={q}, N={demoN}")
    rec_p, rec_q = fermat_factor(demoN, max_iters=1000000)
    if rec_p and rec_q:
        print(f"Fermat recovered p={rec_p}, q={rec_q}")
    else:
        print("Fermat failed (increase max_iters or N not weak).")

    # Coppersmith note
    print("\n-> Coppersmith (partial key exposure) - NOTE:")
    print("- Full Coppersmith requires lattice algorithms (LLL) and is easiest with SageMath.")
    print("- In practice one uses Sage's small_roots or custom LLL to find small roots of polynomial mod N.")
    print("- Here we leave a placeholder: you need Sage to run full Coppersmith examples.")

# -------------------------
# 3) Padding oracle demo (Paddown)
# -------------------------
# We'll implement a local VulnerableEncryptionService that raises on invalid padding.
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

class InvalidPadding(Exception):
    pass

class VulnerableEncryptionService:
    """Service encrypts with AES-CBC and on decrypt raises InvalidPadding for bad PKCS7 padding.
       This simulates a padding oracle that leaks padding validity.
    """
    def __init__(self):
        # 16-byte key and IV (toy demo)
        self.key = b"deadbeeffeedface"  # secret
        self.iv = b"FEDCBA9876543210"   # known IV (in many protocols IV is public)
    def encrypt(self, plaintext: bytes) -> bytes:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("PyCryptodome not available")
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        return self.iv + cipher.encrypt(pad(plaintext, 16))
    def decrypt_and_check(self, ciphertext: bytes) -> bool:
        """Returns True if padding valid, False otherwise (oracle)."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("PyCryptodome not available")
        # assume first 16 bytes are IV (we keep a fixed IV for simplicity)
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        try:
            unpad(cipher.decrypt(ct), 16)
            return True
        except ValueError:
            return False

class SimplePaddown:
    """Simplified Paddown: brute-force padding oracle attack for 1 block (educational).
       This is NOT optimized; for demo and clarity.
    """
    def __init__(self, oracle: VulnerableEncryptionService, blocksize=16):
        self.oracle = oracle
        self.blocksize = blocksize

    def decrypt_single_block(self, iv: bytes, ct_block: bytes) -> bytes:
        """Given IV and one ciphertext block, recover plaintext block using padding oracle."""
        assert len(iv) == self.blocksize
        assert len(ct_block) == self.blocksize
        # We will craft C' such that Oracle(C' || C_i) tells us padding validity.
        c_prime = bytearray(b"\x00" * self.blocksize)
        intermediate = bytearray(b"\x00" * self.blocksize)
        recovered = bytearray(b"\x00" * self.blocksize)

        # Work from last byte to first
        for pos in range(1, self.blocksize + 1):
            pad_val = pos
            # set previously found bytes to match desired padding
            for j in range(1, pos):
                c_prime[-j] = intermediate[-j] ^ pad_val
            # brute force current byte
            found = False
            for guess in range(256):
                c_prime[-pos] = guess
                # send c_prime || ct_block to oracle
                combined = bytes(c_prime) + bytes(ct_block)
                try:
                    ok = self.oracle.decrypt_and_check(combined)
                except RuntimeError:
                    raise RuntimeError("Crypto library not available for padding demo")
                if ok:
                    # compute intermediate byte
                    intermediate_byte = guess ^ pad_val
                    intermediate[-pos] = intermediate_byte
                    recovered_byte = intermediate_byte ^ iv[-pos]
                    recovered[-pos] = recovered_byte
                    found = True
                    break
            if not found:
                raise RuntimeError("No valid padding byte found (unexpected in this demo)")
        return bytes(recovered)

def demo_padding_oracle():
    print("\n" + "="*60)
    print("3) Padding Oracle demo (local Paddown simplified)")
    print("="*60 + "\n")
    if not CRYPTO_AVAILABLE:
        print("PyCryptodome not installed. To run this demo install it:")
        print("  python -m pip install pycryptodome")
        print("Skipping padding oracle demo.")
        return

    svc = VulnerableEncryptionService()
    secret_message = b"CTF{padding_oracle_demo}"
    ct = svc.encrypt(secret_message)
    print("Encrypted secret (hex):", hexify(ct))

    # Split IV and first ciphertext block
    iv = ct[:16]
    first_block = ct[16:32]
    paddown = SimplePaddown(svc, blocksize=16)
    recovered = paddown.decrypt_single_block(iv, first_block)
    print("Recovered first plaintext block (bytes):", recovered)
    # the full plaintext requires chaining for multi-block; this is a one-block demo
    print("Note: This simplified demo recovers one block using the oracle.")


# -------------------------
# Main runner
# -------------------------
def main():
    print("="*80)
    print("CTF Challenges Integrated Demo")
    print(" - 1: Reused XOR keystream")
    print(" - 2: RSA (cube-root, Fermat, Coppersmith note)")
    print(" - 3: Padding-oracle (local simplified demo)")
    print("="*80)
    demo_reused_xor()
    demo_rsa_attacks()
    demo_padding_oracle()

if __name__ == "__main__":
    main()
