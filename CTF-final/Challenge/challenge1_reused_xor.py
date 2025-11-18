
import binascii

def strxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def hexify(b: bytes) -> str:
    return binascii.hexlify(b).decode()

if __name__ == '__main__':
    key = b'supersecretkeystream'  # WARN: reused key (vulnerable)
    messages = [
        b'The password is: swordfish',
        b'Contact admin at: admin@example.com',
        b'Today is a sunny day',
    ]
    cts = [strxor(m, key) for m in messages]
    print("=== Challenge 2: Reused XOR keystream ===\n")
    print("Ciphertexts (hex):")
    for i, ct in enumerate(cts):
        print(f"ct{i+1}: {hexify(ct)}")
    print("\nIf you XOR ct1 and ct2, key cancels out. This gives p1 ^ p2 which can be attacked using known-plaintext guesses.")

    # Demo: recover part of message1 by guessing part of message2
    x = strxor(cts[0], cts[1])
    print("\nct1 ^ ct2 (hex):", hexify(x))
    # If we guess a substring of message2 we can recover substring of message1.
    guess = b'Contact admin at: '
    recovered = strxor(x[:len(guess)], guess)
    print("If guess for start of message2 is:", guess)
    print("Recovered start of message1:", recovered)
    print("\nExercise: use frequency, word guesses, or crib-dragging to fully recover messages.")