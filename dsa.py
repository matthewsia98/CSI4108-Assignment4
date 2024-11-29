import hashlib
import random
import json
import os
import sys


sys.version_info >= (3, 8) or sys.exit("Python 3.8+ is required.")


random.seed(0)


# REFERENCE: Stalling Page 403-406


# 2. [1.5 marks] Implement DSA. Using a 1024-bit prime p and an appropriate 160-bit
# prime q with generator g of the q-order subgroup of Zp*, choose a signature key pair
# (x, y), an appropriate value k, and the hash function SHA-1. You may use any library
# or toolkit to find p and q and to call SHA-1, but implement the rest of DSA yourself.
# Sign the message m = 582346829057612 using the privacy key x. Verify the
# signature using the public key y.


# 3. [1 mark] With your implementation from question #2, sign the message m =
# 8061474912583 using the same value of k. Show that an observer of the two
# signatures will be able to completely compromise security.


def htoi(h: str) -> int:
    return int(h.replace(" ", ""), 16)


def generate_keys() -> dict[str, dict[str, int]]:
    # There are three parameters that are public and can be common to a group of users.
    # A 160-bit prime number q is chosen.
    # Next, a prime number p is selected with a length between 512 and 1024 bits
    # such that q divides (p - 1).
    # Finally, g is chosen to be of the form h^((p - 1)/q) mod p, where h is an
    # integer between 1 and (p - 1) with the restriction that g must be greater than 1.

    # REFERENCE: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/DSA2_All.pdf
    p = htoi(
        "E0A67598 CD1B763B"
        "C98C8ABB 333E5DDA 0CD3AA0E 5E1FB5BA 8A7B4EAB C10BA338"
        "FAE06DD4 B90FDA70 D7CF0CB0 C638BE33 41BEC0AF 8A7330A3"
        "307DED22 99A0EE60 6DF03517 7A239C34 A912C202 AA5F83B9"
        "C4A7CF02 35B5316B FC6EFB9A 24841125 8B30B839 AF172440"
        "F3256305 6CB67A86 1158DDD9 0E6A894C 72A5BBEF 9E286C6B"
    )
    q = htoi("E950511E AB424B9A 19A2AEB4 E159B784 4C589C4F")
    g = htoi(
        "D29D5121 B0423C27"
        "69AB2184 3E5A3240 FF19CACC 792264E3 BB6BE4F7 8EDD1B15"
        "C4DFF7F1 D905431F 0AB16790 E1F773B5 CE01C804 E509066A"
        "9919F519 5F4ABC58 189FD9FF 987389CB 5BEDF21B 4DAB4F8B"
        "76A055FF E2770988 FE2EC2DE 11AD9221 9F0B3518 69AC24DA"
        "3D7BA870 11A701CE 8EE7BFE4 9486ED45 27B7186C A4610A75"
    )
    h = htoi("0002")

    # With these numbers in hand, each user selects a private key and generates a public key.
    # The private key x must be a number from 1 to (q - 1) and should be chosen randomly or pseudorandomly.
    x = random.randint(1, q - 1)
    # The public key is calculated from the private key as y = g^x mod p.
    y = pow(g, x, p)

    return {"public": {"p": p, "q": q, "g": g, "y": y}, "private": {"x": x}}


def dsa_sign(
    keys: dict[str, dict[str, int]], M: bytes, k: int | None = None
) -> tuple[int, tuple[int, int]]:
    p, q, g, y = keys["public"].values()
    x = keys["private"]["x"]

    # To create a signature, a user calculates two quantities, r and s,
    # that are functions of the public key components (p, q, g),
    # the user's private key (x),
    # the hash code of the message H(M),
    # and an additional integer k that should be generated randomly or pseudorandomly and be unique for each signing.
    k = k or random.randint(1, q - 1)

    # r = (g^k mod p) mod q
    r = pow(g, k, p) % q
    # s = [k^-1 * (H(M) + xr)] mod q
    h_m = int.from_bytes(hashlib.sha1(M).digest())
    s = (pow(k, -1, q) * (h_m + x * r)) % q

    return k, (r, s)


def dsa_verify(
    keys: dict[str, dict[str, int]], M: bytes, signature: tuple[int, int]
) -> int:
    p, q, g, y = keys["public"].values()
    r, s = signature

    # At the receiving end, verification is performed using the formulas shown.
    # The receiver generates a quantity v that is a function of the public key components,
    # the sender's public key,
    # and the hash code of the incoming message.
    # If this quantity matches the r component of the signature, then the signature is validated.

    # w = s^-1 mod q
    w = pow(s, -1, q)

    # u1 = [H(M)w] mod q
    u1 = (int.from_bytes(hashlib.sha1(M).digest()) * w) % q

    # u2 = rw mod q
    u2 = (r * w) % q

    # v = [(g^u1 * y^u2) mod p] mod q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

    return v


if __name__ == "__main__":
    print()

    keys = generate_keys()
    print("keys =", json.dumps(keys, indent=4))
    print()

    print("=" * os.get_terminal_size().columns)
    print()

    m1 = 582346829057612
    m1_bytes = int.to_bytes(m1, 8)
    print(f"{m1 = }")
    print()

    k1, sig1 = dsa_sign(keys, m1_bytes)
    print(f"{k1 = }")
    print()
    print(f"{sig1 = }")
    print()

    r1, s1 = sig1
    v1 = dsa_verify(keys, m1_bytes, (r1, s1))
    print(f"{v1 = }")
    print()
    assert v1 == r1

    print("=" * os.get_terminal_size().columns)
    print()

    m2 = 8061474912583
    m2_bytes = int.to_bytes(m2, 8)
    print(f"{m2 = }")
    print()

    k2, sig2 = dsa_sign(keys, m2_bytes, k1)
    print(f"{k2 = }")
    print()
    print(f"{sig2 = }")
    print()

    r2, s2 = sig2
    v2 = dsa_verify(keys, m2_bytes, (r2, s2))
    print(f"{v2 = }")
    print()
    assert v2 == r2

    print("=" * os.get_terminal_size().columns)
    print()

    # When the same k is reused for signing two different messages, r1 = r2
    assert r1 == r2

    # We have equations
    #   s1 = k^-1 * (H(m1) + xr) mod q
    #   s2 = k^-1 * (H(m2) + xr) mod q
    # We can solve for k
    #   (k * s1) - (k * s2) = H(m1) - H(m2) mod q
    #   k = (H(m1) - H(m2)) / (s1 - s2) mod q
    p, q, g, y = keys["public"].values()
    hm1 = int.from_bytes(hashlib.sha1(m1_bytes).digest())
    hm2 = int.from_bytes(hashlib.sha1(m2_bytes).digest())
    k = ((hm1 - hm2) * pow(s1 - s2, -1, q)) % q
    print(f"{k = }")
    print()
    # Once k is computed, the private key x can be derived from either signature
    #   x1 = ((s1 * k) - H(m1)) / r1 mod q or
    #   x2 = ((s2 * k) - H(m2)) / r2 mod q
    x1 = (((s1 * k) - hm1) * pow(r1, -1, q)) % q
    print(f"{x1 = }")
    print()
    x2 = (((s2 * k) - hm2) * pow(r2, -1, q)) % q
    print(f"{x2 = }")
    print()
    x = keys["private"]["x"]
    assert x == x1 == x2
