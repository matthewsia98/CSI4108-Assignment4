import hashlib
import random
import json
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


def dsa_sign(keys: dict[str, dict[str, int]], M: bytes) -> tuple[int, int]:
    p, q, g, y = keys["public"].values()
    x = keys["private"]["x"]

    # To create a signature, a user calculates two quantities, r and s,
    # that are functions of the public key components (p, q, g),
    # the user's private key (x),
    # the hash code of the message H(M),
    # and an additional integer k that should be generated randomly or pseudorandomly and be unique for each signing.
    k = random.randint(1, q - 1)
    print(f"{k = }")
    print()

    # r = (g^k mod p) mod q
    r = pow(g, k, p) % q
    # s = [k^(-1) * (H(M) + xr)] mod q
    h_m = int.from_bytes(hashlib.sha1(M).digest())
    s = (pow(k, -1, q) * (h_m + x * r)) % q

    return (r, s)


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

    # w = s^(-1) mod q
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

    m = 58234682905761
    m_bytes = int.to_bytes(m, 8)
    print(f"{m = }")
    print()

    keys = generate_keys()
    print("keys =", json.dumps(keys, indent=4))
    print()

    signature = dsa_sign(keys, m_bytes)
    print(f"{signature = }")
    print()

    r, s = signature
    v = dsa_verify(keys, m_bytes, signature)
    print(f"{v = }")
    print()
    assert v == r
