import dsa
import json


# 4. [1.5 marks] Samantha’s DSA public parameters are (p, q, g) = (103687, 1571,
# 21947), and her public verification key is A = 31377. Employ whatever method you
# prefer to solve the discrete log problem and find Samantha’s private signing key (but
# show in detail what method you chose). Sign the document D = 610 with Samantha’s
# key, using the random element k = 1305.


def discrete_log(y: int, g: int, p: int) -> int | None:
    # y = g^x mod p
    for x in range(1, p):
        if pow(g, x, p) == y:
            return x
    return None


if __name__ == "__main__":
    print()

    (p, q, g, y) = (103687, 1571, 21947, 31377)

    # We know that y = g^x mod p
    # So x is the discrete log of y to the base g mod p
    x = discrete_log(y, g, p)
    assert x is not None and pow(g, x, p) == y
    print(f"{x = }")
    print()

    keys = {"public": {"p": p, "q": q, "g": g, "y": y}, "private": {"x": x}}
    print("keys =", json.dumps(keys, indent=4))
    print()

    D = 610
    D_bytes = int.to_bytes(D, 8)
    print(f"{D = }")
    print()

    k = 1305
    print(f"{k = }")
    print()

    _, sig = dsa.dsa_sign(keys, D_bytes, k)
    print(f"{sig = }")
    print()
