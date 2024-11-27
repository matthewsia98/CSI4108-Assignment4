from __future__ import annotations

import hashlib
import hmac


# 1. [1 mark] Implement HMAC-SHA-512. You may use any library or toolkit to call
# SHA-512, but implement the rest of HMAC yourself. Compute the HMAC of the
# following string: “I am using this input string to test my own implementation of
# HMAC-SHA-512.” Once that is completed, use any library or toolkit to call
# HMAC-SHA-512 on this string to confirm that your implementation is correct.


def my_hmac(K: bytes, M: bytes) -> hashlib._Hash:
    # REFERENCE: Stallings Page 377-378
    # H = embedded hash function (e.g., MD5, SHA-1, RIPEMD-160)
    # IV = initial value input to hash function
    # M = message input to HMAC (including the padding specified in the embedded hash function)
    # Y_i = i-th block of M, 0 <= i <= (L – 1)
    # L = number of blocks in M
    # b = number of bits in a block
    # n = length of hash code produced by embedded hash function
    # K = secret key; recommended length is >= n; if key length is greater than b,
    #     the key is input to the hash function to produce an n-bit key
    # K+ = K padded with zeros on the left so that the result is b bits in length
    # ipad = 00110110 (36 in hexadecimal) repeated b/8 times
    # opad = 01011100 (5C in hexadecimal) repeated b/8 times
    # Then HMAC can be expressed as
    # HMAC(K, M) = H[(K+ XOR opad) || H[(K+ XOR ipad) || M]]

    # RERERENCE: https://www.ietf.org/rfc/rfc4868.txt
    b = 1024  # HMAC-SHA-512 block size in bits
    B = b // 8  # block size in bytes
    ipad = b"\x36" * B
    opad = b"\x5C" * B

    # 1. Append zeros to the left end of K to create a b-bit string K+ (e.g.,
    # if K is of length 160 bits and b = 512, then K will be appended with 44 zeroes).
    if len(K) > B:
        K_plus = hashlib.sha512(K).digest().ljust(B, b"\x00")
    else:
        K_plus = K.ljust(B, b"\x00")

    # 2. XOR (bitwise exclusive-OR) K+ with ipad to produce the b-bit block S_i.
    S_i = bytes(x ^ y for x, y in zip(K_plus, ipad))

    # 3. Append M to S_i.
    H1_in = S_i + M

    # 4. Apply H to the stream generated in step 3.
    H1_out = hashlib.sha512(H1_in).digest()

    # 5. XOR K+ with opad to produce the b-bit block S_o.
    S_o = bytes(x ^ y for x, y in zip(K_plus, opad))

    # 6. Append the hash result from step 4 to S_o.
    H2_in = S_o + H1_out

    # 7. Apply H to the stream generated in step 6 and output the result.
    H2_out = hashlib.sha512(H2_in)

    return H2_out


if __name__ == "__main__":
    print()

    key = "This is my super secret HMAC-SHA-512 key"
    key_bytes = key.encode()
    print(f"{key = }")
    print()

    message = (
        "I am using this input string to test my own implementation of HMAC-SHA-512"
    )
    message_bytes = message.encode()
    print(f"{message = }")
    print()

    my_h = my_hmac(key_bytes, message_bytes).hexdigest()
    print(f"{my_h  = }")
    print()

    ref_h = hmac.new(key_bytes, message_bytes, hashlib.sha512).hexdigest()
    print(f"{ref_h = }")
    print()

    assert my_h == ref_h
