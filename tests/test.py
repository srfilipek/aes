from __future__ import division
import unittest
import numpy as np

from aes_tools.ops import key_expansion, derive_key
from aes_tools.cipher import encrypt, decrypt


class TestAes(unittest.TestCase):
    """Test AES operations
    """

    # Test vectors from FIPS-197
    # plaintext, key, ciphertext tuples
    AES_VECTORS = (
        (
            "00112233445566778899aabbccddeeff",
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "00112233445566778899aabbccddeeff",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "00112233445566778899aabbccddeeff",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    )

    def test_encrypt(self):
        for (p, k, c) in self.AES_VECTORS:
            pb = np.array(bytearray.fromhex(p))
            kb = np.array(bytearray.fromhex(k))
            cb = np.array(bytearray.fromhex(c))

            result = encrypt(pb, kb)
            self.assertEqual(cb.data, result.data)

    def test_decrypt(self):
        pass

    def test_derivation(self):
        for (p, k, c) in self.AES_VECTORS:
            kb = np.array(bytearray.fromhex(k))

            Nr, Nk = {
                16: (10, 4),
                24: (12, 6),
                32: (14, 8),
            }[len(kb)]

            key_sched = key_expansion(kb, Nr)

            # Slice the key schedule at word granularity and ensure we can
            # work backwords from any word offset
            for word_offset in range(0, key_sched.shape[0] - Nk + 1):
                start = word_offset
                end = start + Nk
                subkey = key_sched[start: end]
                k = derive_key(subkey, word_offset)

                self.assertEqual(k.data, kb.data)
