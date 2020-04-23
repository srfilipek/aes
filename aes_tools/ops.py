from __future__ import division

import numpy as np

from .constants import SBOX, INV_SBOX, RCON, GMUL, MIX_COLS


def rot_word(word, by=1):
    return np.append(word[by:], word[:by])


def sub_word(word):
    temp = np.array(word)
    for i in range(len(word)):
        temp[i] = SBOX[word[i]]
    return temp


def sub_word_inv(word):
    temp = np.array(word)
    for i in range(len(word)):
        temp[i] = INV_SBOX[word[i]]
    return temp


def rcon(i):
    return np.array((RCON[i], 0, 0, 0))


def key_expansion(key, Nr, Nb=4):
    """
    key : Input key as a numpy array
    Nr  : Number of cipher rounds
    """
    Nk = key.size // Nb  # Number of words in key
    if Nk not in (4, 6, 8):
        raise ValueError("Invalid key length")

    # Allocate
    w = np.zeros((Nb*(Nr+1), Nb), dtype=np.uint8)

    # Initialize
    w[:Nk] = key.reshape(Nk, Nb)

    # Create
    for i in range(Nk, w.shape[0]):
        temp = w[i-1]

        if (i % Nk) == 0:
            temp = sub_word(rot_word(temp)) ^ rcon(i // Nk)
        elif Nk > 6 and (i % Nk) == 4:
            temp = sub_word(temp)
        w[i] = w[i-Nk] ^ temp

    return w


def derive_key(sub_key, offset, Nb=4):
    """Derive the original key given a sub key.

    The sub_key must be the size of the encryption key (128, 192, or 256 bits).

    Args:
        sub_key: Input key as a numpy array, binary string, or bytearray
        offset: Offset into the key expansion array in 32-bit words (Nb bytes)
    """
    # Figure out key size based on input
    Nk = sub_key.size // Nb  # Number of words in key
    if Nk not in (4, 6, 8):
        raise ValueError("Invalid key length")

    # Allocate
    w = np.zeros((offset + Nk, Nb), dtype=np.uint8)

    # Initialize
    w[-Nk:] = sub_key.reshape((Nk, Nb))

    # Create
    for i in reversed(range(Nk, w.shape[0])):
        temp = w[i-1]

        if (i % Nk) == 0:
            temp = sub_word(rot_word(temp)) ^ rcon(i // Nk)
        elif Nk > 6 and (i % Nk) == 4:
            temp = sub_word(temp)
        w[i-Nk] = w[i] ^ temp

    return w[:Nk].reshape(Nk * Nb)


def add_round_key(state, key):
    """
    """
    return state ^ key


def sub_bytes(state):
    """
    """
    return np.array(
            list(map(lambda x: list(map(lambda y: SBOX[y], x)), state)),
            dtype=np.uint8)


def shift_rows(state):
    """
    """
    result = np.array(state)
    for i in range(1, 4):
        result[i] = rot_word(state[i], i)
    return result


def shift_rows_inv(state):
    """
    """
    result = np.array(state)
    for i in range(1, 4):
        result[i] = rot_word(state[i], -i)
    return result


def gmul(a, b):
    """
    Use for values of 'a' outside (1,2,3)
    """
    p = 0
    for counter in range(8):
        if (b & 1) == 1:
            p ^= a
        hi_bit_set = (a & 0x80)
        a <<= 1
        a &= 0xFF
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p


def mix_column(col):
    """
    """
    result = np.array(col)
    for i in range(len(col)):
        # Factor of ~10 speedup if we lookup instead of calculate
        result[i] = (
                GMUL[MIX_COLS[i, 0] - 1][col[0]] ^
                GMUL[MIX_COLS[i, 1] - 1][col[1]] ^
                GMUL[MIX_COLS[i, 2] - 1][col[2]] ^
                GMUL[MIX_COLS[i, 3] - 1][col[3]])
        # result[i] = gmul(coefs[i,0], col[0]) ^ gmul(coefs[i,1], col[1]) ^ \
        #            gmul(coefs[i,2], col[2]) ^ gmul(coefs[i,3], col[3])
    return result


def mix_columns(state):
    """
    """
    result = np.array(state.T)
    for col in range(result.shape[0]):
        result[col] = mix_column(result[col])
    return result.T
