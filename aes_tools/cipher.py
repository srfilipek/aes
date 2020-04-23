from __future__ import division
import binascii
import unittest

import numpy as np

from . import ops


KEY_LEN_TO_ROUNDS = {
    16: 10,  # 128-bit
    24: 12,  # 192-bit
    32: 14,  # 256-bit
}


class State(object):
    """Dummy object to quickly hold and build up AES intermediate state
    """
    start = None
    s_box = None
    s_row = None
    m_col = None
    k_sch = None
    out = None
    fout = None


def encrypt_explicit(inb, key, Nr=10, Nb=4):
    """Encrypt the given block with the given key.

    Returns:
        Array of State objects

    The returned  array of State objects allows for inspection of intermediate
    state of the AES encryption operation.

    To get the output, use res[-1].fout
    """
    if len(inb) != 4 * Nb:
        raise ValueError("Invalid input block length: %d" % (len(inb),))

    w = ops.key_expansion(key, Nr, Nb)

    tracker = []
    tracker.append(State())
    tracker[0].start = state = inb.reshape(4, Nb).T
    tracker[0].k_sch = w[:Nb].T
    tracker[0].out = state = ops.add_round_key(state, w[:Nb].T)

    for r in range(1, Nr):
        tracker.append(State())
        tracker[r].start = state
        tracker[r].s_box = state = ops.sub_bytes(state)
        tracker[r].s_row = state = ops.shift_rows(state)
        tracker[r].m_col = state = ops.mix_columns(state)
        tracker[r].k_sch = w[r * Nb: (r + 1) * Nb].T
        tracker[r].out = state = \
            ops.add_round_key(state, w[r * Nb: (r + 1) * Nb].T)
        tracker[r].fout = state.T.reshape(16,)

    tracker.append(State())
    tracker[Nr].start = state
    tracker[Nr].s_box = state = ops.sub_bytes(state)
    tracker[Nr].s_row = state = ops.shift_rows(state)
    tracker[Nr].k_sch = w[Nr*Nb:(Nr+1)*Nb].T
    tracker[Nr].out = state = ops.add_round_key(state, w[Nr*Nb:(Nr+1)*Nb].T)
    tracker[Nr].fout = state.T.reshape(16,)

    return tracker


def _get_rounds(key):
    rounds = KEY_LEN_TO_ROUNDS.get(len(key), None)
    if rounds is None:
        raise ValueError("Invalid key length: %d" % (len(key),))
    return rounds


def encrypt(inb, key):
    rounds = _get_rounds(key)
    return encrypt_explicit(inb, key, rounds)[-1].fout


def decrypt(inb, key):
    rounds = _get_rounds(key)
    return decrypt_explicit(inb, key, rounds)[-1].fout
