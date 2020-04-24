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


class RoundState:
    """Dummy object to quickly hold and build up AES intermediate state
    """
    s_box = None
    s_row = None
    m_col = None
    k_sch = None
    add_k = None


class StateTracker:
    """Object to aid in keeping track of round states

    Attributes, other than append(), start, and result, are retreived from the
    latest round.

    Each round's RoundState object can be retreived by index lookup.
    """

    def __init__(self):
        self._rounds = []
        self.start = None
        self.result = None

    def new_round(self):
        self._rounds.append(RoundState())

    @property
    def round(self):
        """The latest round"""
        return self._rounds[-1]

    def __getitem__(self, i):
        return self._rounds[i]

    def __len__(self):
        return len(self._rounds)


def encrypt_explicit(inb, key, Nr=10, Nb=4):
    """Encrypt the given block with the given key.

    Returns:
        A StateTracker object

    The StateTracker contains an array of RoundState objects. This allows
    for inspection of intermediate state of the AES encryption operation.

    To get the output, use state_tracker.result
    """
    if len(inb) != 4 * Nb:
        raise ValueError("Invalid input block length: %d" % (len(inb),))

    t = StateTracker()
    w = ops.key_expansion(key, Nr, Nb)

    t.new_round()

    t.start = state = inb.reshape(4, Nb).T
    t.round.k_sch = w[:Nb].T
    t.round.add_k = state = ops.add_round_key(state, t.round.k_sch)

    for r in range(1, Nr):
        t.new_round()
        t.round.s_box = state = ops.sub_bytes(state)
        t.round.s_row = state = ops.shift_rows(state)
        t.round.m_col = state = ops.mix_columns(state)
        t.round.k_sch = w[r * Nb: (r + 1) * Nb].T
        t.round.add_k = state = ops.add_round_key(state, t.round.k_sch)

    t.new_round()
    t.round.s_box = state = ops.sub_bytes(state)
    t.round.s_row = state = ops.shift_rows(state)
    t.round.k_sch = w[Nr * Nb: (Nr + 1) * Nb].T
    t.round.add_k = state = ops.add_round_key(state, t.round.k_sch)

    t.result = state.T.reshape(16,)

    return t


def decrypt_explicit(inb, key, Nr=10, Nb=4):
    """Decrypt the given block with the given key.

    Returns:
        A StateTracker object

    The StateTracker contains an array of RoundState objects. This allows
    for inspection of intermediate state of the AES encryption operation.

    To get the output, use state_tracker.result
    """
    if len(inb) != 4 * Nb:
        raise ValueError("Invalid input block length: %d" % (len(inb),))

    w = ops.key_expansion(key, Nr, Nb)

    t = StateTracker()
    t.new_round()

    t.start = state = inb.reshape(4, Nb).T
    t.round.k_sch = w[Nr * Nb: (Nr + 1) * Nb].T
    t.round.add_k = state = ops.add_round_key(state, t.round.k_sch)
    t.round.s_row = state = ops.shift_rows_inv(state)
    t.round.s_box = state = ops.sub_bytes_inv(state)

    for r in reversed(range(1, Nr)):
        t.new_round()
        t.round.k_sch = w[r * Nb: (r + 1) * Nb].T
        t.round.add_k = state = ops.add_round_key(state, t.round.k_sch)
        t.round.m_col = state = ops.mix_columns_inv(state)
        t.round.s_row = state = ops.shift_rows_inv(state)
        t.round.s_box = state = ops.sub_bytes_inv(state)

    t.new_round()
    t.round.k_sch = w[:Nb].T
    t.round.add_k = state = ops.add_round_key(state, t.round.k_sch)

    t.result = state.T.reshape(16,)

    return t


def _num_rounds(key):
    rounds = KEY_LEN_TO_ROUNDS.get(len(key), None)
    if rounds is None:
        raise ValueError("Invalid key length: %d" % (len(key),))
    return rounds


def encrypt(inb, key):
    rounds = _num_rounds(key)
    return encrypt_explicit(inb, key, rounds).result


def decrypt(inb, key):
    rounds = _num_rounds(key)
    return decrypt_explicit(inb, key, rounds).result
