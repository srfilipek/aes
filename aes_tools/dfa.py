import click
import numpy as np
import phoenixAES

from . import ops


def _filter(f):
    """Reject all lines, except those that are 16-byte HEX strings
    """
    for line in f:
        try:
            data = bytearray.fromhex(line.strip())
        except ValueError:
            continue

        if len(data) == 16:
            yield data


def stream(f, verbose=False):
    """DFA a file stream
    """
    # For phoenixAES: 1 = Normal, 2 = Verbose
    verbose = 1 + int(verbose)

    filtered_input = _filter(f)
    ref = next(filtered_input)

    skey = phoenixAES.crack_bytes(filtered_input, ref, verbose=verbose)
    skey = np.array(bytearray.fromhex(skey))

    return ops.derive_key(skey, 40)
