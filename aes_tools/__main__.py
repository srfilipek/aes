import binascii

import click
import numpy as np
import signal

from . import __version__
from . import ops
from . import dfa


@click.group('aes-tools')
@click.version_option(version=__version__, message='%(prog)s %(version)s')
def cli():
    """AES Tools"""


@cli.command('derive', short_help='Derive the AES key from a subkey')
@click.option('--skey', type=str, help='Subkey (ASCII hex)')
@click.option('--offset', type=int, help='Subkey 32-bit word offset')
def derive(skey, offset):
    skey = np.array(bytearray.fromhex(skey.replace(' ', '')))

    key = ops.derive_key(skey, offset)

    print("Derived key: {key}".format(key=binascii.hexlify(key.data)))


@cli.command('dfa', short_help='Perform DFA against corrupted ciphertexts')
@click.option('-f', '--filename', required=True, type=str, help='File path')
@click.option('-p', '--pause', is_flag=True, help='Pause upon completion')
@click.option('-v', '--verbose', is_flag=True, help='Verbose DFA status')
def dfa_file(filename, pause, verbose):
    with open(filename, 'r') as f:
        aes_key = dfa.stream(f, verbose)

    click.secho("\nAES (not-so-)secret key:", bold=True)
    click.secho(bytearray(aes_key).hex(), fg="bright_red", bold=True)

    if pause:
        signal.pause()


if __name__ == "__main__":
    cli(prog_name='aes-tools')
