import sys
from typing import Optional, TextIO

import click

from .cipher import Cipher

# make help available at -h as well as default --help
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


ALIASES = {
    "d": "dec",
    "decrypt": "dec",
    "e": "enc",
    "encrypt": "enc",
}


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        try:
            cmd_name = ALIASES[cmd_name].name
        except KeyError:
            pass
        return super().get_command(ctx, cmd_name)


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option(package_name="vigenere-py")
def cli():
    """Vigenère cipher encryption for Python"""


@cli.command(name="enc")
@click.argument("input", type=click.File("r"), required=False)
@click.option(
    "-o",
    "--output",
    help="Output file",
    type=click.File("w")
)
@click.option(
    "-k",
    "--key-file",
    help="Key file",
    type=click.File("r")
)
@click.option(
    "-b",
    "--batch",
    help="Non-interactive mode",
    is_flag=True,
    default=False
)
def encrypt(
    input: Optional[TextIO],
    key_file: Optional[TextIO],
    output: Optional[TextIO],
    batch: bool,
):
    """
    Encrypt text with a Vigenère cipher.

    Read plaintext from INPUT file or from stdin if not provided.

    For example:

        vigenere enc -o out.txt input.txt

    """

    if not input:
        input = sys.stdin

    # If output is a TTY, highlight spaces in ANSI inverted colors
    if output:
        ansi_invert_spaces = False
    else:
        ansi_invert_spaces = sys.stdout.isatty()

    c = Cipher(key_file=key_file, batch=batch)

    if input.isatty():
        click.echo("Text to encrypt:", err=True)

    ciphertext = c.encrypt(input.read())

    if output:
        output.write(ciphertext)
    else:
        if input.isatty():
            click.echo("Ciphertext:", err=True)

        if ansi_invert_spaces:
            ciphertext = ciphertext.replace(" ", "\033[7m \033[27m")

        click.echo(ciphertext, nl=False)


@cli.command(name="dec")
@click.argument("input", type=click.File("r"), required=False)
@click.option(
    "-o",
    "--output",
    help="Output file",
    type=click.File("w")
)
@click.option(
    "-k",
    "--key-file",
    help="Key file",
    type=click.File("r")
)
@click.option(
    "-b",
    "--batch",
    help="Non-interactive mode",
    is_flag=True,
    default=False
)
def decrypt(
    input: Optional[TextIO],
    key_file: Optional[TextIO],
    output: Optional[TextIO],
    batch: bool,
):
    """Decrypt Vigenère ciphertext"""

    if not input:
        input = sys.stdin

    c = Cipher(key_file=key_file, batch=batch)

    plaintext = c.decrypt(input.read())

    if output:
        output.write(plaintext)
    else:
        click.echo(plaintext, nl=False)
