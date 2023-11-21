import csv
import sys
from typing import Optional, TextIO

import click
import strictyaml

from .alphabet import ALPHABETS, get_alphabet, list_alphabets_labels
from .cipher import Cipher
from .errors import CipherError

# make help available at -h as well as default --help
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


ALIASES = {
    "alpha": "alphabet",
    "d": "dec",
    "decrypt": "dec",
    "e": "enc",
    "encrypt": "enc",
    "genkey": "keygen",
}


class AliasedGroup(click.Group):
    # @typing.override  # python 3.12+
    def get_command(self, ctx: click.Context, cmd_name: str) -> Optional[click.Command]:
        if cmd_name in ALIASES:
            cmd_name = ALIASES[cmd_name]
        return super().get_command(ctx, cmd_name)


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.version_option(package_name="vigenere-py")
def cli() -> None:
    """Vigenère cipher encryption for Python"""


_alphabet_option = click.option(
    "-a",
    "--alphabet",
    type=click.Choice(list(ALPHABETS.keys())),
    default="printable",
)


@cli.command(name="enc")
@click.argument("input", type=click.File("r"), required=False)
@click.option("-o", "--output", help="Output file", type=click.File("w"))
@click.option("-k", "--key-file", help="Key file", type=click.File("r"))
@click.option("-b", "--batch", help="Non-interactive mode", is_flag=True, default=False)
@_alphabet_option
def encrypt(
    input: Optional[TextIO],
    key_file: Optional[TextIO],
    output: Optional[TextIO],
    alphabet: str,
    batch: bool,
) -> None:
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

    c = Cipher(key_file=key_file, batch=batch, alphabet_name=alphabet)

    if input.isatty():
        click.echo("Text to encrypt:", err=True)

    try:
        ciphertext = c.encrypt(input.read())
    except CipherError as err:
        click.secho("Error: " + str(err), fg="red")
        sys.exit(3)

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
@click.option("-o", "--output", help="Output file", type=click.File("w"))
@click.option("-k", "--key-file", help="Key file", type=click.File("r"))
@click.option("-b", "--batch", help="Non-interactive mode", is_flag=True, default=False)
@_alphabet_option
def decrypt(
    input: Optional[TextIO],
    key_file: Optional[TextIO],
    output: Optional[TextIO],
    alphabet: str,
    batch: bool,
) -> None:
    """Decrypt Vigenère ciphertext"""

    if not input:
        input = sys.stdin

    c = Cipher(key_file=key_file, batch=batch, alphabet_name=alphabet)

    if input.isatty():
        click.echo("Enter ciphertext...", err=True)

    try:
        plaintext = c.decrypt(input.read())
    except CipherError as err:
        click.secho("Error: " + str(err), fg="red")
        sys.exit(3)

    if output:
        output.write(plaintext)
    else:
        if input.isatty():
            click.echo("Plaintext:", err=True)
        click.echo(plaintext, nl=False)


@cli.command()
@click.argument("length", type=int)
@_alphabet_option
@click.option("-o", "--output", help="Write key to given file", type=click.File("w"))
@click.option(
    "-f",
    "--format",
    help="Output format",
    default="plain",
    type=click.Choice(["plain", "yaml"]),
)
def keygen(
    length: int,
    output: Optional[TextIO],
    alphabet: str,
    format: str,
) -> None:
    """
    Generate a random key, suitable for use as a one time pad.
    """

    alpha = get_alphabet(name=alphabet)
    key = alpha.generate_key(length=length)

    if format == "yaml":
        key = strictyaml.as_document({"key": key}).as_yaml()
    elif format == "plain":
        pass
    else:
        raise ValueError("Invalid format: " + repr(format))

    if output:
        output.write(key)
    else:
        ansi_invert_spaces = sys.stdout.isatty() and format == "plain"
        if ansi_invert_spaces:
            key = key.replace(" ", "\033[7m \033[27m")

        click.echo(key, nl=(format == "plain"))


@cli.command()
@click.argument("label", required=False)
@click.option(
    "-f",
    "--format",
    help="Output format",
    default="plain",
    type=click.Choice(["plain", "tab", "csv"]),
)
@click.option("--tab", is_flag=True, help="Tab delimit output")
@click.option("--csv", "csv_out", is_flag=True, help="CSV format output")
def alphabet(
    format: str,
    label: Optional[str] = None,
    csv_out: bool = False,
    tab: bool = False,
) -> None:
    """
    Print characters in the given alphabet.

    Or, if no label is given, list all known alphabet names.
    """

    if csv_out:
        format = "csv"
    if tab:
        format = "tab"

    if not label:
        if format == "csv":
            writer = csv.writer(sys.stdout)
            writer.writerow(["name", "description"])
            for alpha in ALPHABETS.values():
                row = [alpha.name, alpha.description]
                writer.writerow(row)
        elif format == "tab":
            for alpha in ALPHABETS.values():
                click.echo(alpha.name + "\t" + alpha.description)
        elif format == "plain":
            click.echo("Known alphabets:\n" + list_alphabets_labels())
        else:
            raise ValueError("Invalid format: " + repr(format))

        return

    try:
        alpha = get_alphabet(name=label)
    except KeyError:
        click.secho("Alphabet not found: " + label, fg="red")
        click.echo("Known alphabets:\n" + list_alphabets_labels())
        sys.exit(1)

    chars = alpha.chars

    if format == "csv":
        row = list(chars)
        writer = csv.writer(sys.stdout)
        writer.writerow(row)
        return

    elif format == "tab":
        chars = "\t".join(chars)

    click.echo(chars)
