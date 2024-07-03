import csv
import functools
import sys
from typing import Callable, Optional, ParamSpec, TextIO, TypeVar

import click
import strictyaml
from click.core import ParameterSource
from click.shell_completion import CompletionItem

from .alphabet import (
    ALPHABETS,
    Alphabet,
    get_alphabet,
    list_alphabets_labels,
    list_alphabets_names,
)
from .cipher import Cipher
from .errors import CLIError

# make help available at -h as well as default --help
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


ALIASES = {
    "alpha": "alphabet",
    "alphabets": "alphabet",
    "d": "dec",
    "decrypt": "dec",
    "digits": "decimal",
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
    """
    Vigenère cipher encryption for Python.

    The cipher alphabet of possible characters must be set by -a/--alphabet or
    by env var VIGENERE_ALPHABET. (See `vigenere alphabet` for list.)

    Run `vigenere COMMAND --help` for more info on each command.
    """


def validate_alphabet(
    ctx: click.Context, param: click.core.Parameter, value: str
) -> Alphabet:
    """
    Click param validator for Alphabet. Accepts string as input and returns an
    Alphabet. Prints error/usage message if no alphabet is found with that
    name.
    """

    if value == ALPHABET_UNSET:
        message = "\n".join(
            [
                "Must set option -a/--alphabet or env var VIGENERE_ALPHABET",
                "\nKnown alphabets: " + ", ".join(ALPHABETS.keys()),
                "(See `vigenere alphabets` for more info)",
            ]
        )
        # NB: we may be inside shell completion, so we don't want to directly
        # print to stdout/stderr
        raise click.UsageError(message)

    try:
        return get_alphabet(name=value)

    except KeyError:
        # customize error based on param source
        source = ctx.get_parameter_source("alphabet")
        source_label = "-a/--alphabet"
        if source == ParameterSource.ENVIRONMENT:
            source_label = "$VIGENERE_ALPHABET"

        click.echo("Known alphabets:\n" + list_alphabets_labels(aliases=True), err=True)
        click.secho(
            f"Error: Invalid value for {source_label}: {value!r}",
            fg="red",
            bold=True,
            err=True,
        )
        ctx.exit(1)


def validate_alphabet_optional(
    ctx: click.Context, param: click.core.Parameter, value: Optional[str]
) -> Optional[Alphabet]:
    """
    Click param validator for Alphabet. Accepts optional string as input and
    returns either None or an Alphabet.
    """

    if not value:
        return None

    return validate_alphabet(ctx=ctx, param=param, value=value)


ALPHABET_UNSET = "<unset>"


def shell_complete_alphabet(
    ctx: click.Context, param: click.core.Parameter, incomplete: str
) -> list[str] | list[CompletionItem]:
    """
    Shell completion for --alphabet
    """
    alphas = list_alphabets_names(aliases=True)

    return [a for a in alphas if a.startswith(incomplete)]


# Alphabet option is used by several commands
_alphabet_option = click.option(
    "-a",
    "--alphabet",
    help="Cipher alphabet, if not set by VIGENERE_ALPHABET",
    metavar="ALPHABET",
    default=ALPHABET_UNSET,
    envvar="VIGENERE_ALPHABET",
    callback=validate_alphabet,
    shell_complete=shell_complete_alphabet,
)


P = ParamSpec("P")
R = TypeVar("R")


def _cipher_options(f: Callable[P, R]) -> Callable[P, R]:
    """
    Common options for encrypt and decrypt
    """

    @click.argument("input", type=click.File("r"), required=False)
    @_alphabet_option
    @click.option(
        "-b", "--batch", help="Non-interactive mode", is_flag=True, default=False
    )
    @click.option("-k", "--key-file", help="Key file", type=click.File("r"))
    @click.option("-o", "--output", help="Output file", type=click.File("w"))
    @click.option(
        "--insecure",
        is_flag=True,
        default=False,
        help="Allow short keys to loop (easily cracked!!)",
    )
    @functools.wraps(f)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        return f(*args, **kwargs)

    return wrapped


@cli.command(name="enc")
@_cipher_options
def encrypt(
    input: Optional[TextIO],
    key_file: Optional[TextIO],
    output: Optional[TextIO],
    alphabet: Alphabet,
    batch: bool,
    insecure: bool,
) -> None:
    """
    Encrypt text with a Vigenère cipher.

    Read plaintext from INPUT file or from stdin if not provided.

    Prompt for key interactively if key file not given.

    For example:

        vigenere enc -o out.txt input.txt

    """

    if not input:
        input = sys.stdin

    try:
        c = Cipher(
            key_file=key_file,
            batch=batch,
            alphabet=alphabet,
            insecure_allow_broken_short_key=insecure,
        )
    except CLIError as err:
        click.secho("Error: " + str(err), fg="red")
        sys.exit(3)

    # If output is a TTY, highlight spaces in ANSI inverted colors, if we're
    # using an alphabet that may contain spaces.
    if output:
        ansi_invert_spaces = False
    else:
        ansi_invert_spaces = sys.stdout.isatty() and c.alphabet.ansi_spaces

    if input.isatty():
        click.echo("Text to encrypt:", err=True)

    try:
        ciphertext = c.encrypt(input.read())
    except CLIError as err:
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
@_cipher_options
def decrypt(
    input: Optional[TextIO],
    key_file: Optional[TextIO],
    output: Optional[TextIO],
    alphabet: Alphabet,
    batch: bool,
    insecure: bool,
) -> None:
    """
    Decrypt Vigenère ciphertext.

    Read plaintext from INPUT file or from stdin if not provided.

    Prompt for key interactively if key file not given.

    For example:

        vigenere dec cipher.txt
    """

    if not input:
        input = sys.stdin

    try:
        c = Cipher(
            key_file=key_file,
            batch=batch,
            alphabet=alphabet,
            insecure_allow_broken_short_key=insecure,
        )
    except CLIError as err:
        click.secho("Error: " + str(err), fg="red")
        sys.exit(3)

    if input.isatty():
        click.echo("Enter ciphertext...", err=True)

    try:
        plaintext = c.decrypt(input.read())
    except CLIError as err:
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
    alphabet: Alphabet,
    format: str,
) -> None:
    """
    Generate a random key, suitable for use as a one time pad.
    """

    alpha = alphabet
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
        ansi_invert_spaces = (
            sys.stdout.isatty() and format == "plain" and alpha.ansi_spaces
        )
        if ansi_invert_spaces:
            key = key.replace(" ", "\033[7m \033[27m")

        click.echo(key, nl=(format == "plain"))


@cli.command()
@click.argument("alphabet", required=False, callback=validate_alphabet_optional)
@click.option(
    "-f",
    "--format",
    help="Output format",
    default="plain",
    type=click.Choice(["plain", "tab", "csv"]),
)
@click.option("--tab", is_flag=True, help="Tab delimit output")
@click.option("--csv", "csv_out", is_flag=True, help="CSV format output")
@click.option("--table", is_flag=True, help="Print decimal table of indexes")
def alphabet(
    alphabet: Optional[Alphabet],
    format: str,
    label: Optional[str] = None,
    csv_out: bool = False,
    tab: bool = False,
    table: bool = False,
) -> None:
    """
    Print helpful info about supported alphabets.

    If a single alphabet is given, print the characters in that alphabet.

    Or, if no label is given, print details about all known alphabets.
    """

    if csv_out:
        format = "csv"
    if tab:
        format = "tab"

    if not alphabet:
        if format == "csv":
            writer = csv.writer(sys.stdout)
            header = ["name", "description", "aliases"]
            writer.writerow(header)

            for alpha in ALPHABETS.values():
                row = [alpha.name, alpha.description, alpha.aliases_str]
                writer.writerow(row)

        elif format == "tab":
            for alpha in ALPHABETS.values():
                row = [alpha.name, alpha.description, alpha.aliases_str]
                click.echo("\t".join(row))

        elif format == "plain":
            click.echo("Known alphabets:\n" + list_alphabets_labels(aliases=True))
        else:
            raise ValueError("Invalid format: " + repr(format))

        return

    alpha = alphabet

    if table:
        for i, c in enumerate(alpha.chars_escaped):
            click.echo(("%02d" % i) + "\t" + c)
        return

    if format == "csv":
        row = list(alpha.chars_escaped)
        writer = csv.writer(sys.stdout)
        writer.writerow(row)

    elif format == "tab":
        click.echo("\t".join(alpha.chars_escaped))

    elif format == "plain":
        click.echo(alpha.chars_for_display)

    else:
        raise ValueError(f"Bad format: {format!r}")


@cli.command()
@click.argument("file", type=click.File("r"), required=False)
@_alphabet_option
@click.option(
    "-e",
    "--encode",
    "mode",
    flag_value="encode",
    help="Encode string to decimal",
)
@click.option(
    "-d",
    "--decode",
    "mode",
    flag_value="decode",
    help="Decode decimal to string",
)
@click.option(
    "-w", "--wrap", metavar="WIDTH", default=60, help="Wrap decimal output at WIDTH"
)
@click.pass_context
def decimal(
    ctx: click.Context,
    alphabet: Alphabet,
    mode: str,
    file: Optional[TextIO],
    wrap: int,
) -> None:
    """
    Decimal encode/decode data and print to standard output.

    In -e/--encode mode, accept string as input and convert to digits according
    to each character's index in the cipher alphabet.

    In -d/--decode mode, accept space-separated digits as input and convert to
    a string of characters in the alphabet.

    For example:

        fortune | vigenere decimal -a 100 -e

        echo 45 74 81 81 84 | vigenere decimal -a 100 -d
    """

    if not mode:
        click.echo(ctx.get_help(), err=True)
        click.echo("\nError: Must set mode -e or -d", err=True)
        ctx.exit(1)

    if not file:
        if sys.stdin.isatty():
            click.echo("Enter input on stdin, end with EOF/ctrl^d...", err=True)

        file = sys.stdin

    text = file.read()

    try:
        if mode == "encode":
            text = alphabet.remove_passthrough(text)
            click.echo(alphabet.decimal_encode(text=text, wrap=wrap))
        elif mode == "decode":
            click.echo(
                alphabet.decimal_decode(decimals=text),
                nl="\n" not in alphabet.chars_dict,
            )
        else:
            raise ValueError(f"Invalid mode: {mode!r}")

    except CLIError as err:
        click.secho("Error: " + str(err), fg="red", bold=True)
        sys.exit(3)
