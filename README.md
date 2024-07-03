# vigenere-py

[![PyPI](https://img.shields.io/pypi/v/vigenere-py.svg)](https://pypi.org/project/vigenere-py/)
[![Changelog](https://img.shields.io/github/v/release/ab/vigenere-py?include_prereleases&label=changelog)](https://github.com/ab/vigenere-py/releases)
[![Tests](https://github.com/ab/vigenere-py/workflows/Test/badge.svg)](https://github.com/ab/vigenere-py/actions?query=workflow%3ATest)
[![Codecov](https://img.shields.io/codecov/c/github/ab/vigenere-py)](https://app.codecov.io/github/ab/vigenere-py)
[![License](https://img.shields.io/github/license/ab/vigenere-py)](https://github.com/ab/vigenere-py/blob/master/LICENSE)

This is a Python implementation of the
[Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher), where
each letter of the plaintext is shifted according to each letter of the key.

Despite having been invented in the 16th century, the Vigenère cipher is still
useful because it's simple enough for anyone to encipher and decipher using
only pen and paper. See [cipher-wheel/](./printouts/cipher-wheel/) for images of
printable cipher wheels. (Pin the centers together with a brass brad.)

If the key is random and at least as long as the plaintext, the Vigenère cipher
is effectively a [one-time pad](https://en.wikipedia.org/wiki/One-time_pad),
which provide *perfect secrecy* when properly used.

However, if the key is reused, not fully random, or shorter than the plaintext,
then the cipher can be easily broken through frequency analysis.

As a result, `vigenere-py` comes with a `keygen` command for generating
suitable random keys, and it will refuse to encrypt text with a key that is too
short unless the `--insecure` mode is specified.

## Installation

Install this package with `pipx` for use as a standalone CLI:

    pipx install vigenere-py

    vigenere --help

Alternatively, you can install this package for use as a library via `pip` (ideally run this inside a virtualenv):

    pip install vigenere-py

## Usage

For help, run:

    vigenere --help

You can also use:

    python -m vigenere --help

### Alphabets

Several different alphabets are available. The `decimal` alphabet expects keys
and ciphertext to be 2-digit decimal numbers. This makes it convenient to
compute by hand because encryption is just adding the numbers modulo 100.

The other alphabets are more traditional ciphers that can be computed on paper
with the help of a table or a cipher wheel. The `printable` alphabet contains
all printable ASCII characters with spaces but no other whitespace.

The other alphabets will pass through punctuation like spaces unchanged.

  decimal:
      100-char full ASCII, ciphertext written as digits
      aliases: (100|ascii)
      passthrough: none
      chars: ␀␉␊␌␍ !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~

  printable:
      All printable characters and spaces
      aliases: (print|wheel)
      passthrough: other whitespace
      chars:  !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~

  letters:
      Uppercase letters only
      aliases: (upper|uppercase)
      passthrough: punctuation/whitespace
      chars: ABCDEFGHIJKLMNOPQRSTUVWXYZ

  alpha-mixed:
      Mixed case letters and numbers
      aliases: (alpha|alphanumeric|alphanumeric-mixed)
      passthrough: punctuation/whitespace
      chars: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789

  alpha-upper:
      Uppercase letters and numbers
      aliases: (alphanumeric-upper)
      passthrough: punctuation/whitespace
      chars: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

### Examples

Generating a key and encrypting:

    $ vigenere genkey -a letters 20 > key.txt

    $ cat key.txt
    RVRTCLIWHNPZAOJLXEWY

    $ cat plain.txt
    ATTACK AT DAWN

    $ vigenere enc -a letters -k key.txt plain.txt
    ROKTEV IP KNLM

Decrypting:

    $ cat key.txt
    RVRTCLIWHNPZAOJLXEWY

    $ cat cipher.txt
    ROKTEV IP KNLM

    $ vigenere dec -a letters -k key.txt cipher.txt
    ATTACK AT DAWN

Interactive mode, end the message with `ctrl+d`:

    $ vigenere enc -a letters
    Key: •••••••••••••••••
    Text to encrypt:
    SECRET MESSAGE
    Ciphertext:
    QSWIIT PXZWDUG

#### Decimal

The `decimal` alphabet (aka `ascii` or `100`) expects keys and ciphertext to be
encoded as two-digit numbers in base 10.

    $ vigenere genkey -a ascii 14 > key.txt

    $ cat key.txt
    20 95 47 06 32 32 16 88 59 87

    $ echo 'Hello, world!' > plain.txt

    $ vigenere enc -a ascii -k key.txt plain.txt
    18 32 84 77 37 76 86 89 86 97 95 30 76 36

To directly encode or decode from decimal, use `vigenere decimal`.

Note that decoded output for the `ascii` alphabet may contain control
characters like `\0`!

    $ export VIGENERE_ALPHABET=ascii

    $ echo 'Hello!' | vigenere decimal -e
    45 74 81 81 84 06 02

    $ echo '45 74 81 81 84 06 02' | vigenere decimal -d
    Hello!

    $ echo '00 01 02 03 63' | vigenere decimal -d | xxd
    00000000: 0009 0a0c 5a                             ....Z

Decimal encoding also works with other alphabets, if you want that for some
reason.

    $ echo 'ABCD' | vigenere decimal -a letters -e
    00 01 02 03

    $ echo '23 24 25 26 27' | vigenere decimal -a alpha -d
    XYZab

### Bash shell completions

    _VIGENERE_COMPLETE=bash_source vigenere > ~/.local/share/bash-completion/completions/vigenere

## Development

To contribute to this tool, first checkout the code.

### Poetry

Poetry is used to manage dependencies and virtualenvs. So install poetry before proceeding.

I recommend installing poetry with pipx.

    pipx install poetry

But if you don't want to use pipx, there are other installation instructions here: https://python-poetry.org/docs/#installation

### Installing dependencies

    cd vigenere-py
    poetry install

### Running the app

    poetry run vigenere --help

### Running tests

    poetry run mypy .
    poetry run pytest -v

Or, you can run these as a `poe` task:


Install poe:

    pipx install poethepoet

Run tests:

    poe test
