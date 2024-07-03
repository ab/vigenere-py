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

⚠️ Note: The name of this Python package is `vigenere-py`, while the name of the
command is `vigenere`. There is an unrelated Python package named `vigenere`.

## Usage

For help, run:

    vigenere --help

You can also use:

    python -m vigenere --help

### Alphabets

Several different alphabets are available. Specify the alphabet using the
option `-a/--alphabet` or the `VIGENERE_ALPHABET` environment variable.

The `decimal` alphabet encodes keys and ciphertext as 2-digit decimal numbers.
This makes it convenient to compute by hand because encryption is just adding
the numbers modulo 100. See
[printouts/Decimal 100 Alphabet.pdf](./printouts/Decimal%20100%20Alphabet.pdf)
for a printable table.

The other alphabets are more traditional Vigenère ciphers that can be computed
on paper with the help of a table or a cipher wheel. The `printable` alphabet
contains all printable ASCII characters with spaces but no other whitespace.

The other alphabets will pass through punctuation like spaces unchanged.

    $ vigenere alphabets

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

### Decimal

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

### Insecure mode

A classical Vigenère cipher repeats the key. Unlike a one-time pad, this can be
trivially broken by frequency analysis.

However, if you want to reproduce historical messages that use repeated keys
(such as US Civil War era ciphers), then the `--insecure` option may be used.

Obviously this shouldn't be used for anything of importance, unless you are a
[Confederate general trying to surrender](https://www.augustachronicle.com/story/news/2010/12/26/civil-war-message-decoded/14566657007/).

Here we'll decrypt a [famous message](https://en.wikisource.org/wiki/Encrypted_message_to_John_Pemberton,_1863-07-04)
with the key `MANCHESTER BLUFF`. (Text corrects some errors in the original.)

    $ cat cipher.txt
        SEAN WIEUIIUY, STZ OAA GETWVX EP SYQU RRBO ALAL WZEP IK YTE EKCIJ. EIK
        HPHQ OAHAUASF DRFX, TZ UTESVDSI, OAIE ZZO HFZ AGVHGC MLV TLGJ UAIAV VR
        LAI VOPGDX XIAG. PRXHVD NP UQXA AAF P AAEP VOOYFAAUE VV QSDI R
        ETPJWEIBP. P LSOI JFYN XTYE PCWW. A LYSKZCS IQSCCAGZ YVFN RYS OAHAUASF.

    $ echo 'MANCHESTER BLUFF' > key.txt

    $ vigenere dec -a letters -k key.txt --insecure cipher.txt
        GENL PEMBERTN, YOU CAN EXPECT NO HELP FROM THIS SIDE OF THE RIVER. LET
        GENL JOHNSTON KNOW, IF POSSIBLE, WHEN YOU CAN ATTACK THE SAME POINT ON
        THE ENEMYS LINE. INFORM ME ALSO AND I WILL ENDEAVOUR TO MAKE A
        DIVERSION. I HAVE SENT SOME CAPS. I SUBJOIN DESPATCH FROM GEN JOHNSTON.

### Shell completions

Tab completion is supported thanks to the [Click CLI](https://click.palletsprojects.com/en/8.1.x/shell-completion/#enabling-completion).


**Bash:**

    _VIGENERE_COMPLETE=bash_source vigenere > ~/.local/share/bash-completion/completions/vigenere

**Zsh:**

    _VIGENERE_COMPLETE=zsh_source vigenere > ~/.../some-dir/vigenere-complete.zsh
    # source this file from ~/.zshrc

**Fish:**

    _VIGENERE_COMPLETE=fish_source vigenere > ~/.config/fish/completions/vigenere.fish


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

    # all tests and linters
    poe all

    # just pytest
    poe test
