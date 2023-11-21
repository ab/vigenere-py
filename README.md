# vigenere-py

[![PyPI](https://img.shields.io/pypi/v/vigenere-py.svg)](https://pypi.org/project/vigenere-py/)
[![Changelog](https://img.shields.io/github/v/release/ab/vigenere-py?include_prereleases&label=changelog)](https://github.com/ab/vigenere-py/releases)
[![Tests](https://github.com/ab/vigenere-py/workflows/Test/badge.svg)](https://github.com/ab/vigenere-py/actions?query=workflow%3ATest)
[![License](https://img.shields.io/github/license/ab/vigenere-py)](https://github.com/ab/vigenere-py/blob/master/LICENSE)

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
