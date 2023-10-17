import secrets
from typing import Optional, TextIO

from .errors import CipherError, CLIError
from .pwinput import pwinput


ALPHABET_PRINTABLE = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"  # noqa: E501

PRINTABLE_PASSTHROUGH = {"\r", "\n", "\t"}


class Cipher():
    def __init__(
        self,
        key: Optional[str] = None,
        key_file: Optional[TextIO] = None,
        generate_key: bool = False,
        batch: bool = False,
    ):
        if key_file and key:
            raise ValueError("Cannot pass both key and key_file")

        if key_file:
            key = key_file.read()
        elif key is None:
            if batch:
                raise CLIError("Must provide key")
            else:
                key = pwinput("Key: ")

        if not key:
            raise ValueError("Empty key")

        self.key = key

        self.alphabet = ALPHABET_PRINTABLE
        self.alphabet_dict = {v: i for i, v in enumerate(self.alphabet)}

        self.passthrough = PRINTABLE_PASSTHROUGH

    def encrypt(self, text: str):
        if text is None:
            raise ValueError("Must provide text")

        if len(self.key) < len(text):
            raise CipherError("Key is shorter than plaintext")

        output = ""

        iter_in = iter(text)
        iter_key = iter(self.key)

        for c, k in zip(iter_in, iter_key):

            # pass through certain plaintext without consuming key
            while c in self.passthrough:
                output += c
                try:
                    c = next(iter_in)
                except StopIteration:
                    return output

            try:
                c_int = self.alphabet_dict[c]
            except KeyError:

                raise CipherError(f"Invalid character in plaintext: {c!r}")

            try:
                k_int = self.alphabet_dict[k]
            except KeyError:
                raise CipherError(f"Invalid character in key: {k!r}")

            o_int = (c_int + k_int) % len(self.alphabet)
            o_chr = self.alphabet[o_int]

            output += o_chr

        return output

    def decrypt(self, text: str):
        if text is None:
            raise ValueError("Must provide text")

        if len(self.key) < len(text):
            raise CipherError("Key is shorter than ciphertext")

        output = ""

        iter_in = iter(text)
        iter_key = iter(self.key)

        for c, k in zip(iter_in, iter_key):

            # pass through certain text without consuming key
            while c in self.passthrough:
                output += c
                try:
                    c = next(iter_in)
                except StopIteration:
                    return output

            try:
                c_int = self.alphabet_dict[c]
            except KeyError:

                raise CipherError(f"Invalid character in ciphertext: {c!r}")

            try:
                k_int = self.alphabet_dict[k]
            except KeyError:
                raise CipherError(f"Invalid character in key: {k!r}")

            o_int = (c_int - k_int) % len(self.alphabet)
            o_chr = self.alphabet[o_int]

            output += o_chr

        return output


def generate_key_printable(length: int) -> str:
    """
    Generate a key of printable chars, using the `secrets` module CSPRNG.
    """
    return generate_key(length=length, alphabet=ALPHABET_PRINTABLE)


def generate_key(length: int, alphabet: str) -> str:
    """
    Generate a key from the given alphabet, using the `secrets` module CSPRNG.
    """
    return ''.join(secrets.choice(alphabet) for i in range(length))
