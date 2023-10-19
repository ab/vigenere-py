import secrets
from typing import Optional, TextIO

from .alphabet import get_alphabet
from .errors import CipherError, CLIError
from .pwinput import pwinput


class Cipher():
    def __init__(
        self,
        key: Optional[str] = None,
        key_file: Optional[TextIO] = None,
        batch: bool = False,
        alphabet_name: str = "printable",
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

        self.alphabet = get_alphabet(name=alphabet_name)

    def encrypt(self, text: str) -> str:
        if text is None:
            raise ValueError("Must provide text")

        if len(self.key) < len(text):
            raise CipherError("Key is shorter than plaintext")

        output = ""

        iter_in = iter(text)
        iter_key = iter(self.key)

        for c, k in zip(iter_in, iter_key):

            # pass through certain plaintext without consuming key
            while c in self.alphabet.passthrough:
                output += c
                try:
                    c = next(iter_in)
                except StopIteration:
                    return output

            try:
                c_int = self.alphabet.chars_dict[c]
            except KeyError:

                raise CipherError(f"Invalid character in plaintext: {c!r}")

            try:
                k_int = self.alphabet.chars_dict[k]
            except KeyError:
                raise CipherError(f"Invalid character in key: {k!r}")

            o_int = (c_int + k_int) % len(self.alphabet.chars)
            o_chr = self.alphabet.chars[o_int]

            output += o_chr

        return output

    def decrypt(self, text: str) -> str:
        if text is None:
            raise ValueError("Must provide text")

        if len(self.key) < len(text):
            raise CipherError("Key is shorter than ciphertext")

        output = ""

        iter_in = iter(text)
        iter_key = iter(self.key)

        for c, k in zip(iter_in, iter_key):

            # pass through certain text without consuming key
            while c in self.alphabet.passthrough:
                output += c
                try:
                    c = next(iter_in)
                except StopIteration:
                    return output

            try:
                c_int = self.alphabet.chars_dict[c]
            except KeyError:

                raise CipherError(f"Invalid character in ciphertext: {c!r}")

            try:
                k_int = self.alphabet.chars_dict[k]
            except KeyError:
                raise CipherError(f"Invalid character in key: {k!r}")

            o_int = (c_int - k_int) % len(self.alphabet.chars)
            o_chr = self.alphabet.chars[o_int]

            output += o_chr

        return output


def generate_key_alphabet_label(length: int, alphabet_name: str) -> str:
    """
    Generate a key from the given alphabet, using the `secrets` module CSPRNG.
    """
    return generate_key(
        length=length,
        chars=get_alphabet(name=alphabet_name).chars
    )


def generate_key(length: int, chars: str) -> str:
    """
    Generate a key from the given alphabet, using the `secrets` module CSPRNG.
    """
    return ''.join(secrets.choice(chars) for i in range(length))
