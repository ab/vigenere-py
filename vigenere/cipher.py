import operator
from typing import Callable, Optional, TextIO

from .alphabet import get_alphabet
from .errors import CipherError, CLIError
from .pwinput import pwinput


class Cipher:
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

        self.alphabet = get_alphabet(name=alphabet_name)

        self.key = self.alphabet.remove_passthrough(key)

    def encrypt(self, text: str) -> str:
        """Encrypt provided text."""
        return self._crypt(text=text, op=operator.add, input_label="plaintext")

    def decrypt(self, text: str) -> str:
        """Decrypt provided text."""
        return self._crypt(text=text, op=operator.sub, input_label="ciphertext")

    def _crypt(self, text: str, op: Callable[[int, int], int], input_label: str) -> str:
        """
        Generic function handling encrypt and decrypt
        """
        if text is None:
            raise ValueError("Must provide text")

        if len(self.key) < len(self.alphabet.remove_passthrough(text)):
            raise CipherError(f"Key is shorter than {input_label}")

        output = ""

        iter_in = iter(text)
        iter_key = iter(self.key)

        while True:
            try:
                c = next(iter_in)
            except StopIteration:
                return output

            # pass through certain text without consuming key
            while c in self.alphabet.passthrough:
                output += c
                try:
                    c = next(iter_in)
                except StopIteration:
                    return output

            try:
                k = next(iter_key)
            except StopIteration:
                raise CipherError(
                    f"Unexpected (bug?) key is shorter than {input_label}"
                )

            try:
                c_int = self.alphabet.chars_dict[c]
            except KeyError:
                raise CipherError(
                    f"Invalid character for alphabet {self.alphabet.name!r}"
                    + f" in {input_label} input: {c!r}"
                )

            try:
                k_int = self.alphabet.chars_dict[k]
            except KeyError:
                raise CipherError(
                    f"Invalid character for alphabet {self.alphabet.name!r}"
                    + f" in key: {k!r}"
                )

            o_int = op(c_int, k_int) % len(self.alphabet.chars)
            o_chr = self.alphabet.chars[o_int]

            output += o_chr

        return output
