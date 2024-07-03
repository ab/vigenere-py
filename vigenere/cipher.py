import itertools
import operator
from typing import Callable, Iterator, Optional, TextIO

from .alphabet import Alphabet, get_alphabet
from .errors import CipherError, InputError
from .pwinput import pwinput


class Cipher:
    def __init__(
        self,
        key: Optional[str] = None,
        key_file: Optional[TextIO] = None,
        batch: bool = False,
        alphabet: Optional[Alphabet] = None,
        alphabet_name: Optional[str] = None,
        insecure_allow_broken_short_key: bool = False,
        max_key_size: int = 1024 * 1024,
        wrap_decimal_width: int | None = 60,
    ):
        """
        If the key is random and longer than the plaintext, then this is
        effectively a one-time pad (secure).

        If insecure_allow_broken_short_key is set to True, then we allow keys
        shorter than the plaintext to be repeated, which acts like the
        classical (insecure) Vigenere cipher, which can be easily broken by
        frequency analysis.
        """

        if key_file and key:
            raise InputError("Cannot pass both key and key_file")

        if key_file:
            key = key_file.read(max_key_size + 1)
            if len(key) > max_key_size:
                raise InputError(f"Exceeded max key size: {max_key_size} B")
        elif key is None:
            if batch:
                raise InputError("Must provide key")
            else:
                key = pwinput("Key: ")

        if not key:
            raise InputError("Empty key")

        # Set alphabet directly or by name
        if alphabet:
            if alphabet_name:
                raise InputError("Cannot pass both alphabet and alphabet_name")

            if not isinstance(alphabet, Alphabet):
                raise InputError(f"Expected Alphabet instance, got {alphabet!r}")

            self.alphabet = alphabet

        else:
            if not alphabet_name:
                raise InputError("Must pass alphabet or alphabet_name")

            self.alphabet = get_alphabet(name=alphabet_name)

        # remove passthrough chars and possibly convert from decimal
        self.key = self.alphabet.prepare_key(key)

        self.insecure_allow_broken_short_key = insecure_allow_broken_short_key

        self.wrap_decimal_width = wrap_decimal_width

    def encrypt(self, text: str) -> str:
        """Encrypt provided text."""
        output = self._crypt(text=text, op=operator.add, input_label="plaintext")

        # convert output to decimal as needed
        if self.alphabet.decimal:
            output = (
                self.alphabet.decimal_encode(output, wrap=self.wrap_decimal_width)
            ) + "\n"

        return output

    def decrypt(self, text: str) -> str:
        """Decrypt provided text."""

        # convert decimal input as needed
        if self.alphabet.decimal:
            text = self.alphabet.decimal_decode(text)

        return self._crypt(text=text, op=operator.sub, input_label="ciphertext")

    def _crypt(
        self,
        text: str,
        op: Callable[[int, int], int],
        input_label: str,
    ) -> str:
        """
        Generic function handling encrypt and decrypt
        """
        if text is None:
            raise InputError("Must provide text")

        if not self.insecure_allow_broken_short_key:
            if len(self.key) < len(self.alphabet.remove_passthrough(text)):
                raise CipherError(f"Key is shorter than {input_label}")

        output = ""

        iter_in = iter(text)
        iter_key: Iterator[str]

        if self.insecure_allow_broken_short_key:
            # loop key forever if insecure mode is enabled
            # This behaves like a classical Vigenere cipher (easily broken)
            # instead of like a one-time pad (secure).
            iter_key = itertools.cycle(self.key)
        else:
            # iterate once through the key
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
