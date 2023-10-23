import string

import pytest

from vigenere.alphabet import (
    Alphabet,
    get_alphabet,
    ALPHABET_PRINTABLE,
    ALPHABET_LETTERS_ONLY,
    ALPHABET_ALPHANUMERIC_UPPER,
    ALPHABET_ALPHANUMERIC_MIXED,
)


def test_get_alphabet():
    with pytest.raises(KeyError):
        get_alphabet("nonexistent")

    printable = get_alphabet("printable")
    assert isinstance(printable, Alphabet)
    assert printable == ALPHABET_PRINTABLE

    assert len(printable.chars) == 95
    assert len(printable.passthrough) == 5

    assert get_alphabet("letters") == ALPHABET_LETTERS_ONLY
    assert get_alphabet("upper") == ALPHABET_LETTERS_ONLY
    assert get_alphabet("alphanumeric") == ALPHABET_ALPHANUMERIC_MIXED
    assert get_alphabet("alphanumeric-upper") == ALPHABET_ALPHANUMERIC_UPPER


def test_alphabet():
    assert ALPHABET_LETTERS_ONLY.chars == string.ascii_uppercase
    assert ALPHABET_LETTERS_ONLY.chars_dict == {
        "A": 0,
        "B": 1,
        "C": 2,
        "D": 3,
        "E": 4,
        "F": 5,
        "G": 6,
        "H": 7,
        "I": 8,
        "J": 9,
        "K": 10,
        "L": 11,
        "M": 12,
        "N": 13,
        "O": 14,
        "P": 15,
        "Q": 16,
        "R": 17,
        "S": 18,
        "T": 19,
        "U": 20,
        "V": 21,
        "W": 22,
        "X": 23,
        "Y": 24,
        "Z": 25,
    }
    assert ALPHABET_LETTERS_ONLY.passthrough == set(
        "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c"
    )
