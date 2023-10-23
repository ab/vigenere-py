import secrets
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


def test_generate_key_mock(mocker):
    spy = mocker.spy(secrets, "choice")

    key = ALPHABET_LETTERS_ONLY.generate_key(length=5)
    assert len(key) == 5
    assert isinstance(key, str)

    # make sure we called secrets.choice
    assert spy.call_args_list == [mocker.call("ABCDEFGHIJKLMNOPQRSTUVWXYZ")] * 5


def test_generate_key():
    key = ALPHABET_LETTERS_ONLY.generate_key(length=10)
    assert len(key) == 10
    assert isinstance(key, str)
    assert all(c in ALPHABET_LETTERS_ONLY.chars_dict for c in key)

    key2 = ALPHABET_PRINTABLE.generate_key(100)
    assert len(key2) == 100
    assert all(c in ALPHABET_PRINTABLE.chars_dict for c in key2)

    # we should be very likely to have at least one char outside letters
    assert any(c not in ALPHABET_LETTERS_ONLY.chars_dict for c in key2)

    key3 = ALPHABET_LETTERS_ONLY.generate_key(10)
    assert len(key3) == 10
    assert key != key3
