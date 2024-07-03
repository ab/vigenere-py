import secrets
import string

import pytest

from vigenere.alphabet import (
    Alphabet,
    get_alphabet,
    ALPHABET_DECIMAL,
    ALPHABET_PRINTABLE,
    ALPHABET_LETTERS_ONLY,
    ALPHABET_ALPHANUMERIC_UPPER,
    ALPHABET_ALPHANUMERIC_MIXED,
)
from vigenere.errors import InputError


def test_get_alphabet():
    with pytest.raises(KeyError):
        get_alphabet("nonexistent")

    printable = get_alphabet("printable")
    assert isinstance(printable, Alphabet)
    assert printable == ALPHABET_PRINTABLE

    assert len(printable.chars) == 95
    assert len(printable.passthrough) == 5

    assert get_alphabet("100") == ALPHABET_DECIMAL
    assert get_alphabet("decimal") == ALPHABET_DECIMAL
    assert get_alphabet("letters") == ALPHABET_LETTERS_ONLY
    assert get_alphabet("upper") == ALPHABET_LETTERS_ONLY
    assert get_alphabet("alphanumeric") == ALPHABET_ALPHANUMERIC_MIXED
    assert get_alphabet("alphanumeric-upper") == ALPHABET_ALPHANUMERIC_UPPER

    with pytest.raises(ValueError, match="name must be str"):
        get_alphabet(name=123)


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

    assert ALPHABET_DECIMAL.decimal
    assert ALPHABET_DECIMAL.ansi_spaces is False
    assert ALPHABET_PRINTABLE.ansi_spaces is True
    assert ALPHABET_LETTERS_ONLY.ansi_spaces is False


def test_generate_key_mock(mocker):
    spy = mocker.spy(secrets, "choice")

    key = ALPHABET_LETTERS_ONLY.generate_key(length=5)
    assert len(key) == 5
    assert isinstance(key, str)

    # make sure we called secrets.choice
    assert spy.call_args_list == [mocker.call("ABCDEFGHIJKLMNOPQRSTUVWXYZ")] * 5


def test_generate_key_decimal(mocker):
    mock = mocker.patch.object(secrets, "choice")
    mock.side_effect = ["R", "a", "n", "d"]

    key = ALPHABET_DECIMAL.generate_key(length=4)

    assert mock.call_args_list == [mocker.call(ALPHABET_DECIMAL.chars)] * 4

    assert key == "55 70 83 73"


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


ENCODE_FIXTURES = [
    ("decimal", "FOO!", "43 52 52 06"),
    ("decimal", "Hello, World!\n", "45 74 81 81 84 17 05 60 84 87 81 73 06 02"),
    ("decimal", "Null: \0 OK", "51 90 81 81 31 05 00 05 52 48"),
    ("letters", "ABCZ", "00 01 02 25"),
    ("printable", " Az.!", "00 33 90 14 01"),
]


@pytest.mark.parametrize("alphabet,text,encoded", ENCODE_FIXTURES)
def test_decimal_encode_decode(alphabet: str, text: str, encoded: str) -> None:
    alpha = get_alphabet(alphabet)

    assert alpha.decimal_encode(text) == encoded

    assert alpha.decimal_decode(encoded) == text


def test_decimal_wrap() -> None:
    alpha = ALPHABET_DECIMAL

    text = "ABC" * 25
    encoded = """
38 39 40 38 39 40 38 39 40 38 39 40 38 39 40 38 39 40 38 39
40 38 39 40 38 39 40 38 39 40 38 39 40 38 39 40 38 39 40 38
39 40 38 39 40 38 39 40 38 39 40 38 39 40 38 39 40 38 39 40
38 39 40 38 39 40 38 39 40 38 39 40 38 39 40
""".strip()

    assert alpha.decimal_encode(text) == encoded

    nowrap = ("38 39 40 " * 25).rstrip()
    assert alpha.decimal_encode(text, wrap=0) == nowrap

    assert alpha.decimal_decode(encoded) == text
    assert alpha.decimal_decode(nowrap) == text


@pytest.mark.parametrize(
    "alphabet,text,err_regex",
    [
        ("decimal", "¿", "Invalid input char '¿' for alphabet 'decimal'"),
        ("letters", "ABCz", "Invalid input char 'z' for alphabet 'letters'"),
        ("letters", "A BEAR", "Invalid input char ' ' for alphabet 'letters'"),
    ],
)
def test_decimal_encode_errors(alphabet: str, text: str, err_regex: str) -> None:
    alpha = get_alphabet(alphabet)

    with pytest.raises(InputError, match=err_regex):
        alpha.decimal_encode(text)


@pytest.mark.parametrize(
    "alphabet,text,err_regex",
    [
        ("decimal", "12 abc", "Invalid decimal input: 'abc'"),
        ("decimal", "12 -45", "Negative numbers are invalid: -45"),
        ("decimal", "10 200", "Invalid input for alphabet: '200' not in 0..99"),
        ("letters", "10 50", "Invalid input for alphabet: '50' not in 0..25"),
    ],
)
def test_decimal_decode_errors(alphabet: str, text: str, err_regex: str) -> None:
    alpha = get_alphabet(alphabet)

    with pytest.raises(InputError, match=err_regex):
        alpha.decimal_decode(text)
