import io
from pathlib import Path

import pytest
import strictyaml

from vigenere.cipher import Cipher
from vigenere.errors import CipherError, CLIError


fixtures_dir = Path(__file__).parent.parent / "fixtures"


def load_fixtures() -> dict:
    text = open(fixtures_dir / "fixtures.yaml").read()
    return strictyaml.load(text).data


def test_cipher_init(mocker):
    fixtures = load_fixtures()
    fixtures["cases"]["printable"]["case-fox"]

    c = Cipher(key="abc")
    assert c.alphabet.name == "printable"  # default
    assert c.key == "abc"

    with pytest.raises(ValueError, match="Cannot pass both key and key_file"):
        Cipher(key="abc", key_file=io.StringIO())

    with pytest.raises(CLIError):
        Cipher(batch=True)

    c = Cipher(key_file=io.StringIO("foobar"))
    assert c.key == "foobar"

    with pytest.raises(ValueError, match="Empty key"):
        Cipher(key="")

    with pytest.raises(ValueError, match="Empty key"):
        Cipher(key_file=io.StringIO(""))


def test_init_interactive_mocked(mocker):
    stub = mocker.patch("vigenere.cipher.pwinput", return_value="somekey")
    c = Cipher()
    assert stub.call_args_list == [mocker.call("Key: ")]
    assert c.key == "somekey"


def load_cases() -> list[tuple[str]]:
    cases = load_fixtures()["cases"]
    output = []

    for alphabet_name, casedict in cases.items():
        for name, info in casedict.items():
            key = info["key"]
            plain = info["plaintext"]
            ciphertext = info["ciphertext"]
            output.append((alphabet_name, name, key, plain, ciphertext))

    return output


@pytest.mark.parametrize("alphabet_name,test_name,key,plain,ciphertext", load_cases())
def test_all_fixtures(alphabet_name, test_name, key, plain, ciphertext):
    c = Cipher(key=key, alphabet_name=alphabet_name)
    assert c.encrypt(plain) == ciphertext
    assert c.decrypt(ciphertext) == plain


def test_character_errors():
    c = Cipher(key="WXYZ")

    with pytest.raises(ValueError, match="Must provide text"):
        c.encrypt(text=None)

    with pytest.raises(CipherError, match="Key is shorter than plaintext"):
        c.encrypt(text="abcde")

    with pytest.raises(
        CipherError,
        match="Invalid character for alphabet 'printable' in plaintext input",
    ):
        c.encrypt(text="\xbfyo?")

    with pytest.raises(
        CipherError,
        match="Invalid character for alphabet 'printable' in plaintext input",
    ):
        c.encrypt(text="¿yo?")

    with pytest.raises(
        CipherError, match="Invalid character for alphabet 'printable' in key"
    ):
        badkey = Cipher(key="\xbfyo?")
        badkey.encrypt("omg")

    with pytest.raises(
        CipherError,
        match="Invalid character for alphabet 'printable' in ciphertext input",
    ):
        c.decrypt(text="¿yo?")


@pytest.mark.parametrize(
    "alphabet,invalid",
    [
        ("letters", "4"),
        ("printable", "\xe9"),
        ("alpha-upper", "z"),
        ("alpha-mixed", "\xe9"),
    ],
)
def test_invalid_chars(alphabet, invalid):
    c = Cipher(key="WXYZ", alphabet_name=alphabet)

    error_prefix = "Invalid character for alphabet"

    with pytest.raises(
        CipherError,
        match=f"{error_prefix} {alphabet!r} in plaintext input: {invalid!r}",
    ):
        c.encrypt(text="YO" + invalid)

    with pytest.raises(
        CipherError,
        match=f"{error_prefix} {alphabet!r} in ciphertext input: {invalid!r}",
    ):
        c.decrypt(text="YO" + invalid)

    badkey = Cipher(key=invalid + "foo", alphabet_name=alphabet)

    with pytest.raises(
        CipherError, match=f"{error_prefix} {alphabet!r} in key: {invalid!r}"
    ):
        badkey.decrypt("BAR")

    with pytest.raises(
        CipherError, match=f"{error_prefix} {alphabet!r} in key: {invalid!r}"
    ):
        badkey.encrypt("BAR")
