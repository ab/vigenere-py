import io
from pathlib import Path

import pytest
import strictyaml

from vigenere.cipher import Cipher
from vigenere.errors import CipherError, CLIError, InputError
from vigenere.alphabet import ALPHABET_PRINTABLE


fixtures_dir = Path(__file__).parent.parent / "fixtures"


def load_fixtures() -> dict:
    text = open(fixtures_dir / "fixtures.yaml").read()
    return strictyaml.load(text).data


def test_cipher_init(mocker):
    fixtures = load_fixtures()
    fixtures["cases"]["printable"]["case-fox"]

    c = Cipher(key="abc", alphabet=ALPHABET_PRINTABLE)
    assert c.alphabet.name == "printable"
    assert c.key == "abc"

    with pytest.raises(InputError, match="Cannot pass both key and key_file"):
        Cipher(key="abc", key_file=io.StringIO())

    with pytest.raises(CLIError):
        Cipher(batch=True)

    c = Cipher(key_file=io.StringIO("foobar"), alphabet=ALPHABET_PRINTABLE)
    assert c.key == "foobar"

    with pytest.raises(InputError, match="Empty key"):
        Cipher(key="")

    with pytest.raises(InputError, match="Empty key"):
        Cipher(key_file=io.StringIO(""))

    with pytest.raises(InputError, match="Exceeded max key size"):
        Cipher(key_file=io.StringIO("x" * 50), max_key_size=40)

    with pytest.raises(InputError, match="both alphabet and alphabet_name"):
        Cipher(key="foo", alphabet=ALPHABET_PRINTABLE, alphabet_name="foo")

    with pytest.raises(InputError, match="Must pass alphabet"):
        Cipher(key="foo")


def test_init_interactive_mocked(mocker):
    stub = mocker.patch("vigenere.cipher.pwinput", return_value="somekey")
    c = Cipher(alphabet_name="printable")
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
            insecure = info.get("insecure", False)
            output.append((alphabet_name, name, key, plain, ciphertext, insecure))

    return output


@pytest.mark.parametrize(
    "alphabet_name,test_name,key,plain,ciphertext,insecure", load_cases()
)
def test_all_fixtures(alphabet_name, test_name, key, plain, ciphertext, insecure):
    c = Cipher(
        key=key, alphabet_name=alphabet_name, insecure_allow_broken_short_key=insecure
    )
    assert c.encrypt(plain) == ciphertext
    assert c.decrypt(ciphertext) == plain


def test_character_errors():
    c = Cipher(key="WXYZ", alphabet_name="printable")

    with pytest.raises(InputError, match="Must provide text"):
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
        badkey = Cipher(key="\xbfyo?", alphabet_name="printable")
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
