import string
from pathlib import Path

import pytest
import strictyaml
from click.testing import CliRunner

from vigenere.alphabet import ALPHABET_PRINTABLE, ALPHABET_LETTERS_ONLY
from vigenere.cli import cli


fixtures_dir = Path(__file__).parent / "fixtures"


def load_fixtures() -> dict:
    text = open(fixtures_dir / "fixtures.yaml").read()
    return strictyaml.load(text).data


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


def test_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.output.startswith("cli, version ")


def test_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"], catch_exceptions=False)
    assert result.exit_code == 0
    assert result.output.startswith("Usage: cli [OPTIONS] COMMAND")
    assert "Vigenère cipher encryption" in result.output


@pytest.mark.parametrize("alphabet_name,test_name,key,plain,ciphertext", load_cases())
def test_encrypt_fixtures(alphabet_name, test_name, key, plain, ciphertext):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("plain.txt", "w") as f:
            f.write(plain)
        with open("key.txt", "w") as f:
            f.write(key)

        result = runner.invoke(
            cli,
            ["enc", "-a", alphabet_name, "-k", "key.txt", "plain.txt"],
            catch_exceptions=False,
        )
        assert result.output == ciphertext
        assert result.exit_code == 0


@pytest.mark.parametrize("alphabet_name,test_name,key,plain,ciphertext", load_cases())
def test_decrypt_fixtures(alphabet_name, test_name, key, plain, ciphertext):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("cipher.txt", "w") as f:
            f.write(ciphertext)
        with open("key.txt", "w") as f:
            f.write(key)

        result = runner.invoke(
            cli,
            ["dec", "-a", alphabet_name, "-k", "key.txt", "cipher.txt"],
            catch_exceptions=False,
        )
        assert result.output == plain
        assert result.exit_code == 0


def test_encrypt_defaults():
    fixture = load_fixtures()["cases"]["printable"]["case-fox"]

    runner = CliRunner()
    with runner.isolated_filesystem():
        plaintext = fixture["plaintext"]
        ciphertext = fixture["ciphertext"]
        key = fixture["key"]

        with open("plain.txt", "w") as f:
            f.write(plaintext)
        with open("key.txt", "w") as f:
            f.write(key)

        result = runner.invoke(
            cli,
            ["enc", "-k", "key.txt", "plain.txt"],
            catch_exceptions=False,
        )
        assert result.output == ciphertext

        result = runner.invoke(
            cli,
            ["enc", "-k", "key.txt", "-o", "out.txt", "plain.txt"],
        )
        assert result.output == ""
        assert open("out.txt").read() == ciphertext
        assert result.exit_code == 0

        result = runner.invoke(cli, ["enc", "-k", "key.txt"], input=plaintext)
        assert result.output == ciphertext
        assert result.exit_code == 0


def test_decrypt_defaults():
    fixture = load_fixtures()["cases"]["printable"]["case-fox"]

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("cipher.txt", "w") as f:
            f.write(fixture["ciphertext"])
        with open("key.txt", "w") as f:
            f.write(fixture["key"])

        result = runner.invoke(
            cli,
            ["dec", "-k", "key.txt", "cipher.txt"],
            catch_exceptions=False,
        )
        assert result.output == fixture["plaintext"]
        assert result.exit_code == 0

        result = runner.invoke(
            cli,
            ["dec", "-k", "key.txt", "-o", "out.txt", "cipher.txt"],
        )
        assert result.output == ""
        assert open("out.txt").read() == fixture["plaintext"]
        assert result.exit_code == 0

        result = runner.invoke(
            cli, ["dec", "-k", "key.txt"], input=fixture["ciphertext"]
        )
        assert result.output == fixture["plaintext"]
        assert result.exit_code == 0


def test_keygen():
    runner = CliRunner()
    result = runner.invoke(cli, ["keygen", "10"])
    assert len(result.output.rstrip("\n")) == 10
    assert result.exit_code == 0

    result = runner.invoke(cli, ["keygen", "-a", "letters", "20"])
    assert len(result.output.strip()) == 20
    assert result.exit_code == 0
    letters_set = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert all(c in letters_set for c in result.output.strip())

    # test alias
    result = runner.invoke(cli, ["genkey", "-a", "letters", "20"])
    assert len(result.output.strip()) == 20
    assert result.exit_code == 0
    letters_set = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert all(c in letters_set for c in result.output.strip())

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["keygen", "-a", "letters", "-o", "key.txt", "20"])
        assert result.output == ""

        key = open("key.txt").read()
        assert len(key) == 20
        assert all(c in letters_set for c in key.strip())

    result = runner.invoke(cli, ["keygen", "-f", "yaml", "10"])
    assert result.output.startswith("key: ")
    assert len(result.output) > 10
    assert result.exit_code == 0


def test_alphabet():
    runner = CliRunner()
    result = runner.invoke(cli, ["alphabet"])
    assert result.output.startswith("Known alphabets:")
    assert result.exit_code == 0

    result = runner.invoke(cli, ["alphabet", "printable"])
    assert result.output == ALPHABET_PRINTABLE.chars + "\n"
    assert result.exit_code == 0

    csv_printable = ''' ,!,"""",#,$,%,&,',(,),*,+,",",-,.,/,0,1,2,3,4,5,6,7,8,9,:,;,<,=,>,?,@,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,[,\\,],^,_,`,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,{,|,},~'''  # noqa: E501

    result = runner.invoke(cli, ["alphabet", "-c", "printable"])
    assert result.output == csv_printable + "\n"
    assert result.exit_code == 0

    result = runner.invoke(cli, ["alphabet", "letters"])
    assert result.output == ALPHABET_LETTERS_ONLY.chars + "\n"
    assert result.exit_code == 0

    result = runner.invoke(cli, ["alphabet", "--csv", "letters"])
    assert result.output == "A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z\n"
    assert result.exit_code == 0

    result = runner.invoke(cli, ["alphabet", "--tab", "letters"])
    assert result.output == "\t".join(string.ascii_uppercase) + "\n"
    assert result.exit_code == 0

    result = runner.invoke(cli, ["alphabet", "nonexistent"])
    assert result.output.startswith("Alphabet not found")
    assert result.exit_code == 1
