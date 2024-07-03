import string
import textwrap
from pathlib import Path

import pytest
import strictyaml
from click.shell_completion import shell_complete
from click.testing import CliRunner

from vigenere.alphabet import (
    ALPHABET_PRINTABLE,
    ALPHABET_LETTERS_ONLY,
    list_alphabets_names,
)
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
            insecure = info.get("insecure", False)
            output.append((alphabet_name, name, key, plain, ciphertext, insecure))

    return output


def load_decimal_cases() -> list[tuple[str]]:
    cases = load_fixtures()["cases"]
    output = []

    for alphabet_name, casedict in cases.items():
        for name, info in casedict.items():
            if "plaintext_decimal" not in info:
                continue

            plain = info["plaintext"]
            decimal = info["plaintext_decimal"]
            output.append((alphabet_name, name, plain, decimal))

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


@pytest.mark.parametrize(
    "alphabet_name,test_name,key,plain,ciphertext,insecure", load_cases()
)
def test_encrypt_fixtures(alphabet_name, test_name, key, plain, ciphertext, insecure):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("plain.txt", "w") as f:
            f.write(plain)
        with open("key.txt", "w") as f:
            f.write(key)

        if insecure:
            opts = ["--insecure"]
        else:
            opts = []

        result = runner.invoke(
            cli,
            ["enc", "-a", alphabet_name, "-k", "key.txt"] + opts + ["plain.txt"],
            catch_exceptions=False,
        )
        assert result.output == ciphertext
        assert result.exit_code == 0


@pytest.mark.parametrize(
    "alphabet_name,test_name,key,plain,ciphertext,insecure", load_cases()
)
def test_decrypt_fixtures(alphabet_name, test_name, key, plain, ciphertext, insecure):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("cipher.txt", "w") as f:
            f.write(ciphertext)
        with open("key.txt", "w") as f:
            f.write(key)

        if insecure:
            opts = ["--insecure"]
        else:
            opts = []

        result = runner.invoke(
            cli,
            ["dec", "-a", alphabet_name, "-k", "key.txt"] + opts + ["cipher.txt"],
            catch_exceptions=False,
        )
        assert result.output == plain
        assert result.exit_code == 0


@pytest.mark.parametrize("args", [["enc"], ["dec"], ["keygen", "5"]])
def test_alphabet_defaults(args: list[str]) -> None:
    runner = CliRunner()

    result = runner.invoke(cli, args)

    assert "Error: Must set option -a/--alphabet" in result.output
    assert result.exit_code == 2


def test_encrypt_env():
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

        env = {"VIGENERE_ALPHABET": "printable"}

        result = runner.invoke(
            cli,
            ["enc", "-k", "key.txt", "plain.txt"],
            catch_exceptions=False,
            env=env,
        )
        assert result.output == ciphertext

        result = runner.invoke(
            cli,
            ["enc", "-k", "key.txt", "-o", "out.txt", "plain.txt"],
            env=env,
        )
        assert result.output == ""
        assert open("out.txt").read() == ciphertext
        assert result.exit_code == 0

        result = runner.invoke(cli, ["enc", "-k", "key.txt"], input=plaintext, env=env)
        assert result.output == ciphertext
        assert result.exit_code == 0


def test_decrypt_env():
    fixture = load_fixtures()["cases"]["printable"]["case-fox"]

    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("cipher.txt", "w") as f:
            f.write(fixture["ciphertext"])
        with open("key.txt", "w") as f:
            f.write(fixture["key"])

        env = {"VIGENERE_ALPHABET": "printable"}

        result = runner.invoke(
            cli,
            ["dec", "-k", "key.txt", "cipher.txt"],
            catch_exceptions=False,
            env=env,
        )
        assert result.output == fixture["plaintext"]
        assert result.exit_code == 0

        result = runner.invoke(
            cli,
            ["dec", "-k", "key.txt", "-o", "out.txt", "cipher.txt"],
            catch_exceptions=False,
            env=env,
        )
        assert result.output == ""
        assert open("out.txt").read() == fixture["plaintext"]
        assert result.exit_code == 0

        result = runner.invoke(
            cli,
            ["dec", "-k", "key.txt"],
            input=fixture["ciphertext"],
            catch_exceptions=False,
            env=env,
        )
        assert result.output == fixture["plaintext"]
        assert result.exit_code == 0


def test_encrypt_errors():
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("badchars.txt", "w") as f:
            f.write("foo")
        with open("short.txt", "w") as f:
            f.write("AA")
        with open("plain.txt", "w") as f:
            f.write("FOO")
        with open("key.txt", "w") as f:
            f.write("KEY")

        result = runner.invoke(
            cli,
            ["enc", "-a", "letters", "-k", "nonexistent.txt", "plain.txt"],
            catch_exceptions=False,
        )
        assert result.output.endswith("No such file or directory\n")
        assert result.exit_code == 2

        result = runner.invoke(
            cli,
            ["enc", "-a", "letters", "-k", "key.txt", "nonexistent.txt"],
            catch_exceptions=False,
        )
        assert result.output.endswith("No such file or directory\n")
        assert result.exit_code == 2

        result = runner.invoke(
            cli,
            ["enc", "-a", "letters", "-k", "short.txt", "plain.txt"],
            catch_exceptions=False,
        )
        assert result.output == "Error: Key is shorter than plaintext\n"
        assert result.exit_code == 3

        # bad char in key
        result = runner.invoke(
            cli,
            ["enc", "-a", "letters", "-k", "badchars.txt", "plain.txt"],
            catch_exceptions=False,
        )
        assert (
            result.output
            == "Error: Invalid character for alphabet 'letters' in key: 'f'\n"
        )
        assert result.exit_code == 3

        # bad char in text
        result = runner.invoke(
            cli,
            ["enc", "-a", "letters", "-k", "key.txt", "badchars.txt"],
            catch_exceptions=False,
        )
        assert (
            result.output
            == "Error: Invalid character for alphabet 'letters' in plaintext input: 'f'\n"
        )
        assert result.exit_code == 3


def test_decrypt_errors():
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("badchars.txt", "w") as f:
            f.write("foo")
        with open("short.txt", "w") as f:
            f.write("AA")
        with open("input.txt", "w") as f:
            f.write("FOO")
        with open("key.txt", "w") as f:
            f.write("KEY")

        result = runner.invoke(
            cli,
            ["dec", "-a", "letters", "-k", "nonexistent.txt", "input.txt"],
            catch_exceptions=False,
        )
        assert result.output.endswith("No such file or directory\n")
        assert result.exit_code == 2

        result = runner.invoke(
            cli,
            ["dec", "-a", "letters", "-k", "key.txt", "nonexistent.txt"],
            catch_exceptions=False,
        )
        assert result.output.endswith("No such file or directory\n")
        assert result.exit_code == 2

        result = runner.invoke(
            cli,
            ["dec", "-a", "letters", "-k", "short.txt", "input.txt"],
            catch_exceptions=False,
        )
        assert result.output == "Error: Key is shorter than ciphertext\n"
        assert result.exit_code == 3

        # bad char in key
        result = runner.invoke(
            cli,
            ["dec", "-a", "letters", "-k", "badchars.txt", "input.txt"],
            catch_exceptions=False,
        )
        assert (
            result.output
            == "Error: Invalid character for alphabet 'letters' in key: 'f'\n"
        )
        assert result.exit_code == 3

        # bad char in text
        result = runner.invoke(
            cli,
            ["dec", "-a", "letters", "-k", "key.txt", "badchars.txt"],
            catch_exceptions=False,
        )
        assert (
            result.output
            == "Error: Invalid character for alphabet 'letters' in ciphertext input: 'f'\n"
        )
        assert result.exit_code == 3


def test_keygen():
    runner = CliRunner()

    result = runner.invoke(cli, ["keygen", "10"])
    assert "Must set option -a/--alphabet" in result.output
    assert result.exit_code == 2

    result = runner.invoke(cli, ["keygen", "10"], env={"VIGENERE_ALPHABET": "nonesuch"})
    assert "Invalid value for $VIGENERE_ALPHABET: 'nonesuch'" in result.output
    assert result.exit_code == 1

    result = runner.invoke(cli, ["keygen", "-a", "nonesuch", "10"])
    assert "Invalid value for -a/--alphabet: 'nonesuch'" in result.output
    assert result.exit_code == 1

    result = runner.invoke(
        cli, ["keygen", "10"], env={"VIGENERE_ALPHABET": "printable"}
    )
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

    result = runner.invoke(cli, ["keygen", "-f", "yaml", "-a", "printable", "10"])
    assert result.output.startswith("key: ")
    assert len(result.output) > 10
    assert result.exit_code == 0


def test_alphabet_list():
    runner = CliRunner()
    result = runner.invoke(cli, ["alphabet"])
    assert result.output.startswith("Known alphabets:")
    assert result.exit_code == 0
    assert (
        result.output.strip()
        == """
Known alphabets:
  decimal:
      100-char full ASCII, ciphertext written as digits
      aliases: (100|ascii)
      passthrough: none
      chars: ␀␉␊␌␍ !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~

  printable:
      All printable characters and spaces
      aliases: (print|wheel)
      passthrough: other whitespace
      chars:  !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~

  letters:
      Uppercase letters only
      aliases: (upper|uppercase)
      passthrough: punctuation/whitespace
      chars: ABCDEFGHIJKLMNOPQRSTUVWXYZ

  alpha-mixed:
      Mixed case letters and numbers
      aliases: (alpha|alphanumeric|alphanumeric-mixed)
      passthrough: punctuation/whitespace
      chars: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789

  alpha-upper:
      Uppercase letters and numbers
      aliases: (alphanumeric-upper)
      passthrough: punctuation/whitespace
      chars: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
""".strip()  # noqa: E501
    )

    result = runner.invoke(cli, ["alphabet", "-f", "csv"])
    assert result.exit_code == 0
    assert (
        result.output
        == "\n".join(
            [
                "name,description,aliases",
                'decimal,"100-char full ASCII, ciphertext written as digits",100|ascii',
                "printable,All printable characters and spaces,print|wheel",
                "letters,Uppercase letters only,upper|uppercase",
                "alpha-mixed,Mixed case letters and numbers,alpha|alphanumeric|alphanumeric-mixed",  # noqa: E501
                "alpha-upper,Uppercase letters and numbers,alphanumeric-upper",
            ]
        )
        + "\n"
    )

    result = runner.invoke(cli, ["alphabet", "-f", "tab"])
    assert result.exit_code == 0
    assert (
        result.output
        == "\n".join(
            [
                "decimal\t100-char full ASCII, ciphertext written as digits\t100|ascii",
                "printable\tAll printable characters and spaces\tprint|wheel",
                "letters\tUppercase letters only\tupper|uppercase",
                "alpha-mixed\tMixed case letters and numbers\talpha|alphanumeric|alphanumeric-mixed",  # noqa: E501
                "alpha-upper\tUppercase letters and numbers\talphanumeric-upper",
            ]
        )
        + "\n"
    )


def test_alphabet():
    runner = CliRunner()

    result = runner.invoke(cli, ["alphabet", "printable"])
    assert result.output == ALPHABET_PRINTABLE.chars + "\n"
    assert result.exit_code == 0

    csv_printable = ''' ,!,"""",#,$,%,&,',(,),*,+,",",-,.,/,0,1,2,3,4,5,6,7,8,9,:,;,<,=,>,?,@,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,[,\\,],^,_,`,a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,{,|,},~'''  # noqa: E501

    result = runner.invoke(cli, ["alphabet", "--csv", "printable"])
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

    result = runner.invoke(cli, ["alphabet", "nonesuch"])
    assert "Invalid value for -a/--alphabet: 'nonesuch'" in result.output
    assert result.exit_code == 1

    result = runner.invoke(cli, ["alphabet", "--table", "letters"])
    assert result.exit_code == 0
    letters_table = "\n".join(
        "%02d" % (ord(c) - ord("A")) + "\t" + c for c in ALPHABET_LETTERS_ONLY.chars
    )
    assert result.output == letters_table + "\n"

    result = runner.invoke(cli, ["alphabet", "--format", "bad", "letters"])
    assert "Invalid value" in result.output
    assert result.exit_code == 2


def test_decimal():
    runner = CliRunner()

    result = runner.invoke(cli, ["decimal"])
    assert "Must set option -a/--alphabet" in result.output
    assert result.exit_code == 2

    result = runner.invoke(cli, ["decimal", "-a", "100"])
    assert "Must set mode -e or -d" in result.output
    assert result.exit_code == 1

    plain = "Hello!"
    decimal = "45 74 81 81 84 06"

    result = runner.invoke(cli, ["decimal", "-a", "100", "--encode"], input=plain)
    assert result.output == decimal + "\n"
    assert result.exit_code == 0

    result = runner.invoke(cli, ["decimal", "-a", "100", "--decode"], input=decimal)
    assert result.output == plain
    assert result.exit_code == 0

    # test wrapping
    result = runner.invoke(
        cli, ["decimal", "-a", "100", "--encode", "-w", "5"], input=plain
    )
    assert result.output == "45 74\n81 81\n84 06\n"
    assert result.exit_code == 0

    result = runner.invoke(
        cli, ["decimal", "-a", "letters", "--encode", "-w", "2"], input="ABC"
    )
    assert result.output == "00\n01\n02\n"
    assert result.exit_code == 0


@pytest.mark.parametrize("alphabet_name,test_name,plain,decimal", load_decimal_cases())
def test_decimal_fixtures(alphabet_name, test_name, plain, decimal):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("plain.txt", "w") as f:
            f.write(plain)
        with open("decimal.txt", "w") as f:
            f.write(decimal)

        result = runner.invoke(
            cli,
            ["decimal", "-a", alphabet_name, "-e", "plain.txt"],
            catch_exceptions=False,
        )

        # normalize text wrapping so fixture doesn't need to exactly match
        # newlines of output
        wrapped = textwrap.fill(decimal, width=60) + "\n"

        assert result.output == wrapped
        assert result.exit_code == 0

        result = runner.invoke(
            cli,
            ["decimal", "-a", alphabet_name, "-d", "decimal.txt"],
            catch_exceptions=False,
        )

        # hack to handle passthrough chars + newline behavior
        if alphabet_name == "letters":
            expected_plain = plain.replace(" ", "") + "\n"
        elif alphabet_name == "printable":
            expected_plain = plain.replace("\n", "") + "\n"
        else:
            expected_plain = plain

        assert result.output == expected_plain
        assert result.exit_code == 0


@pytest.mark.parametrize(
    "alphabet_name,opts,text,error",
    [
        ("100", ["-e"], "foo \v bar", "Invalid input char '\\x0b'"),
        ("printable", ["-e"], "Vigènere", "Invalid input char 'è'"),
        ("100", ["-d"], "10 abc", "Invalid decimal input: 'abc'"),
        ("letters", ["-d"], "10 50", "Invalid input for alphabet: '50' not in 0..25"),
    ],
)
def test_decimal_errors(
    alphabet_name: str, opts: list[str], text: str, error: str
) -> None:
    runner = CliRunner()

    result = runner.invoke(cli, ["decimal", "-a", alphabet_name] + opts, input=text)
    assert error in result.output
    assert result.exit_code == 3


@pytest.fixture()
def _patch_for_completion(monkeypatch):
    monkeypatch.setattr(
        "click.shell_completion.BashComplete._check_version", lambda self: True
    )


@pytest.mark.usefixtures("_patch_for_completion")
def test_tab_completion(monkeypatch, capsys) -> None:
    """
    This is a somewhat convoluted way to test that tab completion works.

    Previously this was accidentally broken by printing text and exiting
    nonzero within a param validator callback. Click gracefully swallows
    click.UsageError exceptions within tab completion, but not directly
    printing to stderr.
    """

    complete_env = {
        "_VIGENERE_COMPLETE": "bash_complete",
        "COMP_WORDS": "vigenere\nkeygen\n--alpha\n",
        "COMP_CWORD": "2",
    }

    for k, v in complete_env.items():
        monkeypatch.setenv(k, v)

    rv = shell_complete(
        cli,
        {},
        "vigenere",
        complete_var="_VIGENERE_COMPLETE",
        instruction="bash_complete",
    )
    captured = capsys.readouterr()

    assert captured.out == "plain,--alphabet\n"
    assert captured.err == ""
    assert rv == 0


@pytest.mark.usefixtures("_patch_for_completion")
def test_tab_completion_arg(monkeypatch, capsys) -> None:
    """
    Test custom tab completion
    """

    complete_env = {
        "_VIGENERE_COMPLETE": "bash_complete",
        "COMP_WORDS": "vigenere\nkeygen\n--alphabet\n\n",
        "COMP_CWORD": "3",
    }

    for k, v in complete_env.items():
        monkeypatch.setenv(k, v)

    rv = shell_complete(
        cli,
        {},
        "vigenere",
        complete_var="_VIGENERE_COMPLETE",
        instruction="bash_complete",
    )
    captured = capsys.readouterr()

    alphas = list_alphabets_names(aliases=True)
    assert alphas
    assert "decimal" in alphas

    expected = "\n".join(["plain," + name for name in alphas])

    assert captured.out == expected + "\n"
    assert captured.err == ""
    assert rv == 0
