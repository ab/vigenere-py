from click.testing import CliRunner
from vigenere.cli import cli


def test_version() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["--version"], catch_exceptions=False)
        assert result.exit_code == 0
        assert result.output.startswith("cli, version ")
