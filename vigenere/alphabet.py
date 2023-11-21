import dataclasses
import secrets
import string


@dataclasses.dataclass
class Alphabet:
    name: str
    chars: str
    passthrough: set[str]
    chars_dict: dict[str, int] = dataclasses.field(init=False)
    description: str = ""

    def __post_init__(self) -> None:
        self.chars_dict = {v: i for i, v in enumerate(self.chars)}
        self._passthrough_trans = str.maketrans({c: None for c in self.passthrough})

    def remove_passthrough(self, text: str) -> str:
        """
        Return the provided text with passthrough characters removed.
        """
        return text.translate(self._passthrough_trans)

    def generate_key(self, length: int) -> str:
        """
        Generate a key from this alphabet, using the `secrets` module CSPRNG.
        """
        return "".join(secrets.choice(self.chars) for i in range(length))


ALPHABET_PRINTABLE = Alphabet(
    name="printable",
    chars=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",  # noqa: E501
    passthrough={"\t", "\n", "\v", "\f", "\r"},
    description="All printable characters except tabs",
)

ALPHABET_LETTERS_ONLY = Alphabet(
    name="letters",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    passthrough=set(string.punctuation + string.whitespace),
    description="Uppercase letters only",
)
ALPHABET_ALPHANUMERIC_UPPER = Alphabet(
    name="alphanumeric-upper",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    passthrough=set(string.punctuation + string.whitespace),
    description="Uppercase letters and numbers",
)
ALPHABET_ALPHANUMERIC_MIXED = Alphabet(
    name="alphanumeric",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    passthrough=set(string.punctuation + string.whitespace),
    description="Mixed case letters and numbers",
)


ALPHABETS: dict[str, Alphabet] = {
    "printable": ALPHABET_PRINTABLE,
    "letters": ALPHABET_LETTERS_ONLY,
    "alphanumeric": ALPHABET_ALPHANUMERIC_MIXED,
    "alphanumeric-upper": ALPHABET_ALPHANUMERIC_UPPER,
}


ALPHABET_ALIASES: dict[str, str] = {
    "upper": "letters",
    "uppercase": "letters",
    "alphanumeric-mixed": "alphanumeric",
}


def get_alphabet(name: str) -> Alphabet:
    """
    Look up an Alphabet by name or alias.
    """
    if name in ALPHABET_ALIASES:
        name = ALPHABET_ALIASES[name]

    return ALPHABETS[name]


def list_alphabets_labels() -> str:
    """
    Print help text describing each alphabet.
    """
    longest = max(len(a.name) for a in ALPHABETS.values())

    return "\n".join(
        "  - " + a.name.ljust(longest) + "\t" + a.description
        for a in ALPHABETS.values()
    )
