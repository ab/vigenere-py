import dataclasses
import string


@dataclasses.dataclass
class Alphabet:
    name: str
    chars: str
    passthrough: set[str]
    chars_dict: dict[str, int] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.chars_dict = {v: i for i, v in enumerate(self.chars)}
        self._passthrough_trans = str.maketrans({c: None for c in self.passthrough})

    def remove_passthrough(self, text: str) -> str:
        """
        Return the provided text with passthrough characters removed.
        """
        return text.translate(self._passthrough_trans)


ALPHABET_PRINTABLE = Alphabet(
    name="printable",
    chars=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",  # noqa: E501
    passthrough={"\t", "\n", "\v", "\f", "\r"},
)

ALPHABET_LETTERS_ONLY = Alphabet(
    name="letters",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    passthrough=set(string.punctuation + string.whitespace),
)
ALPHABET_ALPHANUMERIC_UPPER = Alphabet(
    name="alphanumeric-upper",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    passthrough=set(string.punctuation + string.whitespace),
)
ALPHABET_ALPHANUMERIC_MIXED = Alphabet(
    name="alphanumeric",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    passthrough=set(string.punctuation + string.whitespace),
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
    if name in ALPHABET_ALIASES:
        name = ALPHABET_ALIASES[name]

    return ALPHABETS[name]
