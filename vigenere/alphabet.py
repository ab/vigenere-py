import dataclasses
import string


@dataclasses.dataclass
class Alphabet:
    chars: str
    passthrough: set[str]
    chars_dict: dict[str, int] = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        self.chars_dict = {v: i for i, v in enumerate(self.chars)}


ALPHABET_PRINTABLE = Alphabet(
    chars=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    passthrough={"\t", "\n", "\v", "\f", "\r"},
)

ALPHABET_LETTERS_ONLY = Alphabet(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    passthrough=set(string.punctuation + string.whitespace),
)
ALPHABET_ALPHANUMERIC_UPPER = Alphabet(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    passthrough=set(string.punctuation + string.whitespace),
)
ALPHABET_ALPHANUMERIC_MIXED = Alphabet(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
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
