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
    aliases: set[str] = dataclasses.field(default_factory=set)

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

    @property
    def aliases_str(self) -> str:
        return "|".join(sorted(self.aliases))

    @property
    def chars_for_display(self) -> str:
        specials_map = {"\0": "␀", "\t": "␉", "\n": "␊", "\f": "␌", "\r": "␍"}
        trans = str.maketrans(specials_map)
        return self.chars.translate(trans)

    @property
    def chars_escaped(self) -> list[str]:
        specials_map = {
            "\0": "\\0", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r",
        }
        return [
            specials_map[c] if c in specials_map else c for c in self.chars
        ]

    def char_to_digits(self, char: str) -> str:
        """
        Given a char, return a 2-digit int (base 10) index in the alphabet.

        e.g. "~" -> "99"
        """
        return "%02d" % self.chars_dict[char]


ALPHABET_DECIMAL = Alphabet(
    name="decimal",
    chars="\0\t\n\f\r !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",  # noqa: E501
    passthrough=set(),  # NB: \v not in passthrough, unlike printable
    description="100-char full ASCII, ciphertext written as digits",
)

ALPHABET_PRINTABLE = Alphabet(
    name="printable",
    chars=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",  # noqa: E501
    passthrough={"\t", "\n", "\v", "\f", "\r"},
    description="All printable characters except tabs/newlines",
)

ALPHABET_LETTERS_ONLY = Alphabet(
    name="letters",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    passthrough=set(string.punctuation + string.whitespace),
    description="Uppercase letters only",
)
ALPHABET_ALPHANUMERIC_UPPER = Alphabet(
    name="alpha-upper",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    passthrough=set(string.punctuation + string.whitespace),
    description="Uppercase letters and numbers",
)
ALPHABET_ALPHANUMERIC_MIXED = Alphabet(
    name="alpha-mixed",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    passthrough=set(string.punctuation + string.whitespace),
    description="Mixed case letters and numbers",
)


ALPHABETS: dict[str, Alphabet] = {
    "decimal": ALPHABET_DECIMAL,
    "printable": ALPHABET_PRINTABLE,
    "letters": ALPHABET_LETTERS_ONLY,
    "alpha-mixed": ALPHABET_ALPHANUMERIC_MIXED,
    "alpha-upper": ALPHABET_ALPHANUMERIC_UPPER,
}


ALPHABET_ALIASES: dict[str, str] = {
    "100": "decimal",
    "ascii": "printable",
    "upper": "letters",
    "uppercase": "letters",
    "alpha": "alpha-mixed",
    "alphanumeric": "alpha-mixed",
    "alphanumeric-upper": "alpha-upper",
    "alphanumeric-mixed": "alpha-mixed",
}


for alias, target in ALPHABET_ALIASES.items():
    ALPHABETS[target].aliases.add(alias)


def get_alphabet(name: str) -> Alphabet:
    """
    Look up an Alphabet by name or alias.
    """
    if name in ALPHABET_ALIASES:
        name = ALPHABET_ALIASES[name]

    return ALPHABETS[name]


def list_alphabets_labels(aliases: bool = True) -> str:
    """
    Print help text describing each alphabet.
    """
    return "\n".join(
        "\n".join(
            [
                "  " + a.name + ":",
                "      " + a.description,
                "      aliases: " + "(" + a.aliases_str + ")",
                "      chars: " + a.chars_for_display,
                "",
            ]
        )
        for a in ALPHABETS.values()
    )
