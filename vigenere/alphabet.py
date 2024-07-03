import dataclasses
import secrets
import string
import textwrap


from .errors import InputError


@dataclasses.dataclass
class Alphabet:
    name: str
    chars: str
    passthrough: set[str]
    chars_dict: dict[str, int] = dataclasses.field(init=False)
    description: str = ""
    description_passthrough: str = ""
    aliases: set[str] = dataclasses.field(default_factory=set)
    decimal: bool = False
    specials_map: dict[str, str] | None = None

    def __post_init__(self) -> None:
        self.chars_dict = {v: i for i, v in enumerate(self.chars)}
        self._passthrough_trans = str.maketrans({c: None for c in self.passthrough})

    def prepare_key(self, text: str) -> str:
        """
        Given key text, prepare for use in encryption/decryption.
        - Remove passthrough characters.
        - If this alphabet has decimal=True, convert decimal input to chars.
        """
        cleaned = self.remove_passthrough(text)

        if self.decimal:
            return self.decimal_decode(cleaned)
        else:
            return cleaned

    def remove_passthrough(self, text: str) -> str:
        """
        Return the provided text with passthrough characters removed.
        """
        return text.translate(self._passthrough_trans)

    def generate_key(self, length: int, auto_decimal: bool = True) -> str:
        """
        Generate a key from this alphabet, using the `secrets` module CSPRNG.
        """
        key = "".join(secrets.choice(self.chars) for i in range(length))

        if self.decimal and auto_decimal:
            return self.decimal_encode(key)

        return key

    @property
    def aliases_str(self) -> str:
        return "|".join(sorted(self.aliases))

    @property
    def ansi_spaces(self) -> bool:
        """
        Default setting for whether output should use fancy ansi inverted color
        spaces. This will default to true if space is in the alphabet and this
        isn't a decimal alphabet.
        """
        return " " in self.chars_dict and not self.decimal

    @property
    def chars_for_display(self) -> str:
        specials_map = {"\0": "␀", "\t": "␉", "\n": "␊", "\f": "␌", "\r": "␍"}
        trans = str.maketrans(specials_map)
        return self.chars.translate(trans)

    @property
    def chars_escaped(self) -> list[str]:
        specials_map = {"\0": "\\0", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
        return [specials_map[c] if c in specials_map else c for c in self.chars]

    def _char_to_decimal(self, char: str) -> str:
        """
        Given a char, return a 2-digit int (base 10) index in the alphabet.

        e.g. if alphabet='decimal':
            "~" -> "99"
        """
        try:
            return "%02d" % self.chars_dict[char]
        except KeyError as err:
            raise InputError(
                f"Invalid input char {char!r} for alphabet {self.name!r}"
            ) from err

    def decimal_encode(self, text: str, wrap: int | None = 60) -> str:
        """
        Format string as a series of 2-digit int (base 10) indexes in the
        alphabet. Each 2-digit number is separated by spaces.

        e.g. if alphabet='decimal':
            "FOO!" -> "43 52 52 06"
        """

        encoded = " ".join(self._char_to_decimal(c) for c in text)
        if wrap:
            return textwrap.fill(encoded, width=wrap)
        return encoded

    def decimal_decode(self, decimals: str) -> str:
        """
        Given a string of whitespace separated decimals that represent indexes
        in the alphabet, convert to a string of chars in the alphabet.

        e.g. if alphabet='decimal':
            "43 52 52 06" -> "FOO!"
        """

        s = ""
        for dec in decimals.split():
            try:
                num = int(dec)
            except ValueError as err:
                raise InputError(f"Invalid decimal input: {dec!r}") from err

            if num < 0:
                raise InputError(f"Negative numbers are invalid: {num!r}")
            if num >= len(self.chars):
                maxnum = len(self.chars) - 1
                raise InputError(
                    f"Invalid input for alphabet: {dec!r} not in 0..{maxnum!r}"
                )

            s += self.chars[num]

        return s


ALPHABET_DECIMAL = Alphabet(
    name="decimal",
    decimal=True,
    chars="\0\t\n\f\r !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",  # noqa: E501
    passthrough=set(),  # NB: \v not in passthrough, unlike printable
    description="100-char full ASCII, ciphertext written as digits",
    description_passthrough="none",
)

ALPHABET_PRINTABLE = Alphabet(
    name="printable",
    chars=" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",  # noqa: E501
    passthrough={"\t", "\n", "\v", "\f", "\r"},
    description="All printable characters and spaces",
    description_passthrough="other whitespace",
)

ALPHABET_LETTERS_ONLY = Alphabet(
    name="letters",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    passthrough=set(string.punctuation + string.whitespace),
    description="Uppercase letters only",
    description_passthrough="punctuation/whitespace",
)
ALPHABET_ALPHANUMERIC_UPPER = Alphabet(
    name="alpha-upper",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    passthrough=set(string.punctuation + string.whitespace),
    description="Uppercase letters and numbers",
    description_passthrough="punctuation/whitespace",
)
ALPHABET_ALPHANUMERIC_MIXED = Alphabet(
    name="alpha-mixed",
    chars="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    passthrough=set(string.punctuation + string.whitespace),
    description="Mixed case letters and numbers",
    description_passthrough="punctuation/whitespace",
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
    "ascii": "decimal",
    "print": "printable",
    "wheel": "printable",
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
    if not isinstance(name, str):
        raise ValueError(f"name must be str, got {name!r}")

    if name in ALPHABET_ALIASES:
        name = ALPHABET_ALIASES[name]

    return ALPHABETS[name]


def list_alphabets_labels(aliases: bool = True) -> str:
    """
    Return help text describing each alphabet.
    """
    return "\n".join(
        "\n".join(
            [
                "  " + a.name + ":",
                "      " + a.description,
                "      aliases: " + "(" + a.aliases_str + ")",
                "      passthrough: " + a.description_passthrough,
                "      chars: " + a.chars_for_display,
                "",
            ]
        )
        for a in ALPHABETS.values()
    )


def list_alphabets_names(aliases: bool = True) -> list[str]:
    """
    List all known alphabet names.
    """
    alphas = list(ALPHABETS.keys())
    if aliases:
        alphas += list(ALPHABET_ALIASES.keys())

    return alphas
