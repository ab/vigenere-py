# Copyright (c) 2021 Al Sweigart
# Copyright (c) 2023 Andy Brody
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Adapted from pwinput, by Al Sweigart

A cross-platform Python module that displays **** for password input.
"""


import sys
from typing import List


def pwinput(prompt: str = "Password: ", mask: str = "•") -> str:
    """
    Like getpass.getpass(), but echo the mask character to stdout with each
    keystroke.
    """

    if not isinstance(prompt, str):
        raise TypeError(
            "prompt argument must be a str, not %s" % (type(prompt).__name__)
        )
    if not isinstance(mask, str):
        raise TypeError("mask argument must be a str, not %s" % (type(prompt).__name__))
    if len(mask) > 1:
        raise ValueError("mask argument must be a zero- or one-character str")

    if mask == "" or sys.stdin is not sys.__stdin__ or not sys.stdin.isatty():
        # Just use getpass if a mask is not needed.
        # Note that getpass will attempt to read/write directly from /dev/tty,
        # so if stdin is a pipe, getpass may still read from the terminal.
        import getpass

        return getpass.getpass(prompt)

    enteredPassword: List[str] = []

    sys.stdout.write(prompt)
    sys.stdout.flush()

    while True:
        key = ord(term_getchar(strip_escapes=True))

        if key == 13 or key == 4:
            # enter key or ^D pressed
            sys.stdout.write("\n")
            return "".join(enteredPassword)
        elif key in (8, 127):  # Backspace/Del key erases previous output.
            if len(enteredPassword) > 0:
                # Erase previous character
                # Print \b to move cursor, overwrite with space, then \b again
                sys.stdout.write("\b \b")
                sys.stdout.flush()
                enteredPassword = enteredPassword[:-1]
        elif 0 <= key <= 31:
            # Do nothing for unprintable characters.
            # We ignore arrow keys, home, end, etc.
            pass
        else:
            # Key is part of the password; display the mask character.
            char = chr(key)
            sys.stdout.write(mask)
            sys.stdout.flush()
            enteredPassword.append(char)


def win_term_getchar(strip_escapes: bool = True) -> str:
    """
    Call msvcrt.getch(), optionally skipping escape sequences.
    """
    while True:
        ch = getch()

        # https://docs.python.org/3/library/msvcrt.html
        # If the pressed key was a special function key, this will return
        # '\000' or '\xe0'; the next call will return the keycode.

        if not strip_escapes:
            return ch

        if ch == "\x00" or ch == "\xe0":
            # discard next keycode, part of escape sequence
            getch()
        else:
            return ch


def unix_term_getchar(strip_escapes: bool = True) -> str:
    """
    Read the next character from stdin, optionally skipping past any ANSI
    escape sequences.
    """
    ch: str = getch()

    while True:
        # handle ^C
        if ch == "\x03":
            raise KeyboardInterrupt

        if not strip_escapes:
            return ch

        # All C0 control codes except for ^C we return as is

        # When strip_escapes is set, we remove ANSI escape sequences starting
        # with ^[ (ESC)

        if ch != "\x1B":
            # not ESC
            return ch

        # read next char after ESC
        ch = getch()

        # Determine whether the next char is part of the escape sequence.
        if ch == "[":
            # This is a multi-byte CSI (Control Sequence Introducer)
            # sequence

            # Read next char
            ch = getch()

            # consume any parameter bytes in 0x30-0x3F [0-?]
            while "\x30" <= ch <= "\x3F":
                ch = getch()

            # consume any intermediate bytes in 0x20-0x2F [ -/]
            while "\x20" <= ch <= "\x2F":
                ch = getch()

            if "\x40" <= ch <= "\x7E":
                # correct final byte, continue with next char
                ch = getch()
                continue
            else:
                # invalid final byte... invalid escape sequence
                raise ValueError("Invalid ANSI CSI escape sequence")

        elif "\x40" <= ch <= "\x5F":
            # This is a C1 Fe escape sequence of two bytes, discard char
            # and continue after next char
            ch = getch()
            continue

        else:
            # Char following ESC is not part of an escape sequence, retry
            # loop and process as standalone character
            continue

        raise NotImplementedError("notreached")


def termios_getch():
    # type: () -> str
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch


if sys.platform == "win32":
    # Windows
    import msvcrt

    getch = msvcrt.getch
    term_getchar = win_term_getchar

else:
    # macOS and Linux
    import termios
    import tty

    getch = termios_getch
    term_getchar = unix_term_getchar
