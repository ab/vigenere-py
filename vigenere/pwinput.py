"""
Utilities to get a password, while echoing a mask asterisk for each char.

GetPassError - This exception is raised if we fail to set up the terminal to
               avoid echoing the password contentx.

On Windows, the msvcrt module will be used.

This is a derived work that incorporates portions of CPython Lib/getpass.py,
used under the Python Software Foundation License Version 2.

Copyright (c) 2001-2024 Python Software Foundation
Copyright (c) 2024 Andy Brody
"""

import sys
from typing import List


__all__ = ["getpass_masked","GetPassError"]


def pwinput(prompt: str = "Password: ", mask: str = "•") -> str:
    """
    Like getpass.getpass(), but echo the mask character to stdout with each
    keystroke.
    """

    if not isinstance(mask, str):
        raise TypeError("mask must be a str, got {mask!r}")
    if len(mask) > 1:
        raise ValueError("mask must be a zero- or one-character str")

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

        if key == 3:
            # ^C pressed
            raise KeyboardInterrupt

        elif key == 13 or key == 4:
            # enter key or ^D pressed
            sys.stdout.write("\n")
            return "".join(enteredPassword)

        # ASCII chars BS(8) or DEL(128) are backspace.
        # In Linux terminals, typically 
        elif key in (8, 127):
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
        # if we're not stripping escapes out, then return anything raw
        if not strip_escapes:
            return ch

        # All C0 control codes we return as is

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
