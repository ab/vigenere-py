class Error(Exception):
    pass


class CLIError(Error):
    pass


class CipherError(CLIError):
    pass


class InputError(CLIError):
    pass
