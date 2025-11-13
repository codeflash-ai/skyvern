import re

_whitespace_pattern = re.compile(r"[ \n\t]+")


def remove_whitespace(string: str) -> str:
    return _whitespace_pattern.sub(" ", string)
