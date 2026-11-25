# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import re
from string import punctuation

_FORMATTED_FIELD = re.compile(rf"(?:[a-z0-9._*?-]|\\[{re.escape(punctuation)}])+")
_URI_FIELD = re.compile(r"(?:[a-z0-9._~-]|%[0-9a-f]{2})*")
_URI_ESCAPES = set(punctuation) - {".", "-", "_"}


def split_cpe_fields(identifier: str) -> list[str] | None:
    """Split on unescaped colons, retaining escapes for the caller."""
    parts = re.findall(r"((?:\\.|[^:\\])*)(:|$)", identifier)
    if "".join(field + delimiter for field, delimiter in parts) != identifier:
        return None
    return [field for field, _ in parts[:-1]]


def _cpe_literal(value: str) -> str:
    return "\\" + value if value in {"\\", "*", "?"} else value


def _uri_field(value: str) -> str:
    if not value:
        return "*"

    def decode(match: re.Match[str]) -> str:
        char = chr(int(match[0][1:], 16))
        # In the URI binding, these bytes encode wildcard operators.
        if char in {"\x01", "\x02"}:
            return "?" if char == "\x01" else "*"
        if char not in _URI_ESCAPES:
            raise ValueError("Invalid CPE URI escape")
        return _cpe_literal(char)

    return re.sub(r"%[0-9a-f]{2}", decode, value)


def cpe_identity(identifier: str) -> str | tuple[str, ...]:
    """Compare CPE bindings by exact attributes, not wildcard coverage."""
    value = identifier.lower()
    if value.startswith("cpe:2.3:"):
        fields = split_cpe_fields(value)
        if fields and len(fields) == 13 and all(map(_FORMATTED_FIELD.fullmatch, fields[2:])):
            return tuple(re.sub(r"\\(.)", lambda match: _cpe_literal(match[1]), field)
                         if field != r"\-" else field for field in fields[2:])
    elif value.startswith("cpe:/"):
        attrs = value[5:].split(":")
        if len(attrs) <= 7:
            attrs += [""] * (7 - len(attrs))
            edition = attrs[5]
            if edition.startswith("~"):
                packed = edition[1:].split("~")
                if len(packed) != 5:
                    return identifier
                attrs[5], *extra = packed
                attrs.extend(extra)
            else:
                attrs.extend([""] * 4)
            if all(map(_URI_FIELD.fullmatch, attrs)):
                try:
                    return tuple(map(_uri_field, attrs))
                except ValueError:
                    pass
    return identifier
