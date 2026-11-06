"""Input checks shared by the web forms and the API.

Each function returns the cleaned value or raises InputError with a message
that can be shown to the user as is.
"""
import ipaddress
import re


class InputError(Exception):
    """Invalid input. status is 400, or 409 when the input conflicts with existing data."""
    def __init__(self, message, status=400):
        # Initialize the parent Exception with the error message.
        super().__init__(message)
        self.message = message
        self.status = status


def text(value, name, max_len, required=True):
    """Trimmed text; None when an optional field is empty."""
    if value is not None and not isinstance(value, str):
        raise InputError(f"{name} must be text.")
    value = (value or "").strip()
    if not value:
        if required:
            raise InputError(f"{name} is required.")
        return None
    if len(value) > max_len:
        raise InputError(f"{name} must be at most {max_len} characters long.")
    return value


def flag(value):
    """Boolean as 0 or 1."""
    if isinstance(value, bool):
        return int(value)
    return 1 if str(value).strip().lower() in ("1", "on", "true", "yes") else 0


def username(value):
    value = text(value, "Username", 50)
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,50}", value):
        raise InputError("Username must be 3 to 50 letters, digits, dots, underscores or hyphens.")
    return value


def password(value, user_name):
    # Not trimmed: spaces are valid password characters.
    if not isinstance(value, str) or not 12 <= len(value) <= 128 \
            or value.lower() == user_name.lower():
        raise InputError("The password must be 12 to 128 characters long and differ "
                         "from the username.")
    return value


def domain(value):
    """Registered domain in lower case, e.g. example.com (punycode for IDNs (Internationalized Domain Names), no trailing dot)."""
    value = text(value, "Domain", 253).lower()
    labels = value.split(".")
    if (
        not value.isascii()
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63 # A label must be between 1 and 63 characters long.
            or label.startswith("-")
            or label.endswith("-")
            or not all(c.isalnum() or c == "-" for c in label)
            for label in labels
        )
        or len(labels[-1]) < 2
    ):
        raise InputError("Invalid domain name.")
    return value


def keyword(value):
    """Brand word in lower case: letters, digits and hyphens, no dots."""
    value = text(value, "Keyword", 63).lower()
    if not re.fullmatch(r"[a-z0-9-]{2,63}", value):
        raise InputError("Keyword must be 2 to 63 letters, digits or hyphens.")
    return value


# Address space that is never a valid scan target.
RESERVED = [ipaddress.ip_network(n) for n in
            ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4")]


def network(value, max_addresses):
    """IPv4 address, CIDR block, range or last-octet range, in canonical form.

    Accepted: 198.51.100.7, 198.51.100.0/24, 198.51.100.10-198.51.100.40,
    198.51.100.10-40. Stored as a CIDR block when the range is exactly one
    block (a single address is /32), otherwise as first-last.
    """
    value = text(value, "Network", 40).replace(" ", "")
    try:
        if "/" in value:
            block = ipaddress.IPv4Network(value)  # strict: rejects host bits, e.g. .5/24; write .0/24
            first, last = block.network_address, block.broadcast_address
        elif "-" in value:
            start, end = value.split("-", 1)
            if end.isdigit():  # last-octet form 198.51.100.10-40
                end = start.rsplit(".", 1)[0] + "." + end
            first, last = ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
        else:
            first = last = ipaddress.IPv4Address(value)
    except ValueError:
        raise InputError("Network must be an IPv4 address, a CIDR block (198.51.100.0/24) "
                         "or a range (198.51.100.10-40).") from None
    if first > last:
        raise InputError("The first address of the range must not be greater than the last.")
    if int(last) - int(first) + 1 > max_addresses:
        raise InputError(f"The network is too large; at most {max_addresses} addresses "
                         f"are allowed.")
    for reserved in RESERVED:
        if first <= reserved.broadcast_address and last >= reserved.network_address:
            raise InputError(f"The network overlaps the reserved range {reserved}.")
    blocks = list(ipaddress.summarize_address_range(first, last))
    return blocks[0].with_prefixlen if len(blocks) == 1 else f"{first}-{last}"


def key_prefix(value):
    """API key prefix chosen by the owner, e.g. n8n. No "_": it separates the key's parts."""
    value = text(value, "Prefix", 32).lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,30}[a-z0-9]", value):
        raise InputError("Prefix must be 3 to 32 letters, digits or hyphens, starting and "
                         "ending with a letter or digit.")
    return value
