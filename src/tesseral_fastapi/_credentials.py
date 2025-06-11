import re


def is_jwt_format(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", value))


def is_api_key_format(value: str) -> bool:
    return bool(re.match(r"^[a-z0-9_]+$", value))
