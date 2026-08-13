import os


def get_bool_env(name: str, default: bool = False) -> bool:
    """
    Get a boolean from an environment variable.
    Any casing of 'true' or 1 is considered True.
    """
    return os.getenv(name, str(default)).lower() in ("true", "1")


def get_int_env(name: str, default: int) -> int:
    """
    Get an integer from an environment variable.
    Falls back to `default` when the variable is unset or not a valid integer.
    """
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
