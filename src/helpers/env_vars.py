import os


def get_bool_env(name: str, default: bool = False):
    """
    Get a boolean from an environment variable.
    Any casing of 'true' or 1 is considered True.
    """
    return os.getenv(name, str(default)).lower() in ("true", "1")
