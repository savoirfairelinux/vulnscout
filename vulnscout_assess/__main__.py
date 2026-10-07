import sys

IMPORT_HINT = (
    "vulnscout cve-assessment needs Python 3.10+ with httpx installed (pip install httpx, "
    "or use the repo venv); set VULNSCOUT_PYTHON to choose the interpreter"
)


def _load_main():
    from .cli import main
    return main


def entry(loader=_load_main) -> int:
    try:
        main = loader()
    except ImportError:
        print(IMPORT_HINT, file=sys.stderr)
        return 1
    return main()


if __name__ == "__main__":
    raise SystemExit(entry())
