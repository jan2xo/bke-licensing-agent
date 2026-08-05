from typing import Sequence

from .app import app


def main(args: Sequence[str] | None = None) -> None:
    app(args=list(args) if args is not None else None)

if __name__ == "__main__":
    main()
