"""Platform-neutral License Center command entry point."""

import tkinter as tk


def main() -> None:
    """Start the shared desktop shell; products supply typed context."""
    root = tk.Tk()
    root.title("BKE License Center")
    root.mainloop()


if __name__ == "__main__":
    main()
