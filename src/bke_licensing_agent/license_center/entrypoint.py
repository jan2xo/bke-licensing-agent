"""Platform-neutral License Center command entry point."""

import tkinter as tk
import sys
from tkinter import ttk


_STATUS_ROWS = (
    ("Agent", "Standalone shell"),
    ("Product", "Waiting for product context"),
    ("Account", "Not signed in"),
    ("License", "No product selected"),
    ("Device", "Available after Agent connection"),
    ("Update", "Available after product authorization"),
)


def build_standalone_window(root: tk.Tk) -> None:
    """Render the safe standalone shell without inventing Agent state."""
    root.title("BKE License Center")
    root.minsize(560, 430)

    container = ttk.Frame(root, padding=24)
    container.pack(fill="both", expand=True)

    ttk.Label(
        container,
        text="BKE License Center",
        font=("TkDefaultFont", 20, "bold"),
    ).pack(anchor="w")
    ttk.Label(
        container,
        text="Licensing and application authorization",
    ).pack(anchor="w", pady=(2, 18))

    notice = ttk.LabelFrame(container, text="Status", padding=14)
    notice.pack(fill="x", pady=(0, 16))
    ttk.Label(
        notice,
        text=(
            "License Center is running. Open it from a BKE product to supply a "
            "validated manifest and enable sign-in, activation, device, and update actions."
        ),
        wraplength=480,
        justify="left",
    ).pack(anchor="w")

    details = ttk.LabelFrame(container, text="Current context", padding=14)
    details.pack(fill="x")
    details.columnconfigure(1, weight=1)

    for row, (label, value) in enumerate(_STATUS_ROWS):
        ttk.Label(details, text=label).grid(row=row, column=0, sticky="w", padx=(0, 24), pady=5)
        ttk.Label(details, text=value).grid(row=row, column=1, sticky="w", pady=5)

    actions = ttk.Frame(container)
    actions.pack(fill="x", pady=(18, 0))
    ttk.Button(actions, text="Sign In", state="disabled").pack(side="left")
    ttk.Button(actions, text="Activate License", state="disabled").pack(side="left", padx=(8, 0))
    ttk.Button(actions, text="Close", command=root.destroy).pack(side="right")

    ttk.Label(
        container,
        text="Actions unlock only after a product opens License Center through the Agent-owned typed boundary.",
        wraplength=500,
        justify="left",
    ).pack(anchor="w", pady=(14, 0))


def main() -> None:
    """Start the standalone desktop shell."""
    if "--smoke" in sys.argv[1:]:
        print("BKE License Center smoke: import and entrypoint OK")
        return
    root = tk.Tk()
    build_standalone_window(root)
    root.mainloop()


if __name__ == "__main__":
    main()
