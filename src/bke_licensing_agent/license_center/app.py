"""Minimal Tk presentation for LicenseCenterController."""

import tkinter as tk
from tkinter import ttk

from .controller import LicenseCenterController, Screen


def run(controller: LicenseCenterController, product=None) -> None:
    root = tk.Tk()
    root.title("BKE License Center")
    status = tk.StringVar(value="Connect to the BKE Licensing Agent")
    key = tk.StringVar()
    ttk.Label(root, text="BKE License Center", font=("TkDefaultFont", 18)).pack(padx=24, pady=16)
    ttk.Label(root, textvariable=status).pack(padx=24, pady=8)
    ttk.Label(root, text=f"Product: {getattr(product, 'productId', product or '(none)')}").pack()
    ttk.Entry(root, textvariable=key, show="*").pack(padx=24, pady=8)

    def connect() -> None:
        state = controller.connect()
        status.set(f"Screen: {state.screen.value}")

    def logout() -> None:
        state = controller.logout()
        status.set(f"Screen: {state.screen.value}")

    def activate() -> None:
        activate_button.configure(state="disabled")
        try:
            controller.connect()
            controller.enter_license_key(key.get())
            controller.select_product(product)
            state = controller.activate()
            if state.screen is Screen.STATUS:
                status.set("Activation successful")
                root.after(100, root.destroy)
            else:
                status.set(state.error or "Activation denied")
        finally:
            if root.winfo_exists():
                activate_button.configure(state="normal")

    ttk.Button(root, text="Connect", command=connect).pack(pady=4)
    activate_button = ttk.Button(root, text="Activate", command=activate)
    activate_button.pack(pady=4)
    ttk.Button(root, text="Log out", command=logout).pack(pady=4)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
