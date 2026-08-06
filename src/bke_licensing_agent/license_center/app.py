"""Minimal Tk presentation for LicenseCenterController."""

import tkinter as tk
from tkinter import ttk

from .controller import LicenseCenterController, Screen


def run(controller: LicenseCenterController, product=None, mode: str = "activation_required") -> None:
    root = tk.Tk()
    root.title("BKE License Center")
    status = tk.StringVar(value="Ready for license activation")
    key = tk.StringVar()
    title = "Activate Another License" if mode in {"activate_license", "add_license"} else "BKE License Center"
    ttk.Label(root, text=title, font=("TkDefaultFont", 18)).pack(padx=24, pady=16)
    if mode == "activate_license":
        ttk.Label(root, text="Your current license remains active until replacement succeeds.").pack()
    ttk.Label(root, textvariable=status).pack(padx=24, pady=8)
    ttk.Label(root, text=f"Product: {getattr(product, 'productId', product or '(none)')}").pack()
    if mode in {"activation_required", "add_license"}:
        ttk.Entry(root, textvariable=key).pack(padx=24, pady=8)

    def activate() -> None:
        activate_button.configure(state="disabled")
        try:
            if mode in {"activation_required", "add_license"}:
                controller.connect()
                controller.enter_license_key(key.get())
                controller.select_product(product)
                state = controller.add_license() if mode == "add_license" else controller.activate()
            elif mode == "refresh_license":
                state = controller.refresh_license()
            elif mode == "deactivate_device":
                state = controller.deactivate_device()
            else:
                state = controller.refresh_license()
            if state.screen is Screen.STATUS:
                status.set("Activation successful")
                root.after(100, root.destroy)
            else:
                status.set(state.error or "Activation denied")
        finally:
            if root.winfo_exists():
                activate_button.configure(state="normal")

    # The product has already requested the License Center; connect as part of
    # opening it so the customer only supplies the license key.
    controller.connect()
    if product is not None:
        controller.select_product(product)
    action_label = {"add_license": "Add License", "refresh_license": "Refresh",
                    "deactivate_device": "Deactivate"}.get(mode, "Activate")
    activate_button = ttk.Button(root, text=action_label, command=activate)
    activate_button.pack(pady=4)
    if mode == "deactivate_device":
        status.set("Confirm deactivation for this product and device?")
        ttk.Label(root, text="This may remove current authorization.").pack(pady=4)
    if mode in {"select_license", "view_licenses", "remove_license"}:
        listbox = tk.Listbox(root, height=6, exportselection=False)
        listbox.pack(fill="both", padx=24, pady=8)
        license_ids: list[str] = []

        def refresh_list() -> None:
            license_ids.clear()
            listbox.delete(0, tk.END)
            for item in controller.list_licenses():
                license_ids.append(item["license_id"])
                active = "Active" if item.get("active") else "Inactive"
                listbox.insert(tk.END, f"{item['license_id']} | {item.get('edition', 'Unknown')} | {item['status']} | {active}")

        refresh_list()

        def select_or_remove() -> None:
            selected = listbox.curselection()
            if not selected:
                return
            state = (controller.remove_license(license_ids[selected[0]])
                     if mode == "remove_license" else controller.select_license(license_ids[selected[0]]))
            status.set(state.error or state.screen.value)
            refresh_list()

        if mode != "view_licenses":
            ttk.Button(root, text="Remove Selected" if mode == "remove_license" else "Use Selected",
                       command=select_or_remove).pack(pady=4)
        ttk.Button(root, text="Refresh", command=refresh_list).pack(pady=4)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
