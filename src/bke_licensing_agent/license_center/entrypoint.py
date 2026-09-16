"""Platform-neutral License Center command entry point."""

import argparse
import json
import tkinter as tk
from tkinter import ttk
from urllib.request import Request, urlopen

from ..config import get_agent_port
from ..notifications import AgentNotificationService, NotificationCode


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


def _agent_update_window(current_version: str, latest_version: str, release_notes: str | None) -> int:
    """Ask the active user whether the free Licensing Agent should update now."""
    root = tk.Tk()
    presentation = AgentNotificationService.presentation(NotificationCode.AGENT_UPDATE_AVAILABLE)
    root.title(presentation.title)
    root.minsize(520, 300)
    outcome = {"code": 2}

    frame = ttk.Frame(root, padding=24)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text=presentation.title, font=("TkDefaultFont", 20, "bold")).pack(anchor="w")
    ttk.Label(
        frame,
        text=(
            f"{presentation.body}\n\n"
            f"Current version: {current_version}\n"
            f"Available version: {latest_version}"
        ),
        wraplength=460,
        justify="left",
    ).pack(anchor="w", pady=(10, 16))

    if release_notes:
        notes = ttk.LabelFrame(frame, text="What's new", padding=12)
        notes.pack(fill="x", pady=(0, 16))
        ttk.Label(notes, text=release_notes, wraplength=440, justify="left").pack(anchor="w")

    actions = ttk.Frame(frame)
    actions.pack(fill="x", pady=(8, 0))

    def update_now() -> None:
        outcome["code"] = 0
        root.destroy()

    def later() -> None:
        outcome["code"] = 2
        root.destroy()

    ttk.Button(actions, text="Update Now", command=update_now).pack(side="left")
    ttk.Button(actions, text="Later", command=later).pack(side="left", padx=(8, 0))
    root.protocol("WM_DELETE_WINDOW", later)
    root.mainloop()
    return outcome["code"]


def _activation_window(
    product_id: str, version: str, installation_id: str,
    notification_code: NotificationCode | None = None,
) -> int:
    """Run the Agent-owned activation UI; return 0 on success or 2 on cancel."""
    root = tk.Tk()
    root.title("BKE License Center")
    root.minsize(520, 300)
    outcome = {"code": 2}
    if notification_code is None:
        initial_status = "Enter the license key for this product."
    else:
        presentation = AgentNotificationService.presentation(notification_code)
        initial_status = f"{presentation.body} Enter a license key to activate."
    status = tk.StringVar(value=initial_status)
    key = tk.StringVar()

    frame = ttk.Frame(root, padding=24)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="BKE License Center", font=("TkDefaultFont", 20, "bold")).pack(anchor="w")
    ttk.Label(frame, text=f"Activate {product_id} version {version}").pack(anchor="w", pady=(4, 18))
    if notification_code is not None:
        presentation = AgentNotificationService.presentation(notification_code)
        notice = ttk.LabelFrame(frame, text=presentation.title, padding=12)
        notice.pack(fill="x", pady=(0, 14))
        ttk.Label(notice, text=presentation.body, wraplength=450, justify="left").pack(anchor="w")
    ttk.Entry(frame, textvariable=key, show="*").pack(fill="x")
    ttk.Label(frame, textvariable=status, wraplength=460).pack(anchor="w", pady=12)

    def activate() -> None:
        license_key = key.get().strip()
        if not license_key:
            status.set("Enter a license key.")
            return
        button.configure(state="disabled")
        status.set("Activating…")
        try:
            payload = json.dumps({
                "product_id": product_id, "version": version,
                "installation_id": installation_id, "license_key": license_key,
            }).encode()
            request = Request(
                f"http://127.0.0.1:{get_agent_port()}/v1/activate", data=payload,
                headers={"content-type": "application/json", "accept": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=30) as response:  # noqa: S310 - fixed loopback Agent endpoint.
                result = json.loads(response.read())
            if result.get("authorized") is True:
                key.set("")
                outcome["code"] = 0
                status.set("Activation successful. Returning to the product…")
                root.after(150, root.destroy)
                return
            status.set("Activation failed: " + str(result.get("reason", "denied")))
        except Exception:
            status.set("Activation failed: Licensing Agent unavailable")
        finally:
            if root.winfo_exists():
                button.configure(state="normal")

    button = ttk.Button(frame, text="Activate License", command=activate)
    button.pack(anchor="w")
    ttk.Button(frame, text="Cancel", command=root.destroy).pack(anchor="e")
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
    return outcome["code"]


def main() -> int:
    """Start the standalone desktop shell or run a non-interactive package smoke check."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--agent-update-prompt", action="store_true")
    parser.add_argument("--current-version")
    parser.add_argument("--latest-version")
    parser.add_argument("--release-notes")
    parser.add_argument("--product-id")
    parser.add_argument("--product-version")
    parser.add_argument("--installation-id")
    parser.add_argument("--correlation-id")
    parser.add_argument("--action")
    parser.add_argument("--notification-code")
    args, _unknown = parser.parse_known_args()

    if args.smoke:
        print("BKE License Center smoke: import and entrypoint OK")
        return 0

    if args.agent_update_prompt:
        if not args.current_version or not args.latest_version:
            return 3
        return _agent_update_window(args.current_version, args.latest_version, args.release_notes)

    context = (args.product_id, args.product_version, args.installation_id, args.correlation_id)
    if any(context):
        if not all(context) or args.action != "activation_required":
            return 3
        try:
            notification_code = NotificationCode(args.notification_code) if args.notification_code else None
        except ValueError:
            return 3
        return _activation_window(
            args.product_id, args.product_version, args.installation_id, notification_code
        )
    root = tk.Tk()
    build_standalone_window(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
