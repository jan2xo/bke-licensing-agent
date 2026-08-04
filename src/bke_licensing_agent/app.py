from pathlib import Path
from typing import Any

import typer

from .discovery.scanner import scan as discovery_scan
from .storage.database import Database
from .storage.models import DiscoveredProductRecord

app = typer.Typer(help="BKE Licensing Agent CLI")


@app.command()
def scan(paths: str | None = typer.Option(None, "--paths", "-p", help="Colon-separated paths to search for BKE applications.")):
    """Scan configured folders for BKE application manifests."""
    discovered = discovery_scan(paths)
    db = Database()

    if not discovered:
        typer.echo("No valid BKE application manifests found.")
        raise typer.Exit(code=1)

    typer.secho("Discovered BKE products:", fg=typer.colors.GREEN)
    for product in discovered:
        manifest = product.manifest
        typer.echo(f"- {manifest.get('displayName')} ({manifest.get('productId')})")
        typer.echo(f"  version: {manifest.get('version')}")
        typer.echo(f"  path: {product.product_root}")
        typer.echo(f"  entryPoint: {product.entry_point_path}")

        record = DiscoveredProductRecord.create(
            product_id=manifest.get("productId"),
            display_name=manifest.get("displayName"),
            version=manifest.get("version"),
            manifest_path=product.manifest_path,
            product_root=product.product_root,
            entry_point_path=product.entry_point_path,
        )
        db.save_discovered_product(record)

    typer.secho(f"Saved {len(discovered)} products to local cache.", fg=typer.colors.BLUE)


@app.command("list")
def list_cached():
    """List previously discovered products from local cache."""
    db = Database()
    records = db.list_discovered_products()

    if not records:
        typer.echo("No cached discovered products found.")
        raise typer.Exit(code=1)

    typer.secho("Cached discovered products:", fg=typer.colors.GREEN)
    for record in records:
        typer.echo(f"- {record.display_name} ({record.product_id})")
        typer.echo(f"  version: {record.version}")
        typer.echo(f"  path: {record.product_root}")
        typer.echo(f"  entryPoint: {record.entry_point_path}")
        typer.echo(f"  discoveredAt: {record.discovered_at}")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("Use --help for available commands.")
