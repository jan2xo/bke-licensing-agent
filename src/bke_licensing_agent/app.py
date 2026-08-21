from pathlib import Path
import typer

from .config import get_agent_port
from .discovery.scanner import scan as discovery_scan
from .runtime import InstalledAgentRuntime
from .storage.database import Database
from .storage.models import DiscoveredProductRecord
from .manifest.validator import validate_manifest

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

        validated = validate_manifest(manifest)
        record = DiscoveredProductRecord.create(
            product_id=validated.productId,
            display_name=validated.displayName,
            version=validated.version,
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


@app.command()
def serve(port: int | None = typer.Option(None, "--port", help="Override the canonical loopback authorization port.")):
    """Run the installed loopback-only authorization service until stopped."""
    runtime = InstalledAgentRuntime(port=port if port is not None else get_agent_port())
    typer.echo(f"BKE Licensing Agent listening on http://127.0.0.1:{runtime.port}")
    try:
        runtime.serve_forever()
    finally:
        runtime.close()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo("Use --help for available commands.")
