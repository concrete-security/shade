"""Shade CLI.

Command-line interface for the Shade CVM framework.
"""

import json
import sys
from pathlib import Path

import click

from shade import api
from shade.policy import DEFAULT_POLICY_BASE_URL, DEFAULT_POLICY_PATH_TEMPLATE


@click.group()
@click.version_option()
def cli():
    """Shade CVM Framework - TEE infrastructure for containerized apps."""
    pass


@cli.command()
@click.option("--config", "-c", default="shade.yml", help="Path to shade.yml config file.")
@click.option(
    "--compose", "-f", default="docker-compose.yml", help="Path to user docker-compose.yml."
)
@click.option(
    "--output",
    "-o",
    default="docker-compose.shade.yml",
    help="Output path for generated compose file.",
)
def build(config: str, compose: str, output: str):
    """Build the Shade docker-compose from config + user compose."""
    try:
        result = api.build(config_path=config, compose_path=compose, output_path=output)
        click.echo(f"Generated {result.output_path}")
        click.echo(f"  Services: {result.services_count}")
        click.echo(f"  Networks: {result.networks_count}")
        click.echo(f"  Routes:   {result.routes_count}")
    except (ValueError, FileNotFoundError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--config", "-c", default="shade.yml", help="Path to shade.yml config file.")
@click.option(
    "--compose", "-f", default="docker-compose.yml", help="Path to user docker-compose.yml."
)
def validate(config: str, compose: str):
    """Validate the Shade configuration."""
    errors = api.validate(config_path=config, compose_path=compose)
    if errors:
        click.echo("Validation errors:", err=True)
        for error in errors:
            click.echo(f"  - {error}", err=True)
        sys.exit(1)
    else:
        click.echo("Configuration is valid.")


@cli.command()
@click.option("--output-dir", "-d", default=".", help="Directory to create shade.yml in.")
def init(output_dir: str):
    """Initialize a new Shade project with a starter shade.yml."""
    try:
        path = api.init(output_dir=output_dir)
        click.echo(f"Created {path}")
        click.echo("Edit shade.yml to configure your CVM deployment.")
    except FileExistsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--repo",
    required=True,
    help="Repository in owner/repo format (for example: concrete-security/secure-chat).",
)
@click.option("--cvm", required=True, help="CVM target name (for example: dev).")
@click.option("--ref", default="main", show_default=True, help="Git ref (branch/tag/SHA).")
@click.option(
    "--path-template",
    default=DEFAULT_POLICY_PATH_TEMPLATE,
    show_default=True,
    help="Policy path template; must contain '{cvm}'.",
)
@click.option(
    "--base-url",
    default=DEFAULT_POLICY_BASE_URL,
    show_default=True,
    help="Raw-content base URL.",
)
@click.option(
    "--timeout",
    default=20.0,
    show_default=True,
    type=float,
    help="HTTP timeout in seconds.",
)
@click.option(
    "--output",
    "-o",
    default="-",
    show_default=True,
    help="Output file path, or '-' for stdout.",
)
@click.option(
    "--no-validate-shape",
    is_flag=True,
    default=False,
    help="Skip Atlas policy shape validation.",
)
def policy(
    repo: str,
    cvm: str,
    ref: str,
    path_template: str,
    base_url: str,
    timeout: float,
    output: str,
    no_validate_shape: bool,
):
    """Fetch Atlas policy for a specific repo/CVM target."""
    try:
        result = api.get_atlas_policy(
            repo=repo,
            cvm=cvm,
            ref=ref,
            path_template=path_template,
            base_url=base_url,
            timeout=timeout,
            validate_shape=not no_validate_shape,
        )
    except (ValueError, RuntimeError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    rendered = json.dumps(result.policy, indent=2) + "\n"
    if output == "-":
        click.echo(rendered, nl=False)
    else:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        click.echo(f"Wrote {out_path}")

    click.echo(f"Source URL: {result.url}", err=True)
