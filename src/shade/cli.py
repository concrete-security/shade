"""Shade CLI.

Command-line interface for the Shade CVM framework.
"""

import sys

import click

from shade import api


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
