"""Shade CLI.

Command-line interface for the Shade CVM framework.
"""

import json
import sys
from pathlib import Path

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


# ---------------------------------------------------------------------------
# shade policy <subcommand>
# ---------------------------------------------------------------------------


@cli.group()
def policy():
    """Atlas policy commands."""
    pass


def _write_policy_output(policy_dict: dict, output: str) -> None:
    """Render policy JSON and write to stdout or file."""
    rendered = json.dumps(policy_dict, indent=2) + "\n"
    if output == "-":
        click.echo(rendered, nl=False)
    else:
        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered, encoding="utf-8")
        click.echo(f"Wrote {out_path}")


@policy.command()
@click.option(
    "--domain",
    default=None,
    help="CVM domain to fetch measurements from (e.g., vllm.concrete-security.com).",
)
@click.option(
    "--compose",
    "-f",
    default=None,
    type=click.Path(exists=True),
    help="Docker-compose file to verify against the CVM (recommended for production).",
)
@click.option(
    "--allowed-tcb-status",
    default=None,
    help="Comma-separated TCB status values (default: UpToDate).",
)
@click.option(
    "--disable-runtime-verification",
    is_flag=True,
    default=False,
    help="Skip runtime verification (dev mode only).",
)
@click.option(
    "--output",
    "-o",
    default="-",
    show_default=True,
    help="Output file path, or '-' for stdout.",
)
def generate(
    domain: str | None,
    compose: str | None,
    allowed_tcb_status: str | None,
    disable_runtime_verification: bool,
    output: str,
):
    """Generate an Atlas-compatible policy.

    \b
    Production:  shade policy generate --domain vllm.example.com --compose docker-compose.shade.yml
    Dev mode:    shade policy generate --disable-runtime-verification
    """
    try:
        tcb_list = None
        if allowed_tcb_status is not None:
            tcb_list = [s.strip() for s in allowed_tcb_status.split(",") if s.strip()]

        compose_content = None
        if compose is not None:
            compose_content = Path(compose).read_text(encoding="utf-8")

        policy_dict = api.generate_atlas_policy(
            domain=domain,
            docker_compose_file=compose_content,
            allowed_tcb_status=tcb_list,
            disable_runtime_verification=disable_runtime_verification,
        )
    except (ValueError, RuntimeError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    _write_policy_output(policy_dict, output)
