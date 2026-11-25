"""NEXUS CLI entry point."""

import click

from nexus import __version__, __codename__
from nexus.cli.commands import ALL_COMMANDS


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name=__codename__)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """NEXUS — Network EXploration & Unified Security.

    AI-optional autonomous penetration testing framework for Linux.
    """
    ctx.ensure_object(dict)
    if ctx.invoked_subcommand is None:
        from nexus.cli.tui import print_banner
        print_banner()
        click.echo(ctx.get_help())


# Register all commands
for cmd in ALL_COMMANDS:
    cli.add_command(cmd)


if __name__ == "__main__":
    cli()
