# cli.py

import click
from commands import scan

@click.group()
def cli():
    """A CLI tool for scanning Docker images and containers for security issues."""
    pass

cli.add_command(scan)

if __name__ == '__main__':
    cli()
