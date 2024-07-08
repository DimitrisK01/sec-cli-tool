#commands

import logging
import click

from handlers import handle_scan
from logger_setup import setup_logging

# Call setup_logging at the beginning of your script to ensure all output is captured
setup_logging()


@click.command()
@click.option('--image', '-i', help='Docker image to scan')
@click.option('--scan-type', '-t', multiple=True,
              type=click.Choice(['vulnerabilities', 'malware', 'dependencies', 'secrets'], case_sensitive=False),
              help='Types of scans (e.g., vulnerabilities, malware, dependencies, secrets)')
@click.option('--output', '-o', default='report.txt', help='Output report file name')
def scan(image, scan_type, output):
    """Scan Docker images and containers for security issues."""
    logging.info(f"Starting scan for image: {image} with scan types: {scan_type}")
    handle_scan(image, scan_type, output)
