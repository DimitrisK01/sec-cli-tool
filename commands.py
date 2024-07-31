#commands

import logging
import click
import os
import getpass
import datetime

from handlers import handle_scan
from logger_setup import setup_logging

# Call setup_logging at the beginning of your script to ensure all output is captured
setup_logging()

@click.command()
@click.option('--image', '-i', help='Docker image to scan')
@click.option('--scan-type', '-t', default='', help='Comma-separated list of scan types (e.g., vulnerabilities,malware,dependencies,secrets)')
@click.option('--all', 'all_scans', is_flag=True, help='Run all scan types')
@click.option('--output', '-o', is_flag=True, help='Generate output report file')
@click.option('--output-filename', '-f', default=None, help='Output report file name (optional)')
@click.option('--username', default=None, help='DockerHub username (for private repositories)')
@click.option('--password', default=None, help='DockerHub password (for private repositories)')
@click.option('--registry', default=None, help='Docker registry (default is DockerHub)')
def scan(image, scan_type, all_scans, output, output_filename, username, password, registry):
    """Scan Docker images and containers for security issues."""
    logging.info(f"Starting scan for image: {image} with scan types: {scan_type}")
    
    # Generate scan types
    scan_types = []
    if all_scans:
        scan_types = ['vulnerabilities', 'malware', 'dependencies', 'secrets']
    else:
        scan_types = scan_type.split(',')

    # Generate output file name if not provided
    if output:
        if output_filename is None:
            now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            image_tag = image.replace(':', '_').replace('/','_')
            output_file = f"/app/output/{image_tag}_{now}_{'_'.join(scan_types)}.txt"
        else:
            output_file = f"/app/output/{output_filename}"
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
    else:
        output_file = None

    handle_scan(image, scan_types, output_file, username, password, registry)
