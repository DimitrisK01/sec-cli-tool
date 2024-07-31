#handlers

import os
import click
import re
import subprocess

from formatter import append_to_report, format_gitleaks_findings
from scanners import (
    run_trivy, run_grype, run_gitleaks,
    run_clamav, run_maldet, run_dependency_check, run_dockle, run_trufflehog
)
from utils import save_docker_image, extract_tar_file, clean_up

# Compile a regex pattern for matching ANSI escape sequences
ansi_escape_pattern = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

def remove_ansi_codes(text):
    return ansi_escape_pattern.sub('', text)

def login_to_registry(username, password, registry):
    """Log in to the Docker registry if username and password are provided."""
    if username and password:
        login_command = ['docker', 'login']
        if registry:
            login_command.append(registry)
        login_command += ['--username', username, '--password-stdin']
        process = subprocess.Popen(login_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(input=password)
        if process.returncode != 0:
            click.echo(f"Error logging into {registry if registry else 'DockerHub'}: {stderr}")
            return False
        click.echo(f"Successfully logged into {registry if registry else 'DockerHub'}")
    return True

def handle_scan(image, scan_type, output, username, password, registry):
    if username and password:
        if not login_to_registry(username, password, registry):
            return
    
    # Pull the Docker image if it does not exist locally
    click.echo(f"Pulling image {image} if it does not exist locally...")
    pull_command = ['docker', 'pull', image]
    pull_process = subprocess.run(pull_command, capture_output=True, text=True)
    if pull_process.returncode != 0:
        click.echo(f"Error pulling image {image}: {pull_process.stderr}")
        return
    else:
        click.echo("No credentials provided. Skipping image pull and continuing with local resources.")


    report_contents = ""

    if image:
        tar_file = f"/tmp/{image.replace(':', '_')}.tar"
        extract_dir = f"/tmp/{image.replace(':', '_')}"

        # Save and extract the Docker image to get the file system path for certain scans
        save_docker_image(image, tar_file)
        extract_tar_file(tar_file, extract_dir)

        if not os.path.exists(extract_dir):
            click.echo(f"Extraction directory {extract_dir} does not exist.")
            return
        else:
            click.echo(f"Extraction directory {extract_dir} exists.")
            click.echo("Contents of extraction directory:")
            click.echo(os.listdir(extract_dir))

        if 'vulnerabilities' in scan_type:
            trivy_output = run_trivy(image, 'vulnerabilities')
            grype_output = run_grype(image)
            if trivy_output:
                click.echo(f"Trivy Vulnerability Scan Output:\n{trivy_output}")
                report_contents = append_to_report(report_contents, trivy_output, 'Trivy Vulnerability')
            if grype_output:
                click.echo(f"Grype Vulnerability Scan Output:\n{grype_output}")
                report_contents = append_to_report(report_contents, grype_output, 'Grype Vulnerability')

        if 'dependencies' in scan_type:
            dependency_check_output = run_dependency_check(extract_dir)
            dockle_output = run_dockle(image)
            if dependency_check_output:
                click.echo(f"Dependency-Check Output:\n{dependency_check_output}")
                report_contents = append_to_report(report_contents, dependency_check_output, 'Dependency-Check')
            if dockle_output:
                click.echo(f"Dockle Dependency Scan Output:\n{dockle_output}")
                report_contents = append_to_report(report_contents, dockle_output, 'Dockle Dependency')

        if 'secrets' in scan_type:
            click.echo('Running Gitleaks and truffleHog for secrets...')
            gitleaks_output = run_gitleaks(extract_dir)
            trufflehog_output = run_trufflehog(extract_dir)
            if gitleaks_output:
                formatted_gitleaks_output = format_gitleaks_findings(gitleaks_output)
                click.echo(f"Gitleaks Secrets Scan Output:\n{formatted_gitleaks_output}")
                report_contents = append_to_report(report_contents, formatted_gitleaks_output, 'Gitleaks Secrets')
            if trufflehog_output:
                click.echo(f"truffleHog Secrets Scan Output:\n{trufflehog_output}")
                report_contents = append_to_report(report_contents, trufflehog_output, 'truffleHog Secrets')

        if 'malware' in scan_type:
            clamav_output = run_clamav(extract_dir)
            maldet_output = run_maldet(extract_dir)
            if clamav_output:
                click.echo(f"ClamAV Malware Scan Output:\n{clamav_output}")
                report_contents = append_to_report(report_contents, clamav_output, 'ClamAV Malware')
            if maldet_output:
                click.echo(f"Maldet Malware Scan Output:\n{maldet_output}")
                report_contents = append_to_report(report_contents, maldet_output, 'Maldet Malware')

        clean_up(tar_file, extract_dir)

    # Apply ANSI code removal just before writing to file
    if output:
        final_report = remove_ansi_codes(report_contents)

        with open(output, 'w') as report_file:
            report_file.write(final_report)

        click.echo(f"Scan results written to {output}")
    click.echo(report_contents)