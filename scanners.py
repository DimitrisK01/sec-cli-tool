import os
import subprocess
import json
import threading
import time

import click


def run_trivy(image, scan_type):
    """Run Trivy to scan the given Docker image for vulnerabilities, dependencies, or secrets."""
    command = ['trivy', 'image']

    if scan_type == 'secrets':
        command += ['--scanners', 'secret', '--quiet']
    elif scan_type == 'vulnerabilities':
        command += ['--scanners', 'vuln']
    elif scan_type == 'dependencies':
        command += ['--list-all-pkgs']

    command.append(image)

    click.echo(f"Running Trivy with command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)

    click.echo(f"Trivy return code: {result.returncode}")
    click.echo(f"Trivy stdout: {result.stdout}")
    click.echo(f"Trivy stderr: {result.stderr}")

    if result.returncode != 0:
        click.echo(f"Error running Trivy: {result.stderr}", err=True)
        return None

    return result.stdout


def run_grype(image):
    """Run Grype to scan the given Docker image for vulnerabilities."""
    click.echo(f"Running Grype with command: grype {image} --quiet")
    result = subprocess.run(['grype', image, '--quiet'], capture_output=True, text=True)
    click.echo(f"Grype return code: {result.returncode}")
    click.echo(f"Grype stdout: {result.stdout}")
    click.echo(f"Grype stderr: {result.stderr}")
    if result.returncode != 0:
        click.echo(f"Error running Grype: {result.stderr}", err=True)
        return None
    return result.stdout


def run_gitleaks(image_dir):
    """Run Gitleaks to scan the given Docker image directory for secrets."""
    output_path = f"/tmp/gitleaks_output.json"
    command = ['gitleaks', 'detect', '--source', image_dir, '--no-git', '--report-format', 'json', '--report-path', output_path,'--verbose']
    click.echo(f"Running Gitleaks with command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)
    stdout_output = result.stdout.strip()
    stderr_output = result.stderr.strip()

    click.echo(f"Gitleaks return code: {result.returncode}")
    click.echo(f"Gitleaks stdout: {stdout_output}")
    click.echo(f"Gitleaks stderr: {stderr_output}")

    if result.returncode != 0 and result.returncode != 1:
        click.echo(f"Error running Gitleaks: {stderr_output}", err=True)
        return None

    # Read the output from the file
    try:
        with open(output_path, 'r') as file:
            findings = json.load(file)
        return findings if findings else None
    except json.JSONDecodeError as e:
        click.echo(f"Failed to parse Gitleaks output: {e}", err=True)
        return None

def run_clamav(scan_dir):
    """Run ClamAV to scan for malware."""
    command = ['clamscan', '-r', scan_dir]
    click.echo(f"Running ClamAV with command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)

    click.echo(f"ClamAV return code: {result.returncode}")
    click.echo(f"ClamAV stdout: {result.stdout}")
    click.echo(f"ClamAV stderr: {result.stderr}")

    if result.returncode not in (0, 1):  # 0: no virus found, 1: virus(es) found
        click.echo(f"Error running ClamAV: {result.stderr}", err=True)
        return None
    return result.stdout


def run_dependency_check(scan_dir):
    """Run Dependency-Check to scan for dependencies."""
    log_directory = '/usr/local/bin/dependency-check/logs'
    log_file = os.path.join(log_directory, 'dependency-check.log')
    report_directory = '/usr/local/bin/dependency-check/reports'
    report_file = os.path.join(report_directory, 'dependency-check-report.json')

    # Ensure the directories exists
    os.makedirs(log_directory, exist_ok=True)
    os.makedirs(report_directory, exist_ok=True)

    command = [
        '/usr/local/bin/dependency-check/bin/dependency-check.sh',
        '--project', 'docker-scan',
        '--scan', scan_dir,
        '--format', 'JSON',
        '--nvdApiKey', os.getenv('NVD_API_KEY'),
        '--propertyfile', '/app/dependency-check.properties',
        '--prettyPrint',
        '--out', report_directory,
        '--log', log_file
    ]

    click.echo(f"Running Dependency-Check with command: {' '.join(command)}")

    start_time = time.time()

    # Function to periodically print progress
    def print_progress():
        while process.poll() is None:
            elapsed_time = time.time() - start_time
            click.echo(f"Dependency-Check running for {elapsed_time:.2f} seconds...")
            time.sleep(60)  # Print progress every 60 seconds

    # Run the subprocess and start the progress thread
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    progress_thread = threading.Thread(target=print_progress)
    progress_thread.start()

    stdout, stderr = process.communicate()
    progress_thread.join()  # Ensure the progress thread finishes

    elapsed_time = time.time() - start_time
    click.echo(f"Dependency-Check completed in {elapsed_time:.2f} seconds")
    click.echo(f"Dependency-Check return code: {process.returncode}")
    click.echo(f"Dependency-Check stdout: {stdout}")

    # Load and print the JSON report content to stderr
    if os.path.exists(report_file):
        with open(report_file, 'r') as file:
            json_report = file.read()
            stdout += "\n" + json_report  # Append the JSON content to stderr

    click.echo(f"Dependency-Check stderr: {stderr}")

    if process.returncode != 0:
        click.echo(f"Error running Dependency-Check: {stderr}", err=True)
        return None
    return stdout


def run_maldet(scan_dir):
    """Run Maldet to scan for malware."""
    command = ['maldet', '--scan-all', scan_dir]
    click.echo(f"Running Maldet with command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)

    click.echo(f"Maldet return code: {result.returncode}")
    click.echo(f"Maldet stdout: {result.stdout}")
    click.echo(f"Maldet stderr: {result.stderr}")

    if result.returncode != 0:
        click.echo(f"Error running Maldet: {result.stderr}", err=True)
        return None
    return result.stdout


def run_dockle(image):
    """Run Dockle to lint the given Docker image."""
    command = ['dockle', image]
    click.echo(f"Running Dockle with command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)

    # Log standard output and standard error
    click.echo(f"Dockle stdout: {result.stdout}")
    click.echo(f"Dockle stderr: {result.stderr}")

    if result.returncode != 0:
        click.echo(f"Error running Dockle: {result.stderr}", err=True)
        return None
    return result.stdout


def run_trufflehog(scan_dir):
    """Run truffleHog to scan for secrets."""
    command = ['trufflehog3', 'filesystem', scan_dir]
    click.echo(f"Running truffleHog with command: {' '.join(command)}")

    result = subprocess.run(command, capture_output=True, text=True)

    click.echo(f"truffleHog return code: {result.returncode}")
    if result.stdout:
        click.echo(f"truffleHog stdout: {result.stdout[:2000]}...")  # Truncate for readability
    if result.stderr:
        click.echo(f"truffleHog stderr: {result.stderr}")

    if result.returncode != 0 and result.returncode != 2:
        click.echo(f"Error running truffleHog: {result.stderr}", err=True)
        return None

    # Parsing the output for findings
    findings = result.stdout.split("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    formatted_findings = []
    for finding in findings:
        if "High Entropy" in finding:
            formatted_findings.append(finding.strip())

    return "\n".join(formatted_findings) if formatted_findings else "No high entropy findings detected."
