#utils

import subprocess
import os
import shutil

def save_docker_image(image, tar_file):
    """Save a Docker image to a tar file."""
    tar_dir = os.path.dirname(tar_file)
    if not os.path.exists(tar_dir):
        os.makedirs(tar_dir)

    subprocess.run(['docker', 'save', '-o', tar_file, image], check=True)

def extract_tar_file(tar_file, extract_dir):
    """Extract a tar file to a directory."""
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)

    subprocess.run(['tar', '-xf', tar_file, '-C', extract_dir], check=True)

def clean_up(tar_file, extract_dir):
    """Clean up the tar file and extracted directory."""
    if tar_file and os.path.exists(tar_file):
        os.remove(tar_file)

    if extract_dir and os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)

