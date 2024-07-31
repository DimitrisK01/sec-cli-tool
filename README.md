# sec-cli-tool

Set Up Your Environmen

Install Docker: Ensure you have Docker installed on your machine.
Clone the Repository: Clone the repository containing the project files.
git clone <repository_url>
cd <repository_directory>

Docker Build Command: Build the Docker image using the Dockerfile provided.
docker build -t cli-container-security .

Run the Docker Container: Run the Docker container with the necessary volume mount to access the Docker socket and local dir to dir of output.
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/app/output cli-container-security -i mysecretimage -t vulnerabilities,malware,dependencies,secrets -o  (or -o -f output2.txt for specific file name)
