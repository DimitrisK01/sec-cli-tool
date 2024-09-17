FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    lsb-release \
    software-properties-common \
    ca-certificates \
    docker.io \
    clamav \
    wget \
    tar \
    unzip \
    default-jdk

RUN apt-get update && apt-get install -y git

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y trivy

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Node.js and npm
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && \
    apt-get install -y nodejs

# Install Dockle
RUN wget https://github.com/goodwithtech/dockle/releases/download/v0.4.6/dockle_0.4.6_Linux-64bit.deb && \
    dpkg -i dockle_0.4.6_Linux-64bit.deb && \
    rm dockle_0.4.6_Linux-64bit.deb

# Install Gitleaks
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    chmod +x /usr/local/bin/gitleaks

# Install OWASP Dependency-Check with permission verification
RUN VERSION=$(curl -s https://jeremylong.github.io/DependencyCheck/current.txt) && \
    curl -Ls "https://github.com/jeremylong/DependencyCheck/releases/download/v$VERSION/dependency-check-$VERSION-release.zip" --output dependency-check.zip && \
    unzip dependency-check.zip -d /usr/local/bin/ && \
    rm dependency-check.zip && \
    chmod -R +x /usr/local/bin/dependency-check/bin && \
    ls -la /usr/local/bin/dependency-check/bin # This will list permissions in the build output

# Install Maldet
RUN wget http://www.rfxn.com/downloads/maldetect-current.tar.gz && \
    tar -xzf maldetect-current.tar.gz && \
    cd maldetect-* && \
    ./install.sh

COPY . /app

# Set NVD API key environment variable 
ENV NVD_API_KEY=

# Copy the dependency-check.properties file
COPY dependency-check.properties /app/

# Install Python dependencies
RUN pip install --no-cache-dir click trufflehog3

# Run cli.py when the container launches
ENTRYPOINT ["python", "cli.py", "scan"]
