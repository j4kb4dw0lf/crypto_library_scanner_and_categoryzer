FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV GIT_TERMINAL_PROMPT=0

# Install system dependencies for building C/C++ codebases and CodeQL support
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    g++ \
    gcc \
    cmake \
    ninja-build \
    bear \
    make \
    git \
    curl \
    unzip \
    jq \
    pkg-config \
    autoconf \
    automake \
    libtool \
    libssl-dev \
    zlib1g-dev \
    libffi-dev \
    ca-certificates \
    file \
    gnupg \
    lsb-release \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Download and install the latest CodeQL CLI (.zip version)
RUN CODEQL_VERSION=$(curl -s https://api.github.com/repos/github/codeql-cli-binaries/releases/latest | jq -r '.tag_name') && \
    echo "Downloading CodeQL version: $CODEQL_VERSION" && \
    curl -fL "https://github.com/github/codeql-cli-binaries/releases/download/${CODEQL_VERSION}/codeql-linux64.zip" -o codeql.zip && \
    mkdir -p /opt/codeql && \
    unzip codeql.zip -d /opt/codeql && \
    rm codeql.zip

# Add CodeQL to PATH
ENV PATH="/opt/codeql/codeql:${PATH}"

# Set working directory
WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY ./scanner ./scanner
COPY ./scripts ./scripts

# Verify CodeQL installation
RUN codeql --version

# Go into your query pack directory and install dependencies
WORKDIR /app/scanner/query
RUN codeql pack install

WORKDIR /app
ENTRYPOINT ["python", "-m", "scanner.main"]


