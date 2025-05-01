# Use a specific Python version for consistency
FROM python:3.11-slim

# Set environment variables to non-interactive (avoids prompts during build)
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
# Prevent git from prompting for credentials
ENV GIT_TERMINAL_PROMPT=0

# Install necessary system dependencies: git, clang, libclang dev headers, ca-certificates
# Using specific LLVM/Clang version (e.g., 14) for stability. Adjust if needed.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    clang-14 \
    libclang-14-dev \
    ca-certificates \
    && ln -s /usr/lib/llvm-14/lib/libclang.so.1 /usr/lib/libclang.so \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set an environment variable for the libclang path inside the container
ENV LIBCLANG_PATH=/usr/lib/llvm-14/lib/libclang.so.1

# Set workdir
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies (will now install clang compatible with v14, requests, packaging)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
# Copy scanner module into the container's working directory
COPY ./scanner ./scanner
# Note: We don't copy repos or output here; they should be mounted as volumes

# Define the entrypoint for the application
# Use python -m to run scanner.main as a module, allowing relative imports
# Expects repo URLs as command-line arguments passed after the image name
ENTRYPOINT ["python", "-m", "scanner.main"]
