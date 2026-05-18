FROM python:3.10-slim

LABEL description="Kernel CVE Livepatch Auto-Generation Agent - Development Environment"
LABEL version="0.1.0"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies (kpatch-build prerequisites)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    git \
    patch \
    diffutils \
    binutils \
    libelf-dev \
    libssl-dev \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install pytest for testing
RUN pip install --no-cache-dir pytest

# Create test workspace
RUN mkdir -p /tmp/test_workspace

# Default command: run tests
CMD ["python", "-m", "pytest", "tests/", "-v"]
