FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    nasm \
    binutils \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wemu

# Copy the entire repository into the container
COPY . .

# Create virtual environment and install requirements
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --no-cache-dir -r requirements.txt

# Make the virtual environment active by default
RUN echo "source /wemu/venv/bin/activate" >> ~/.bashrc
RUN echo "cd /wemu/src" >> ~/.bashrc
RUN echo "echo 'WeMu ready! Try: python unit_tests.py all'" >> ~/.bashrc

WORKDIR /wemu/src
CMD ["/bin/bash"]