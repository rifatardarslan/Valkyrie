FROM ubuntu:22.04

# Avoid interactive prompts during apt operations
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    strace \
    tcpdump \
    sudo \
    file \
    python3 \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for safe execution
RUN useradd -m valkyrie
WORKDIR /home/valkyrie

# Create shared mount point directory and give access
RUN mkdir /sandbox && chown valkyrie:valkyrie /sandbox

CMD ["/bin/bash", "-c", "sleep infinity"]
