FROM ubuntu:18.04 as build

# Get required dependencies
RUN apt-get update && apt-get install -y --no-install-recommends curl \
# Required for https
    ca-certificates \
# Required for signing-key
    gnupg \
# To extract git snapshot
    unzip \
# For building native modules
    build-essential \
# Python headers required for node-gyp
    python-dev \
# libgmp-dev required for secp256k1
    libgmp-dev \
# Git, for certain modules
    git

# Install node
RUN curl -sL https://deb.nodesource.com/setup_11.x | bash
RUN apt-get update && apt-get install -y --no-install-recommends nodejs

# Mount the current directory as /verifier
ADD . /verifier-source

# Create a user to run under
RUN useradd -m verifier -s /bin/bash -g root -G sudo; chown -R verifier /verifier-source; chown -R verifier /usr/lib/node_modules; chown -R verifier /usr/bin
USER verifier

# Install the verifier from source
RUN cd verifier-source;npm install -g;npm i -g ts-node typescript
WORKDIR /verifier-source

EXPOSE 9000