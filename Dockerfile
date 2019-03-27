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

# Install the verifier from source
RUN cd verifier-source;npm install -g
EXPOSE 9000