###############
# BUILD STAGE #
###############
FROM starknetfoundation/starknet-dev:2.9.4 AS builder

USER root

WORKDIR /build

# Copy the entire contracts directory
COPY ./contracts ./contracts

# Build the contracts
WORKDIR /build/contracts
RUN scarb build

###############
# FINAL STAGE #
###############
FROM starknetfoundation/starknet-dev:2.9.4

USER root

# Install Node.js and npm
RUN apt-get update && apt-get install -y \
    nodejs \
    npm \
    && npm install -g yarn \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy required directories
COPY docker /app/docker
COPY scripts /app/scripts

# Copy the entire contracts directory including target from the builder
COPY --from=builder /build/contracts /app/contracts

# Install Node.js dependencies
WORKDIR /app/scripts
RUN yarn install

WORKDIR /app

RUN chmod 755 /app/docker/entrypoint.sh

# Make sure line endings are correct for the entrypoint script
RUN sed -i 's/\r$//' /app/docker/entrypoint.sh

# Expose the Starknet Devnet port
EXPOSE 5050

ENTRYPOINT ["/bin/sh", "/app/docker/entrypoint.sh"]
