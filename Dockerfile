#####################
# CAIRO BUILD STAGE #
#####################
FROM starknetfoundation/starknet-dev:2.9.4 AS cairo-builder

USER root
WORKDIR /build

# Build Cairo contracts
COPY ./contracts ./contracts
WORKDIR /build/contracts
RUN scarb build

###################
# NODE BUILD STAGE #
###################
FROM node:18-alpine AS js-builder

WORKDIR /build

# Copy scripts and package.json
COPY ./scripts /build/scripts
WORKDIR /build/scripts

# Install only production dependencies with yarn
RUN yarn install --production --frozen-lockfile

###############
# FINAL STAGE #
###############
FROM starknetfoundation/starknet-dev:2.9.4

USER root
WORKDIR /app

# Install Node.js (minimal runtime)
RUN apt-get update && apt-get install -y \
    nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy Docker files
COPY docker /app/docker

# Copy Cairo build artifacts
COPY --from=cairo-builder /build/contracts /app/contracts

# Copy JS files and production dependencies from js-builder
COPY --from=js-builder /build/scripts /app/scripts

# Make scripts executable
RUN chmod 755 /app/docker/entrypoint.sh

# Make sure line endings are correct
RUN sed -i 's/\r$//' /app/docker/entrypoint.sh

# Expose the Starknet Devnet port
EXPOSE 5050

ENTRYPOINT ["/bin/sh", "/app/docker/entrypoint.sh"]
