###############
# BUILD STAGE #
###############
FROM starknetfoundation/starknet-dev:2.9.4 AS builder

USER root

WORKDIR /build

COPY ./.tool-versions ./.tool-versions
COPY ./src ./src
COPY ./Scarb.toml ./Scarb.toml
COPY ./Scarb.lock ./Scarb.lock

RUN scarb build

###############
# FINAL STAGE #
###############
FROM starknetfoundation/starknet-dev:2.9.4

USER root

WORKDIR /app

COPY docker /app/docker

COPY bash_scripts /app/bash_scripts
COPY Scarb.toml /app/Scarb.toml

COPY --from=builder /build/target /app/target

RUN chmod 755 /app/docker/entrypoint.sh
RUN chmod +x /app/bash_scripts/dep*.sh

# Make sure line endings are correct for the entrypoint script
RUN sed -i 's/\r$//' /app/docker/entrypoint.sh

# Expose the Starknet Devnet port
EXPOSE 5050

ENTRYPOINT ["/bin/sh", "/app/docker/entrypoint.sh"]
