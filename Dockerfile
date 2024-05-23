FROM alpine:3.19

# Populated during the build process, for example, with 'darwin_arm64' or 'linux_amd64'.
ARG TARGETOS
ARG TARGETARCH

ENV TARGET_DIR=${TARGETOS}_${TARGETARCH}

# Copy binary
RUN mkdir -p /usr/local/bin
COPY ./dist/$TARGET_DIR/release/glide /usr/local/bin/glide
COPY ./dist/$TARGET_DIR/release/glided /usr/local/bin/glided

ENTRYPOINT ["/usr/local/bin/glided", "startup", "config.yaml"]
