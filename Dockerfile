# Carries the release binaries (built and checksummed by the release workflow) and nothing else, so
# SHA256SUMS stays valid for what is inside. Meant to be mounted as a Kubernetes image volume
# (or copied out by an init container) next to SPIRE's own distroless images.
FROM scratch
ARG TARGETARCH
COPY dist/spire-plugin-oci-server-linux-${TARGETARCH} /spire-plugin-oci-server
COPY dist/spire-plugin-oci-agent-linux-${TARGETARCH} /spire-plugin-oci-agent
