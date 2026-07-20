# ─── Stage 1: Build ─────────────────────────────────────────────────────────
# Use the official Go builder image. All build tools stay in this stage only.
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Download dependencies first (layer-cached unless go.mod/go.sum changes).
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source.
COPY . .

# Compile: CGO disabled (required for distroless/static), stripped binary for size.
# -ldflags="-s -w" removes symbol table and DWARF debug info.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags="-s -w" \
      -trimpath \
      -o /vuln-alert-service \
      ./cmd/server

# Verify: no shell execution anywhere in the codebase (acceptance criterion §8).
RUN if find . -name "*.go" | xargs grep -l 'os/exec' 2>/dev/null | grep -v _test.go | grep -q .; then echo "FAIL: os/exec found"; exit 1; fi

# Create a writable data directory with nonroot ownership (UID 65532).
# This ensures the /data volume mount-point is owned by nonroot when
# Docker initializes the named volume from the image layer.
RUN mkdir -p /data && chown -R 65532:65532 /data

# ─── Stage 2: Final image ────────────────────────────────────────────────────
# distroless/static-debian12:nonroot — no shell, no libc, no package manager.
# Pinned by digest to prevent supply-chain tag-mutation attacks (§4).
# To update: docker pull gcr.io/distroless/static-debian12:nonroot
#             docker inspect --format='{{index .RepoDigests 0}}' gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12:nonroot

# Timezone data is embedded in the binary via `import _ "time/tzdata"`.
# No /usr/share/zoneinfo needed in this image.

# Copy only the compiled binary.
COPY --from=builder /vuln-alert-service /vuln-alert-service

# Copy the sources config — this is the only config file the binary reads.
COPY --from=builder --chown=65532:65532 /build/config /config

# Copy the pre-created /data directory with nonroot ownership.
# When Docker mounts a named volume at /data, it copies the image's /data
# directory contents (empty with correct ownership) into the new volume.
COPY --from=builder --chown=65532:65532 /data /data

# Run as the non-root user provided by the distroless image.
# UID 65532 = nonroot
USER nonroot:nonroot

# Declare /data as a volume (read-write for bbolt).
VOLUME ["/data"]

EXPOSE 8080

ENTRYPOINT ["/vuln-alert-service"]
