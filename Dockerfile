# Must match the toolchain line in go.mod (CI checks this).
ARG GO_VERSION=1.27.3

# ---- build stage (has a shell; never shipped) ----
# Pin by digest too, e.g. golang:1.27.3-alpine@sha256:<digest>; Dependabot
# keeps a pinned digest up to date. See README "Pinning the build image".
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=readonly GOTOOLCHAIN=local
COPY go.mod ./
COPY main.go ./
COPY site ./site
# Pure Go, statically linked, no cgo -> no libc, no libbrotli, nothing dynamic.
# -trimpath and an empty buildid make the binary reproducible for a given toolchain.
RUN go build -trimpath -ldflags="-s -w -buildid=" -o /noshell .

# ---- runtime stage: literally empty except the binary ----
FROM scratch
COPY --from=build /noshell /noshell
# Unprivileged numeric user (no /etc/passwd needed).
USER 65532:65532
ENV ADDR=:8080
EXPOSE 8080
# The healthcheck reads the same ADDR variable as the server, so
# `docker run -e ADDR=:9090 ...` keeps both in sync.
HEALTHCHECK --interval=30s --timeout=5s CMD ["/noshell", "-healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/noshell"]
