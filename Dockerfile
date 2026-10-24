# ---- build stage (has a shell; never shipped) ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY site ./site
# Pure Go, statically linked, no cgo -> no libc, no libbrotli, nothing dynamic.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" -o /noshell .

# ---- runtime stage: literally empty except the binary ----
FROM scratch
COPY --from=build /noshell /noshell
# Unprivileged numeric user (no /etc/passwd needed).
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD ["/noshell", "-healthcheck"]
ENTRYPOINT ["/noshell"]
