# noshell — static site in a container with no shell and no OS

The runtime image is `FROM scratch` with one file in it: a statically linked Go
binary that has your site embedded. No `/bin/sh`, no libc, no busybox, no package
manager, no `/etc`, no writable files.

Inspired by the Brotli decoder RCE (CVE-2026-111497, "Node2Shell"/"HTTP2Shell")
and the half-joking advice to "just remove the shell and the OS".

## Use

```
# put your pages in site/ (index.html, 404.html, css, images…)
docker build -t noshell .
docker run --rm -p 8080:8080 --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --ulimit nofile=4096 noshell
```

Change the site → rebuild the image (the content is compiled in).

Files and folders starting with `.` or `_` are never embedded or served, so a
stray `.env`, `.DS_Store` or `_drafts/` stays private.

### Configuration

| Env / flag | Default | Meaning |
|---|---|---|
| `ADDR` / `-addr` | `:8080` | Listen address. The healthcheck reads the same value. |
| `MAX_CONNS` / `-max-conns` | `1024` | Concurrent connection cap. |
| `QUIET` / `-quiet` | off | Disable the access log (one line per request on stderr). |
| `TLS_CERT` / `-tls-cert` | unset | PEM certificate chain. Setting it and `TLS_KEY` switches the listener to HTTPS. |
| `TLS_KEY` / `-tls-key` | unset | PEM private key. |

### HTTPS

Mount a certificate and key read-only and point the env vars at them:

```
docker run --rm -p 443:8080 --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --ulimit nofile=4096 \
  -v /etc/noshell/tls:/tls:ro \
  -e TLS_CERT=/tls/fullchain.pem -e TLS_KEY=/tls/privkey.pem noshell
```

- The files must be readable by UID 65532 inside the container.
- The container still listens on `:8080` (it can't bind 443 without
  capabilities); map the host port with `-p 443:8080`.
- TLS 1.2+ with Go's default cipher suites, HTTP/1.1 only (no HTTP/2).
- Renewed files (certbot, cert-manager, a Kubernetes secret) are picked up
  within a minute without a restart. A broken or half-written renewal is
  logged and the previous certificate keeps being served.
- Over HTTPS every response carries `Strict-Transport-Security: max-age=31536000`
  (no `includeSubDomains`/`preload`; add those at a proxy if you want them).
- There's no ACME client and no port-80 redirect: getting certificates needs
  outbound network, CA roots and a writable cache, which this image avoids.
  Issue them outside (certbot, cert-manager, `lego`) and mount them.
- The healthcheck probes `https://127.0.0.1` without verifying the
  certificate; it only checks liveness on loopback.

## What it does and doesn't do

- GET/HEAD only; anything else, including `OPTIONS *`, → 405
- Rejects any request body or `Content-Encoding` → 400. Go's server never decodes
  request bodies and has no Brotli; cgo is off so no libbrotli is linked. The
  check is defense in depth.
- Single byte-range requests only (multi-range would amplify traffic)
- No directory listings, no compression, no CGI, no proxying, HTTP/1.1 only
  (also over TLS)
- Timeouts, ~16 KiB header limit, connection cap, graceful shutdown on SIGTERM
- Security headers (CSP, nosniff, frame-deny, referrer, COOP, permissions)
- Runs as UID 65532; `-healthcheck` replaces curl for Docker's HEALTHCHECK and
  only passes on a `200` from `/`

### Content Security Policy

The default CSP is `default-src 'self'`, which blocks inline `<script>`, inline
`<style>` and `style=` attributes, and third-party CDNs or fonts. Move inline
code into files, or edit the policy in `secure()` in `main.go`, allowing
specific origins or hashes rather than `'unsafe-inline'`.

## Honest limits

- "No attack surface" isn't achievable: the binary still parses HTTP, and the
  container still shares the host kernel. What's gone is everything an attacker
  normally uses *after* a bug: no shell to spawn, no tools to download with,
  nothing to write to.
- TLS adds Go's `crypto/tls` handshake parser to what's exposed. If you
  already run a proxy (Caddy, Traefik, a cloud LB), terminating TLS there and
  leaving noshell on plain HTTP is just as good. Keep that proxy patched —
  Envoy/Istio were in the Brotli advisory.
- The image only stays secure if it's rebuilt when Go ships security releases.
  CI rebuilds and rescans weekly; redeploy the new image.
- `--read-only` and `--cap-drop=ALL` must be passed at run time; the image
  can't enforce them.
- For a stronger boundary than Docker, run it under gVisor (`--runtime=runsc`)
  or as a unikernel/Firecracker microVM.

## Supply chain

- Go version pinned in one place (`toolchain` in `go.mod`, mirrored in the
  Dockerfile; CI fails if they drift).
- CI actions pinned to commit SHAs; Dependabot updates actions, the base
  image and Go modules weekly.
- `govulncheck` runs on the source and on the built binary.
- Images are multi-arch (amd64/arm64), carry SBOM and provenance
  attestations, and are signed with cosign (keyless). Verify with:

  ```
  cosign verify ghcr.io/OWNER/noshell:latest \
    --certificate-identity-regexp 'https://github.com/OWNER/noshell/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

### Pinning the build image

Pin `golang:<version>-alpine` by digest so a moved tag can't change what builds
the binary. Get the digest with
`docker buildx imagetools inspect golang:1.27.3-alpine --format '{{.Manifest.Digest}}'`
and change the `FROM` line to `golang:${GO_VERSION}-alpine@sha256:…`.
Dependabot keeps it updated afterwards.

## Development

```
go test ./...
go run . -addr :8080
```

## License

MIT — see [LICENSE](LICENSE).
