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
  --security-opt=no-new-privileges noshell
```

Change the site → rebuild the image (the content is compiled in).

## What it does and doesn't do

- GET/HEAD only; anything else → 405
- Rejects any request body or `Content-Encoding` → 400 (no decoder is ever reachable;
  Go's standard library has no Brotli at all, and cgo is off so no libbrotli is linked)
- No directory listings, no compression, no CGI, no proxying
- Timeouts and a 16 KiB header limit
- Security headers (CSP, nosniff, frame-deny, etc.)
- Runs as UID 65532; `-healthcheck` flag replaces curl for Docker's HEALTHCHECK

## Honest limits

- "No attack surface" isn't achievable: the binary still parses HTTP, and the
  container still shares the host kernel. What's gone is everything an attacker
  normally uses *after* a bug: no shell to spawn, no tools to download with,
  nothing to write to.
- Put TLS in front (Caddy, Traefik, a cloud LB) or add `ListenAndServeTLS`.
  Keep that proxy patched — Envoy/Istio were in the Brotli advisory.
- Rebuild when Go ships security releases, since the HTTP stack is compiled in.
- For a stronger boundary than Docker, run it under gVisor (`--runtime=runsc`)
  or as a unikernel/Firecracker microVM.

## Development

```
go test ./...
go run . -addr :8080
```

CI runs vet, tests and `govulncheck`, then builds multi-arch images
(amd64/arm64) and pushes them to GitHub Container Registry on `main` and `v*` tags.

## License

MIT — see [LICENSE](LICENSE).
