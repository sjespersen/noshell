# Security policy

Please report vulnerabilities privately via GitHub's "Report a vulnerability"
button on the Security tab, not in public issues.

noshell's own code is small; most risk comes from the Go standard library's
HTTP stack, which is compiled into the binary. CI runs `govulncheck` on every
push. When Go publishes a security release, rebuild and redeploy the image.
