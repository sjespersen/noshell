# Security policy

Please report vulnerabilities privately via GitHub's "Report a vulnerability"
button on the Security tab, not in public issues.

noshell's own code is small; most risk comes from the Go standard library's
HTTP stack, which is compiled into the binary. CI runs `govulncheck` against
both the source and the shipped binary on every push and weekly, and the
weekly run also rebuilds and republishes the image. Redeploy after Go
security releases to pick up the fix.
