module noshell

go 1.24

// The exact Go that builds the shipped binary. Keep in sync with GO_VERSION in
// the Dockerfile (CI fails if they differ).
toolchain go1.27.3
