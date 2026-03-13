# Contributing

## Setup

```bash
git clone https://github.com/YOUR_USERNAME/sniproxy.git
cd sniproxy
go mod download
go build -v ./cmd/sniproxy/
go test -v ./...
```

Needs Go 1.24+ and git.

## Making changes

Fork, branch, fix, test, PR. Use descriptive branch names like `fix/dns-timeout` or `feature/doq-support`.

Write commit messages in imperative mood ("Add X" not "Added X"). Keep the first line under 50 chars. Reference issue numbers if applicable.

## Testing

```bash
go test -v ./...                              # all tests
go test -v -cover ./...                       # with coverage
go test -v -run TestDNSClient_lookupDomain4 ./pkg/  # specific test
```

Write tests for new code. Table-driven tests where it makes sense. Test the error paths too.

## Code style

Run `gofmt`, `go vet`, and `golangci-lint run` before submitting. Zero warnings is the goal.

Follow [Effective Go](https://golang.org/doc/effective_go.html). Add godoc comments on exported symbols. Keep them concise.

## Pull requests

Rebase on latest master before submitting. Include a clear description of what changed and why. Make sure CI is green.

## Bugs and feature requests

Open an issue. For bugs, include: what you did, what happened, what you expected, your OS/Go version, and relevant logs (run with `log_level: debug`).
