# Contributing to SNIProxy

Thank you for your interest in contributing to SNIProxy! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

## Code of Conduct

Please be respectful and constructive in all interactions. We aim to maintain a welcoming and inclusive community.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your changes
4. Make your changes
5. Test your changes
6. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.24.5 or later
- Git
- (Optional) Docker for containerized testing

### Setup Instructions

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/sniproxy.git
cd sniproxy

# Add upstream remote
git remote add upstream https://github.com/mosajjal/sniproxy.git

# Install dependencies
go mod download

# Build the project
go build -v ./cmd/sniproxy/

# Run tests
go test -v ./...
```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/your-feature-name` - For new features
- `fix/bug-description` - For bug fixes
- `docs/what-you-updated` - For documentation updates
- `refactor/what-you-refactored` - For code refactoring

### Commit Messages

Write clear, concise commit messages:
- Use the imperative mood ("Add feature" not "Added feature")
- First line should be 50 characters or less
- Add detailed description after a blank line if needed
- Reference issue numbers when applicable

Example:
```
Add IPv6 support for DoH queries

- Implement IPv6 address handling in DNS client
- Update pickSrcAddr to support IPv6 preferences
- Add tests for IPv6 connectivity

Fixes #123
```

## Testing

### Running Tests

```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -v -cover ./...

# Run tests for a specific package
go test -v ./pkg/acl/

# Run a specific test
go test -v -run TestDNSClient_lookupDomain4 ./pkg/
```

### Writing Tests

- Write tests for all new functionality
- Aim for at least 80% code coverage
- Use table-driven tests where appropriate
- Test error cases and edge conditions

Example:
```go
func TestNewFeature(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "test", "expected", false},
        {"invalid input", "", "", true},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := NewFeature(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("NewFeature() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if got != tt.want {
                t.Errorf("NewFeature() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

## Code Style

### Go Standards

- Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines
- Use `gofmt` to format your code
- Use `goimports` to manage imports
- Run `go vet` before submitting

### Linting

We use golangci-lint for additional code quality checks:

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run
```

### Documentation

- Add godoc comments for all exported functions, types, and constants
- Keep comments concise but descriptive
- Update README.md if you add new features or change behavior
- Add examples for complex functionality

Example:
```go
// ProcessRequest handles incoming HTTP requests and proxies them to the origin server.
// It performs ACL checks, DNS resolution, and applies configured transformations.
//
// Parameters:
//   - c: Configuration object containing proxy settings
//   - req: The incoming HTTP request to process
//
// Returns an error if the request cannot be processed or ACL denies the connection.
func ProcessRequest(c *Config, req *http.Request) error {
    // Implementation
}
```

## Submitting Changes

### Pull Request Process

1. Update your branch with the latest upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/master
   ```

2. Push your changes to your fork:
   ```bash
   git push origin your-branch-name
   ```

3. Create a pull request on GitHub with:
   - Clear title describing the change
   - Detailed description of what changed and why
   - Reference to related issues
   - Screenshots/logs if applicable

4. Wait for review and address any feedback

### Pull Request Checklist

Before submitting, ensure:
- [ ] Code builds without errors
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Code is formatted with `gofmt`
- [ ] No linter warnings
- [ ] Documentation updated
- [ ] Commit messages are clear
- [ ] Branch is rebased on latest master

## Reporting Bugs

### Bug Report Template

When reporting bugs, please include:

1. **Description**: Clear description of the bug
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Environment**:
   - OS and version
   - Go version
   - SNIProxy version
   - Configuration (sanitized)
6. **Logs**: Relevant log output (use DEBUG log level)
7. **Additional Context**: Any other relevant information

## Feature Requests

We welcome feature requests! Please:

1. Check if the feature already exists or is planned
2. Describe the problem you're trying to solve
3. Explain your proposed solution
4. Consider alternatives you've thought about
5. Be open to discussion and feedback

## Questions?

If you have questions:
- Check the [documentation](https://pkg.go.dev/github.com/mosajjal/sniproxy/v2/pkg)
- Search [existing issues](https://github.com/mosajjal/sniproxy/issues)
- Open a new issue with the "question" label

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to SNIProxy! 🎉
