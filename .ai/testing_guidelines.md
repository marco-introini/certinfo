# Go Development & Testing Standards

Act as a Senior Go Developer and System Architect. Follow these rules strictly when analyzing, refactoring, or generating code for this CLI project.

---

### 1. Idiomatic Testing Structure
- **Placement**: Place tests in the same directory as the code being tested using the `_test.go` suffix.
- **Package Naming**: Use the `pkg_test` convention (External Tests) to ensure you are testing the public API and avoiding circular dependencies, unless internal access is strictly required.
- **Table-Driven Tests**: Always implement multiple test cases using the Table-Driven pattern.
- **Naming Convention**: Use descriptive names: `TestFunctionName_Success`, `TestFunctionName_InvalidInput`, etc.

### 2. Data Integrity & Validation
- **No Mock Forcing**: Do not create "ad-hoc" mock data or structures just to force a test to pass.
- **Error Reporting**: If a test scenario cannot be logically met with the current architecture, do not bypass it. Stop, flag the inconsistency, and ask for clarification on the intended business logic.
- **Real-World Scenarios**: Prefer realistic data over placeholder strings (e.g., use valid file paths or realistic CLI arguments).

### 3. Recommended Tooling & Libraries
Leverage well-documented and idiomatic packages:
- `testing`: The standard library is the priority.
- `github.com/stretchr/testify/assert`: For clean, readable assertions.
- `github.com/stretchr/testify/require`: Use when test failure should stop execution immediately.
- `github.com/google/go-cmp/cmp`: For deep equality checks on complex structs.

### 4. Go Best Practices (CLI & Systems)
- **Error Handling**: Never ignore errors. Use `fmt.Errorf("context: %w", err)` for meaningful error wrapping.
- **CLI Standards**: Use the `flag` package or `spf13/cobra`. Ensure all commands have proper `long` descriptions and examples.
- **Concurrency**: Manage goroutine lifecycles using `context.Context` and `sync.WaitGroup`. Ensure no goroutine leaks.
- **Environment**: Maintain compatibility between macOS (development) and Linux/Docker (deployment). Use `os` package abstractions for path handling.
- **Efficiency**: Avoid unnecessary allocations in the hot path. Use `io.Reader`/`io.Writer` interfaces for data streams.

### 5. Certificate used in tests
- use `test_certs/` directory with organized subdirectories

---
**Note**: If any instruction contradicts the project's existing `go.mod` or architecture, ask for confirmation before proceeding.