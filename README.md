# ServiceNow SDK (Extracted)

This directory contains the standalone SDK extracted from the toolkit.

## Module

- Module path: `github.com/Krive/ServiceNow-SDK`
- Source layout preserved from toolkit for low-risk migration:
  - `pkg/servicenow/*`
  - `pkg/types/*`
  - `pkg/utils/*`

## Local development from toolkit repo

The toolkit root module uses:

- `require github.com/Krive/ServiceNow-SDK v0.1.0`
- `replace github.com/Krive/ServiceNow-SDK => ./sdk`

This lets `cmd/`, `internal/`, `examples/`, and `tests/` consume the extracted SDK while staying in one repository.

## Validation

Run from this folder:

```bash
GOCACHE=/tmp/go-build go test ./...
```

## Externalization (next step)

1. Move `sdk/` contents to a new repository.
2. Tag SDK releases in that repository.
3. Remove the `replace` directive in toolkit root `go.mod`.
4. Pin toolkit to released SDK versions.
