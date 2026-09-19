# Development commands. Everything CI runs is a recipe here — the shared
# check workflow (truvity/ci-workflows) runs each one as its own job.

charts := "openbao-ops openbao-consumers"

# Lint every chart and the Go module.
#
# The schema is part of the lint: an unknown key must fail the render, not
# be silently ignored. Everything a schema cannot express — a snapshot job
# with no uploader, a store with no server, a PKI check with no hierarchy —
# is checked by the chart's own render-time validation, and every rule has
# a fixture under tests/invalid/<chart>/ that must fail.
lint:
    #!/usr/bin/env bash
    set -euo pipefail
    for chart in {{ charts }}; do
      helm lint "charts/$chart"
      ! helm template x "charts/$chart" --set bogusKey=1 >/dev/null 2>&1
      for values in tests/invalid/"$chart"/*.yaml; do
        if helm template invalid "charts/$chart" -f "$values" >/dev/null 2>&1; then
          echo "RENDERED BUT SHOULD HAVE FAILED: $values" >&2
          exit 1
        fi
      done
      echo "$chart: schema and $(ls tests/invalid/"$chart"/*.yaml | wc -l | tr -d ' ') negative fixtures OK"
    done
    golangci-lint config verify
    golangci-lint run ./...

# Golden renders (every chart test case against tests/golden) and the Go
# tests, which run every ceremony against a KMS double.
test:
    hack/golden.sh
    go test ./...

# Regenerate the golden renders and the ceremony's template goldens —
# review the diff before committing.
golden:
    hack/golden.sh update
    UPDATE_GOLDEN=1 go test ./pkg/ceremony/ -run Golden

# Compile everything, openbaoctl included.
build:
    go build ./...

# Format Go files.
fmt:
    golangci-lint fmt ./...

# Reachable Go advisories.
vuln:
    govulncheck ./...

# Run go mod tidy.
tidy:
    go mod tidy

# The reason this repository can be public. Runs in CI as its own job.
leak-canary:
    hack/leak-canary.sh

# Package every chart locally (the release workflow stamps the version from the tag).
package:
    #!/usr/bin/env bash
    set -euo pipefail
    for chart in {{ charts }}; do helm package "charts/$chart" --destination dist/; done

# Everything CI runs on a pull request.
check: build lint test leak-canary
