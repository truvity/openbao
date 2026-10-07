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
      # Not `! helm template ...`: bash's `set -e` ignores a command
      # negated with `!`, so such a probe could never fail the recipe.
      if helm template x "charts/$chart" --set bogusKey=1 >/dev/null 2>&1; then
        echo "$chart: an unknown key rendered" >&2
        exit 1
      fi
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
# tests, which run every ceremony against a KMS double and every apply
# under Pulumi's mocks -- and the conformance tests against a real `bao
# server` the dev shell pins: access-roster (`bao server -dev`) and the
# break-glass TLS bootstrap rehearsal (`bao server`, TLS terminated by a
# stand-in-signed leaf; see rehearse-bootstrap-tls) -- and `promtool check
# rules` over every format of every alerts case of openbao-consumers. Required here, so a
# shell without `bao` fails rather than skipping the proof.
test:
    hack/golden.sh
    OPENBAO_CONFORMANCE=required go test ./...

# The break-glass TLS bootstrap, alone: signs a leaf with a local
# stand-in KMS signer, installs it, starts a real `bao server` with it,
# verifies with only the root, then simulates the normal issuer taking
# over and verifies again. No AWS credential, no cluster -- what `just
# test` already runs as part of ./conformance, isolated for a quick
# rehearsal. docs/ceremony.md's yearly drill is the same shape with the
# real KMS root, run by hand, not by this recipe.
rehearse-bootstrap-tls:
    OPENBAO_CONFORMANCE=required go test ./conformance/... -run TestBootstrapTLS -v

# The OpenBAO 2.7 seal-as-plugin rehearsal (conformance/seal_plugin_test.go):
# real `bao server`s on the exact rendered HCL, on a Docker network with no
# route out, the KMS emulated by a sibling container, the seal plugin
# installed by the preset's own init container. Proves a cold start, a
# restart and a three-voter Raft cluster rolled 2.6.3 to 2.7.0 one node at a
# time, and prints the timings. Needs a Docker daemon (28+, for image
# mounts) and network for the image pulls; it is not part of `just test`
# because CI has no container runtime for it.
rehearse-seal-plugin:
    OPENBAO_SEAL_REHEARSAL=required go test ./conformance/ -run TestSealPluginRehearsal -count=1 -v

# The rendered server HCL against a real `bao`, offline: starts a server in a
# network namespace with no interface and requires it to reach the seal, and
# `bao operator diagnose` to parse the file. CI runs it for 2.6.2 and 2.7.0
# (the server-config job); locally, BAO is the binary to try. Needs
# unprivileged user and network namespaces; not part of `just test`.
server-config BAO=`command -v bao`:
    OPENBAO_BAO_BINARY={{ BAO }} go test ./conformance/ -run 'TestServerAccepts|TestServerStartsOn|TestDiagnose' -count=1 -v

# Regenerate the golden renders, the ceremony's template goldens, the
# model's example, the builder's example, the apply's registered resources, the
# esoaws policy documents and the access-roster example — review the diff
# before committing.
golden:
    hack/golden.sh update
    UPDATE_GOLDEN=1 go test ./pkg/ceremony/ -run Golden
    UPDATE_GOLDEN=1 go test ./pkg/model/ -run Canonical
    UPDATE_GOLDEN=1 go test ./pkg/builder/ -run Golden
    UPDATE_GOLDEN=1 go test ./pkg/apply/ -run Golden
    UPDATE_GOLDEN=1 go test ./pkg/esoaws/ -run 'TestTheClusterIdentity|TestTheReaders'
    UPDATE_GOLDEN=1 go test ./examples/roster/ -run Golden
    UPDATE_GOLDEN=1 go test ./examples/org/

# The worked example (examples/org), levels 0 to 5, with no cluster and no
# cloud account: each level's contract and desired state validate, its apply
# previews under Pulumi's mocks, and its chart values render with
# `helm template` against the committed goldens. The Go half also runs in
# `test`; this is its own job so a failure names the example.
examples:
    go test ./examples/org/ -count=1
    hack/golden.sh examples

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
check: build lint test examples leak-canary

# The admission policies of openbao-consumers (mTLS enforcement, and the AWS
# stores' in podIdentity mode), proved on a real API server: creates a
# throwaway kind cluster (its own temporary kubeconfig, never the ambient
# one), installs each rendered ValidatingAdmissionPolicy, asserts what is
# admitted and refused, and deletes the cluster. The AWS policy is proved
# against External Secrets' real CRDs, fetched from its release
# (OPENBAO_ESO_CRDS overrides the path or URL). Needs docker, kind, kubectl
# and helm on PATH; it is not part of `just test` because CI has no
# container runtime for a cluster.
admission-conformance:
    #!/usr/bin/env bash
    set -euo pipefail
    dir="$(mktemp -d)"
    cluster="openbao-admission-$$"
    trap 'kind delete cluster --name "$cluster" --kubeconfig "$dir/kubeconfig" >/dev/null 2>&1 || true; rm -rf "$dir"' EXIT
    kind create cluster --name "$cluster" --kubeconfig "$dir/kubeconfig" --wait 120s
    OPENBAO_ADMISSION_CONFORMANCE=required OPENBAO_ADMISSION_KUBECONFIG="$dir/kubeconfig" \
      go test ./conformance/ -run TestAdmissionPolicy -count=1 -v
