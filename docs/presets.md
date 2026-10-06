# Presets for cert-manager, trust-manager and External Secrets

`charts/openbao-consumers` renders the objects an OpenBAO-backed cluster
needs (stores, issuers, bundles, certificates). Those objects run on three
UPSTREAM charts, which the cluster installs itself. The presets are the
values those installs need, kept beside the objects that depend on them.

They are **values files**, shipped in the chart under `presets/`, the same way
as the other component repositories' presets. Pass one with `-f` (or Argo CD
`valueFiles` on an OCI source) BEFORE your own values; your values win where
they set the same key.

| File | Upstream chart | Sets |
|---|---|---|
| `presets/cert-manager.yaml` | `cert-manager` (charts.jetstack.io) | CRDs, metrics scraping, requests, two replicas and a PDB for controller, webhook and cainjector |
| `presets/trust-manager.yaml` | `trust-manager` (charts.jetstack.io) | no injected public package, trust namespace `cert-manager`, Secret targets off, requests, two replicas and a PDB |
| `presets/external-secrets.yaml` | `external-secrets` (charts.external-secrets.io) | CRDs, metrics scraping, requests |

Scheduling (node selectors, tolerations, affinity, spread) is not in a
preset: it is a fact of the cluster. Add it in your own values.

Check a preset against the upstream chart:

```sh
helm template x cert-manager --repo https://charts.jetstack.io \
  -f charts/openbao-consumers/presets/cert-manager.yaml
```

## From Go

A consumer that composes the upstream chart's values in code (one Argo CD
source, the preset under its own values) reads the same files from the module:

```go
import "github.com/truvity/secrets/charts/openbao-consumers/presets"

base, err := presets.Values(presets.CertManager) // map[string]any
```

They are versioned with the module, so the preset a consumer runs is the one
its `go.mod` pins.

