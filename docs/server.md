# The server, from upstream's chart

This repository does not install the server: upstream's `openbao/openbao`
chart does. What follows is the shape these charts assume of it — an HA
Raft cluster that auto-unseals, serves a certificate cert-manager renews,
and is reached by clients that verify one name — as values for that chart.
Every particular (the endpoint, the key, the region, the image registry) is
a placeholder.

```yaml
global:
  tlsDisable: false
injector:
  enabled: false
server:
  # With the JWT auth method nothing calls TokenReview.
  authDelegator:
    enabled: false
  # All pods start together and retry-join until one is initialised;
  # OrderedReady would stall the others behind an uninitialised first pod.
  podManagementPolicy: Parallel
  extraEnvironmentVars:
    BAO_CACERT: /openbao/userconfig/openbao-tls/ca.crt
    # The in-pod CLI dials 127.0.0.1. Verify the endpoint's name instead of
    # the address: with a name-constrained chain the endpoint is the one
    # name the certificate is certain to carry.
    BAO_TLS_SERVER_NAME: openbao.example.internal
    AWS_REGION: eu-example-1
  extraVolumes:
    - type: secret
      name: openbao-tls           # serverCertificate, from openbao-ops
  # tls-reload (below) signals the bao process across containers.
  shareProcessNamespace: true
  extraContainers: []            # the tls-reload fragment, below
  ha:
    enabled: true
    replicas: 3
    raft:
      enabled: true
      setNodeId: true
      config: |
        ui = true
        # Standbys forward every request to the active node. Since 2.5
        # standbys serve reads, eventually consistent: behind a load
        # balancer that targets every pod, a client's next call can land on
        # a standby that has not applied its last write yet.
        disable_standby_reads = true
        listener "tcp" {
          address         = "[::]:8200"
          cluster_address = "[::]:8201"
          tls_cert_file   = "/openbao/userconfig/openbao-tls/tls.crt"
          tls_key_file    = "/openbao/userconfig/openbao-tls/tls.key"
        }
        storage "raft" {
          path = "/openbao/data"
          # Dial the pod, verify the endpoint's name.
          retry_join {
            leader_api_addr       = "https://openbao-0.openbao-internal:8200"
            leader_ca_cert_file   = "/openbao/userconfig/openbao-tls/ca.crt"
            leader_tls_servername = "openbao.example.internal"
          }
          # ... one retry_join per replica
        }
        seal "awskms" {
          region     = "eu-example-1"
          kms_key_id = "alias/openbao-unseal"
        }
        service_registration "kubernetes" {}
        # Declared, because OpenBAO refuses API-created audit devices. The
        # restore check's scratch server declares the same (auditConfig).
        audit "file" "to-stdout" {
          options {
            file_path = "stdout"
          }
        }
```

## Verifying one name

A certificate issued from a name-constrained intermediate cannot carry the
short in-cluster names (`openbao`, `openbao-active.<ns>.svc`, the peers'
pod names) unless the constraint admits them, and every SAN of a leaf is
checked against it. The alternative to widening the constraint is to put
ONE name on the certificate — the endpoint — and have every in-cluster
client verify that name while dialling whatever address it dials:

| Client | Setting |
|---|---|
| the server's own CLI | `BAO_TLS_SERVER_NAME` |
| Raft peers | `retry_join { leader_tls_servername }` |
| the openbao-ops jobs | `server.tlsServerName` |
| the certificate | `serverCertificate.serviceDnsNames: false`, `ipAddresses: []` |

## Reloading a renewed certificate

The upstream chart runs `bao server` under a `/bin/sh -ec` wrapper, so PID
1 is the shell and a SIGHUP sent to the pod is swallowed. cert-manager
renews the certificate on disk, nothing reloads it, and the server keeps
presenting the old one until something restarts it — usually an expiry
outage. The tls-reload sidecar watches the file and signals the `bao`
process itself; it needs `shareProcessNamespace: true`.

When openbao-ops is a subchart of the chart that installs the server, the
fragment splices in directly:

```yaml
server:
  shareProcessNamespace: true
  extraContainers: |
    {{- include "ops.tlsReloadContainer" . | nindent 2 }}
```

Otherwise copy the container from `ops.tlsReloadContainer` in
`charts/openbao-ops/templates/_helpers.tpl` into `server.extraContainers`,
with the `tlsReload` values filled in.

## Rolling a configuration change

The upstream StatefulSet uses `OnDelete`: a change to the server's
configuration reaches a pod only when that pod is deleted. Roll by hand,
one pod at a time, standbys first and the active node last, waiting for
Raft to report every voter healthy between pods.

## Image

Keep the server's image, `snapshot.image`, `restoreCheck.image` and
`tlsReload.image` on the same tag: a restore check that restores with an
older `bao` than took the snapshot is proving the wrong pairing.
