# The web UI: served under /ui on the same listener, so it
# is exactly as private as the API. People sign in with
# "OIDC".
#
# The StatefulSet is OnDelete: a change here reaches a pod
# only when that pod is deleted. Roll by hand, one pod at a
# time, standbys first and the leader last, waiting for Raft
# to show three healthy voters between pods.
ui = true
# Standbys forward EVERY request to the active node, as HA
# did before 2.5.0. Serving reads on a standby is only
# eventually consistent, and since the NLB targets every
# pod (example change 1) a client's next call can land on a
# standby that has not applied its last write: the first
# configuration apply got a nil read-back of a mount it
# had just created and `404 no handler for route` writing
# the config of a JWT mount it had just enabled.
disable_standby_reads = true
listener "tcp" {
  address         = "[::]:8200"
  cluster_address = "[::]:8201"
  tls_cert_file   = "/openbao/userconfig/openbao-tls/tls.crt"
  tls_key_file    = "/openbao/userconfig/openbao-tls/tls.key"
}
listener "tcp" {
  address       = "[::]:9101"
  tls_cert_file = "/openbao/userconfig/openbao-tls/tls.crt"
  tls_key_file  = "/openbao/userconfig/openbao-tls/tls.key"
  telemetry {
    metrics_only                   = true
    unauthenticated_metrics_access = true
  }
}
telemetry {
  prometheus_retention_time = "24h"
  disable_hostname          = true
}
storage "raft" {
  path = "/openbao/data"
  # Dial the pod, verify the endpoint's name: the one name
  # the serving certificate is certain to carry, on either
  # chain (the short pod names cannot sit under the private
  # chain's name constraint).
  retry_join {
    leader_api_addr       = "https://openbao-0.openbao-internal:8200"
    leader_ca_cert_file   = "/openbao/userconfig/openbao-tls/ca.crt"
    leader_tls_servername = "openbao.example.internal"
  }
  retry_join {
    leader_api_addr       = "https://openbao-1.openbao-internal:8200"
    leader_ca_cert_file   = "/openbao/userconfig/openbao-tls/ca.crt"
    leader_tls_servername = "openbao.example.internal"
  }
  retry_join {
    leader_api_addr       = "https://openbao-2.openbao-internal:8200"
    leader_ca_cert_file   = "/openbao/userconfig/openbao-tls/ca.crt"
    leader_tls_servername = "openbao.example.internal"
  }
}
# The awskms seal is an external KMS plugin from OpenBAO 2.7
# (no longer built into the binary): the seal stanza AND the
# `plugin "kms"` block that registers the binary are
# the preset's rendering, generated into values (example
# adapter 1). The binary is installed
# by the seal-plugin-install init container above, before
# `bao server` starts; plugin_directory is declared below.
seal "awskms" {
  region     = "eu-example-1"
  kms_key_id = "alias/openbao-unseal"
}
plugin "kms" "awskms" {
  command = "kms-awskms-v0.1.0"
  version = "v0.1.0"
  sha256sum = "9925bd77bb644fbf8a3a479deb39768e5a230e9b2b4eafad18971b54b3b580e2"
}
service_registration "kubernetes" {}
# The `aws` IAM auth method (a host-certificate pilot,
# example adapter 2) ships as an
# external plugin, not in the server binary: OpenBAO,
# unlike Vault, ships no cloud auth methods built in. The
# plugin directory, the download settings and the
# `plugin "auth" "aws"` block are the preset's
# rendering (example adapter 3), so the
# checksum's architecture, the catalog command and the
# sidecar's poll path cannot drift apart.
plugin_directory         = "/openbao/plugins"
plugin_auto_download     = true
plugin_auto_register     = true
plugin_download_behavior = "continue"
plugin "auth" "aws" {
  image       = "ghcr.io/openbao/openbao-plugin-auth-aws"
  version     = "v0.1.1"
  binary_name = "openbao-plugin-auth-aws"
  sha256sum   = "3b03fb12b8cedd9d2d83ea282a32a4f70147c93a927af5937c9b081525830db2"
}
# Declared here because OpenBAO refuses API-created audit
# devices (v2.3.2+). The active node creates it on unseal;
# nothing is configured until it exists.
audit "file" "to-stdout" {
  description = "Every request and response, HMAC'd, to the pod log (example record 1)."
  options {
    file_path = "stdout"
  }
}
