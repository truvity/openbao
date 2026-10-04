ui = true
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
seal "awskms" {
  region     = "eu-example-1"
  kms_key_id = "alias/openbao-unseal"
}
service_registration "kubernetes" {}
plugin_directory         = "/openbao/plugins"
plugin_auto_download     = true
plugin_auto_register     = true
plugin_download_behavior = "continue"
plugin "auth" "aws" {
  image       = "ghcr.io/openbao/openbao-plugin-auth-aws"
  version     = "v0.1.1"
  binary_name = "openbao-plugin-auth-aws"
  sha256sum   = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
}
audit "file" "to-stdout" {
  options {
    file_path = "stdout"
  }
}
