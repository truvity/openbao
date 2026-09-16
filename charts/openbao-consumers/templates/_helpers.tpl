{{/*
openbao-consumers helpers.

This chart runs on every cluster that CONSUMES an OpenBAO: it renders the
objects that let a cluster read secrets, write them back, and trust the
certificates OpenBAO issues. The server itself is elsewhere.

Three things it renders, and the reason each is here rather than hand-written:

  stores       an External Secrets ClusterSecretStore per kind, all with the
               same auth shape, because the shape is what is easy to get
               subtly wrong — a missing audience, a token that lives too
               long, a role that does not match the store.
  writers      the asymmetric case: a store that presents the WRITER's own
               ServiceAccount token to the environment it writes into. One
               per (writer, environment).
  pki          a cert-manager issuer backed by OpenBAO, the trust bundle
               that makes what it issues verifiable, and the certificates
               that prove both work.
*/}}

{{- define "consumers.annotations" -}}
{{- mergeOverwrite (deepCopy (.root.Values.commonAnnotations | default dict)) (.extra | default dict) | toYaml -}}
{{- end -}}

{{/*
The auth mount for one OpenBAO namespace. A mount is per cluster, so its
name usually carries the cluster's own name; `auth.mountPath` overrides it
outright for an estate that names mounts some other way.
*/}}
{{- define "consumers.authMount" -}}
{{- .Values.auth.mountPath -}}
{{- end -}}

{{/*
The shared half of every ClusterSecretStore this chart renders: the Vault
provider pointed at one OpenBAO namespace, authenticated by a projected
ServiceAccount token.

The token is audience-scoped and short-lived on purpose. An audience means
a token minted for this purpose cannot be replayed against the Kubernetes
API, and ten minutes means a leaked one is worth almost nothing.

  {{- include "consumers.vaultProvider" (dict "root" $ "namespace" $ns "mount" $m "role" $r "sa" $sa "saNamespace" $sans) }}
*/}}
{{- define "consumers.vaultProvider" -}}
vault:
  server: {{ .root.Values.server | quote }}
  {{- with .namespace }}
  namespace: {{ . | quote }}
  {{- end }}
  path: {{ .root.Values.kvMount | quote }}
  version: v2
  {{- with .root.Values.caBundle }}
  caBundle: {{ . | quote }}
  {{- end }}
  auth:
    jwt:
      path: {{ .mount | quote }}
      role: {{ .role | quote }}
      kubernetesServiceAccountToken:
        serviceAccountRef:
          name: {{ .sa | quote }}
          namespace: {{ .saNamespace | quote }}
        audiences:
          - {{ .root.Values.auth.audience | quote }}
        expirationSeconds: {{ .root.Values.auth.expirationSeconds }}
{{- end -}}

{{/*
Claim one object identity, failing when two entries collide.
*/}}
{{- define "consumers.claim" -}}
{{- $key := printf "%s/%s/%s" .kind (.namespace | default "-") .name -}}
{{- if hasKey .registry $key -}}
{{- fail (printf "%s %s is claimed by both %s and %s — two objects cannot share one name" .kind .name (get .registry $key) .by) -}}
{{- end -}}
{{- $_ := set .registry $key .by -}}
{{- end -}}
