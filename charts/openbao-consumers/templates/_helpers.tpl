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
  pki          cert-manager issuers backed by OpenBAO, the trust anchors
               and bundle that make what they issue verifiable, and the
               certificates that prove both work.
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
Refuse a ClusterSecretStore with no conditions: without them it is readable
from every namespace on the cluster. `by` names the entry, as in
"stores.<name>". The schema refuses a condition that selects nothing
specific (an empty one, an empty list of names, an empty selector); what it
cannot see is a namespace regex that matches more than its author meant.
External Secrets matches a regex unanchored, so "app" also matches
"not-an-app": a regex must be anchored at both ends (^...$), with no
top-level alternation ("^a|b$" anchors only "a" at the start and "b" at the
end; write "^(?:a|b)$"). And one that matches every probe below, names that
share nothing, matches every namespace.
*/}}
{{- define "consumers.requireConditions" -}}
{{- if not .conditions -}}
{{- fail (printf "%s has no conditions — a ClusterSecretStore without them is readable from every namespace on the cluster" .by) -}}
{{- end -}}
{{- range $c := .conditions -}}
{{- range $re := $c.namespaceRegexes | default list -}}
{{- if not (and (hasPrefix "^" $re) (regexMatch `(^|[^\\])(\\\\)*\$$` $re)) -}}
{{- fail (printf "%s has the namespace regex %q, which is not anchored at both ends — External Secrets matches it anywhere in a namespace's name; write ^...$" $.by $re) -}}
{{- end -}}
{{- if eq (include "consumers.topLevelAlternation" $re) "true" -}}
{{- fail (printf "%s has the namespace regex %q, whose | is outside any group — the anchors bind only the first and the last alternative; write ^(?:a|b)$" $.by $re) -}}
{{- end -}}
{{- if and (regexMatch $re "default") (regexMatch $re "kube-system") (regexMatch $re "x") (regexMatch $re "0") -}}
{{- fail (printf "%s has the namespace regex %q, which matches every namespace — name the namespaces, or narrow the regex" $.by $re) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
"true" when a regular expression has a | outside every group: it walks the
pattern once, skipping escaped characters and character classes, counting
parentheses. A class that opens with "]" or "^]" is read as closing early,
which can only refuse a pattern, never admit one.
*/}}
{{- define "consumers.topLevelAlternation" -}}
{{- $escaped := false -}}
{{- $inClass := false -}}
{{- $depth := 0 -}}
{{- $found := false -}}
{{- range $c := splitList "" . -}}
{{- if $escaped -}}
{{- $escaped = false -}}
{{- else if eq $c "\\" -}}
{{- $escaped = true -}}
{{- else if $inClass -}}
{{- if eq $c "]" }}{{ $inClass = false }}{{ end -}}
{{- else if eq $c "[" -}}
{{- $inClass = true -}}
{{- else if eq $c "(" -}}
{{- $depth = add1 $depth -}}
{{- else if eq $c ")" -}}
{{- $depth = sub $depth 1 -}}
{{- else if and (eq $c "|") (le $depth 0) -}}
{{- $found = true -}}
{{- end -}}
{{- end -}}
{{- $found -}}
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
