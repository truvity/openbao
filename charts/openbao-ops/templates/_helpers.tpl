{{/*
openbao-ops helpers.

This chart runs beside the OpenBAO server, and owns the operational half
the upstream server chart leaves out: proving the backups exist, proving
one of them can still be opened, noticing a serving certificate that stops
renewing, keeping the traffic that reaches the server to what should, and
reloading the serving certificate when it is renewed.

The server itself stays upstream's. What is here is what an install is
actually judged on when it fails.
*/}}

{{- define "ops.annotations" -}}
{{- mergeOverwrite (deepCopy (.root.Values.commonAnnotations | default dict)) (.extra | default dict) | toYaml -}}
{{- end -}}

{{- define "ops.namespace" -}}
{{- .Values.namespace | default .Release.Namespace -}}
{{- end -}}

{{/* The server address a job talks to, defaulted from the release. */}}
{{- define "ops.serverAddress" -}}
{{- if .Values.server.address -}}
{{- .Values.server.address -}}
{{- else -}}
{{- printf "https://%s.%s.svc:%d" .Values.server.activeService (include "ops.namespace" .) (int .Values.server.apiPort) -}}
{{- end -}}
{{- end -}}

{{/*
The pod-level securityContext every job here runs under. Nothing in this
chart needs a filesystem, a user or a capability, so none is granted.
*/}}
{{- define "ops.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65534
runAsGroup: 65534
fsGroup: 65534
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "ops.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop:
    - ALL
{{- end -}}

{{/*
The projected token a job logs in with: audience-scoped, so it cannot be
replayed against the Kubernetes API, and short-lived, so a leaked one is
worth almost nothing. Jobs set automountServiceAccountToken: false and use
this instead — the default token is neither scoped nor short.
*/}}
{{- define "ops.loginVolume" -}}
name: login
projected:
  sources:
    - serviceAccountToken:
        audience: {{ .Values.auth.audience }}
        expirationSeconds: {{ .Values.auth.expirationSeconds }}
        path: token
{{- end -}}

{{/* The login token's path inside a job's container. */}}
{{- define "ops.tokenPath" -}}
{{- printf "%s/token" (trimSuffix "/" .Values.auth.tokenMountPath) -}}
{{- end -}}

{{/* An image reference; a digest wins over a tag. */}}
{{- define "ops.image" -}}
{{- $img := .image -}}
{{- if $img.digest -}}
{{- printf "%s@%s" $img.repository $img.digest -}}
{{- else -}}
{{- printf "%s:%s" $img.repository $img.tag -}}
{{- end -}}
{{- end -}}

{{/*
A container's image lines: the reference, and a pull policy only when one
is set — an unset field takes the cluster's default for the tag.
*/}}
{{- define "ops.imageLines" -}}
image: {{ include "ops.image" (dict "image" .) }}
{{- with .pullPolicy }}
imagePullPolicy: {{ . }}
{{- end }}
{{- end -}}

{{/* The labels every object of one part carries. */}}
{{- define "ops.labels" -}}
app.kubernetes.io/name: {{ . }}
app.kubernetes.io/part-of: openbao
{{- end -}}

{{/*
Renewal lead time in seconds, for the expiry alert's text: explicit, or
derived from serverCertificate.renewBefore when that is whole hours.
*/}}
{{- define "ops.renewBeforeSeconds" -}}
{{- $e := .Values.certificateExpiry -}}
{{- if $e.renewBeforeSeconds -}}
{{- int $e.renewBeforeSeconds -}}
{{- else -}}
{{- $rb := toString .Values.serverCertificate.renewBefore -}}
{{- if not (regexMatch "^[0-9]+h$" $rb) -}}
{{- fail (printf "certificateExpiry.renewBeforeSeconds is required: serverCertificate.renewBefore %q is not whole hours" $rb) -}}
{{- end -}}
{{- mul (trimSuffix "h" $rb | atoi) 3600 -}}
{{- end -}}
{{- end -}}

{{/*
The tls-reload sidecar, as a fragment to splice into the UPSTREAM server
chart's server.extraContainers (docs/server.md).

It exists because of a specific, invisible failure: the upstream chart runs
`bao server` under a `/bin/sh -ec` wrapper, so PID 1 is the shell and a
SIGHUP sent to the pod is swallowed. cert-manager renews the serving
certificate on disk, nothing reloads it, and the server keeps presenting
the old one until something restarts it — which is usually an expiry
outage. This watches the file and signals the `bao` process itself.

Requires shareProcessNamespace: true on the server pod.

  {{- include "ops.tlsReloadContainer" . }}
*/}}
{{- define "ops.tlsReloadContainer" -}}
{{- $r := .Values.tlsReload -}}
- name: tls-reload
  {{- include "ops.imageLines" $r.image | nindent 2 }}
  command: ["/bin/sh", "-c"]
  args:
    - |
      crt={{ $r.certPath }}
      last=$(cksum "$crt")
      while sleep {{ $r.intervalSeconds }}; do
        cur=$(cksum "$crt") || continue
        [ "$cur" = "$last" ] && continue
        for p in /proc/[0-9]*; do
          cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
          case "$cmd" in
            "bao server "*) kill -HUP "${p#/proc/}" && echo "{{ base $r.mountPath }} changed: reloaded bao (pid ${p#/proc/})" ;;
          esac
        done
        last=$cur
      done
  volumeMounts:
    - name: {{ $r.volumeName }}
      mountPath: {{ $r.mountPath }}
      readOnly: true
  resources:
    {{- toYaml $r.resources | nindent 4 }}
  securityContext:
    {{- include "ops.containerSecurityContext" . | nindent 4 }}
{{- end -}}
