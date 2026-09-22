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

{{/*
A value as one POSIX shell WORD: single-quoted, with any single quote in it
closed, escaped and reopened.

Helm's `quote` renders a DOUBLE-quoted string, and a double-quoted string is
still read by the shell: a value carrying a backtick or a $( is EXECUTED by
the container that was meant to print it. Found live on 2026-09-21, when a
runbook that said `bao operator generate-root -cancel` ran `bao` inside the
alert container, failed, and left the alert without the one sentence that
says how to stop what it is reporting.

So: nothing a values file carries is code. Every value this chart puts into
a script goes through here, or into the container's environment, where the
shell never looks at it twice.
*/}}
{{- define "ops.shellArg" -}}
'{{ . | toString | replace "'" "'\\''" }}'
{{- end -}}

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

{{/*
The alert contract, and the two implementations of it this chart ships.

`certificateExpiry.alert` came first and reads the thing it is alerting
about (`/work/status`) itself, so every implementation of it has to do the
same arithmetic. The parts that came after it — the watches — separate the
two halves instead: a probe decides whether something is wrong and writes
the whole report, and the alert container only delivers it.

  Container   Reads         Environment   Must
  ------------------------------------------------------------------
  <part>.alert  /work/alert  HOME          deliver the report and exit
                                           non-zero; an empty or absent
                                           file means nothing is wrong,
                                           and then it must exit zero

`/work/alert` is the report: the first line is a one-line summary, the
rest is the description — what broke, what to look at, and the way back.
A probe writes it and nothing else; that is what makes one alert
container serve every watch, and one preset serve every channel.
*/}}

{{/*
The refusals every `<part>.alert` shares. Two presets for one container are
refused because the job alerts once, so a second channel would be silently
dropped.

  {{- include "ops.alertRefusals" (dict "part" "snapshotAge" "alert" $a.alert) }}
*/}}
{{- define "ops.alertRefusals" -}}
{{- $part := .part -}}
{{- $a := .alert -}}
{{- $am := $a.alertmanager -}}
{{- if and $a.sns.enabled $am.enabled -}}
{{- fail (printf "%s.alert has both presets on: sns and alertmanager are two implementations of one contract, and the job alerts once" $part) -}}
{{- end -}}
{{- if and (not $a.sns.enabled) (not $am.enabled) (not $a.command) -}}
{{- fail (printf "%s.alert needs a preset (sns, alertmanager) or an explicit command — a check that tells nobody is a log line" $part) -}}
{{- end -}}
{{- if and $a.sns.enabled (not $a.sns.topicArn) -}}
{{- fail (printf "%s.alert.sns.topicArn is required when the sns preset is on" $part) -}}
{{- end -}}
{{- if and $a.sns.enabled (not $a.sns.region) -}}
{{- fail (printf "%s.alert.sns.region is required when the sns preset is on" $part) -}}
{{- end -}}
{{- if and $am.enabled (not $am.url) -}}
{{- fail (printf "%s.alert.alertmanager.url is required when the alertmanager preset is on" $part) -}}
{{- end -}}
{{- /* The path is the v2 API's and the chart appends it, so what is
       configured is an origin, not an endpoint: a value that is not one
       is a job that posts nowhere, and nobody is told. */ -}}
{{- if and $am.enabled (not (regexMatch `^https?://\S+$` $am.url)) -}}
{{- fail (printf "%s.alert.alertmanager.url must be an http(s) URL Alertmanager answers at, not %q — the alert goes to <url>/api/v2/alerts" $part $am.url) -}}
{{- end -}}
{{- end -}}

{{/*
The alert container of a watch, as a containers[] entry. Both shipped
presets, and the escape hatch for a channel this chart does not know.

  {{- include "ops.alertContainer" (dict "root" $ "part" "snapshotAge" "alert" $a.alert) | nindent 12 }}
*/}}
{{- define "ops.alertContainer" -}}
{{- $part := .part -}}
{{- $a := .alert -}}
{{- $am := $a.alertmanager -}}
{{- $img := $a.image -}}
{{- if $am.enabled -}}
{{- $img = $am.image -}}
{{- end -}}
- name: alert
  {{- include "ops.imageLines" $img | nindent 2 }}
  {{- if $a.sns.enabled }}
  command:
    - /bin/sh
    - -ec
    - |
      if [ ! -s /work/alert ]; then
        echo "{{ $part }}: nothing to report"
        exit 0
      fi
      cat /work/alert
      {{- /* The report is handed over as a file, not as an argument: it
             carries newlines and the words of whatever failed, and a
             shell that has to quote those is a shell that one day does
             not. An SNS subject is one line of at most 100 characters. */}}
      cp /work/alert /tmp/message
      {{- with $a.sns.runbook }}
      {{- /* From the environment, where the shell never looks at it
             twice. It was rendered into the script until 2026-09-21,
             when a runbook naming a command in backticks RAN that
             command here and the sentence never reached the alert. */}}
      printf '\n%s\n' "$OPENBAO_RUNBOOK" >> /tmp/message
      {{- end }}
      aws sns publish --topic-arn {{ include "ops.shellArg" $a.sns.topicArn }} \
        --subject "$(sed -n 1p /work/alert | cut -c1-99)" \
        --message file:///tmp/message
      exit 1
  env:
    - name: AWS_REGION
      value: {{ $a.sns.region }}
    - name: HOME
      value: /tmp
    {{- with $a.sns.runbook }}
    - name: OPENBAO_RUNBOOK
      value: {{ . | quote }}
    {{- end }}
    {{- with $a.env }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- else if $am.enabled }}
  command:
    - /bin/sh
    - -ec
    - |
      if [ ! -s /work/alert ]; then
        echo "{{ $part }}: nothing to report"
        exit 0
      fi
      cat /work/alert
      summary=$(sed -n 1p /work/alert)
      {{- /* A JSON string cannot carry a raw newline and the description
             is several lines, so they are folded into one. The words of
             whatever failed go into that body, and one quote in them
             would make it something Alertmanager rejects — and then
             nobody is told at all. */}}
      description=$(sed -n '2,$p' /work/alert | tr '\n\t' '  ')
      escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
      cat > /tmp/alert.json <<JSON
      [
        {
          "labels": {
            "alertname": "$(escape "$OPENBAO_ALERTNAME")",
            "severity": "$(escape "$OPENBAO_SEVERITY")"{{ if $am.release }},
            "release": "$(escape "$OPENBAO_RELEASE")"{{ end }}
          },
          "annotations": {
            "summary": "$(escape "$summary")",
            "description": "$(escape "$description")"{{ with $am.runbook }},
            "runbook": "$(escape "$OPENBAO_RUNBOOK")"{{ end }}
          }
        }
      ]
      JSON
      curl --silent --show-error --fail --max-time 30 \
        --header 'Content-Type: application/json' \
        --data-binary @/tmp/alert.json \
        {{ include "ops.shellArg" (printf "%s/api/v2/alerts" (trimSuffix "/" $am.url)) }}
      exit 1
  env:
    - name: HOME
      value: /tmp
    {{- /* The JSON body is built in a heredoc that EXPANDS, so every
           value in it arrives through the environment and goes out
           through the same escaper the alert's own words do. A label
           carrying a backtick used to run it here. */}}
    - name: OPENBAO_ALERTNAME
      value: {{ $am.alertname | quote }}
    - name: OPENBAO_SEVERITY
      value: {{ $am.severity | quote }}
    {{- with $am.release }}
    - name: OPENBAO_RELEASE
      value: {{ . | quote }}
    {{- end }}
    {{- with $am.runbook }}
    - name: OPENBAO_RUNBOOK
      value: {{ . | quote }}
    {{- end }}
    {{- with $a.env }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- else }}
  {{- /* The contract for a replacement: read /work/alert — the first line
         a summary, the rest the description — and when it is not empty,
         deliver it and exit non-zero. */}}
  command:
    {{- toYaml $a.command | nindent 4 }}
  {{- with $a.args }}
  args:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  env:
    - name: HOME
      value: /tmp
    {{- with $a.env }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
  {{- end }}
  volumeMounts:
    - name: work
      mountPath: /work
      readOnly: true
    - name: tmp
      mountPath: /tmp
  resources:
    {{- toYaml $a.resources | nindent 4 }}
  securityContext:
    {{- include "ops.containerSecurityContext" .root | nindent 4 }}
{{- end -}}

{{/*
The S3 preset, on any store that speaks the S3 API.

The preset drives the AWS CLI, which reaches AWS unless told otherwise, so
the chart was AWS-only by omission: a caller whose backups sit in Cloudflare
R2, MinIO or Ceph RGW had no way to say so. Three values say so, and every
one of them is inert when left at its default, so an AWS caller renders
what it always did:

  endpoint        empty keeps the AWS endpoint; set, it is AWS_ENDPOINT_URL_S3,
                  which `aws s3` and `aws s3api` both honour. A store that is
                  not AWS also gets AWS_REQUEST_CHECKSUM_CALCULATION and
                  AWS_RESPONSE_CHECKSUM_VALIDATION set to when_required: the
                  CLI's default since 2.23 is to add a CRC32 checksum to every
                  request and expect one on every response, which broke
                  uploads to several S3-compatible stores in early 2025. `--checksum-algorithm` on the
                  upload is explicit and still sent.
  pathStyle       false; true addresses the bucket as endpoint/bucket/key
                  rather than bucket.endpoint/key. The CLI has no environment
                  variable for that, only its config file, so the script
                  writes one line of config into its scratch space and
                  AWS_CONFIG_FILE names it. A property of the store's
                  CERTIFICATE (does its wildcard cover a bucket subdomain?),
                  not of the endpoint, which is why it is its own switch.
  existingSecret  empty keeps the pod's ambient identity; set, it is a Secret
                  holding AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (and
                  optionally AWS_SESSION_TOKEN), given through envFrom.

  {{- include "ops.s3Refusals" (dict "part" "snapshot.upload.s3" "s3" $s3) }}
  {{- with include "ops.s3Configure" (dict "s3" $s3 "configFile" "/tmp/aws-config") }}
  {{ . }}
  {{- end }}
  {{- with include "ops.s3Env" (dict "s3" $s3 "configFile" "/tmp/aws-config") | trim }}
  {{- . | nindent 16 }}
  {{- end }}
  {{- with $s3.existingSecret }}
  envFrom:
    - secretRef:
        name: {{ . }}
  {{- end }}
*/}}

{{/* What every S3 preset refuses. `part` is the values path of the preset. */}}
{{- define "ops.s3Refusals" -}}
{{- $part := .part -}}
{{- $s3 := .s3 -}}
{{- if and $s3.enabled (not $s3.bucket) -}}
{{- fail (printf "%s.bucket is required when the s3 preset is on" $part) -}}
{{- end -}}
{{- if and $s3.enabled (not $s3.region) -}}
{{- fail (printf "%s.region is required when the s3 preset is on" $part) -}}
{{- end -}}
{{- /* The CLI takes the value as it stands, so one it cannot dial is a job
       that fails on every run. Empty is not an endpoint: it is AWS. */ -}}
{{- if and $s3.enabled $s3.endpoint (not (regexMatch `^https?://\S+$` $s3.endpoint)) -}}
{{- fail (printf "%s.endpoint must be an http(s) URL the store answers at, not %q — empty keeps the AWS endpoint" $part $s3.endpoint) -}}
{{- end -}}
{{- end -}}

{{/* The line a preset's script starts with when the bucket is addressed by path. */}}
{{- define "ops.s3Configure" -}}
{{- if .s3.pathStyle -}}
printf '[default]\ns3 =\n  addressing_style = path\n' > {{ .configFile }}
{{- end -}}
{{- end -}}

{{/* The env entries a store that is not AWS needs, after AWS_REGION. */}}
{{- define "ops.s3Env" -}}
{{- with .s3.endpoint }}
- name: AWS_ENDPOINT_URL_S3
  value: {{ . | quote }}
- name: AWS_REQUEST_CHECKSUM_CALCULATION
  value: when_required
- name: AWS_RESPONSE_CHECKSUM_VALIDATION
  value: when_required
{{- end }}
{{- if .s3.pathStyle }}
- name: AWS_CONFIG_FILE
  value: {{ .configFile }}
{{- end }}
{{- end -}}
