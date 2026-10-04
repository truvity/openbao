# openbao-ops

The operational half of an OpenBAO install; every part is off until enabled.
The values and their defaults are documented in `values.yaml` and in
[docs/reference.md](../../docs/reference.md).

## serverAlerts.pluginDownload

Alerts on the server's own log, for a failure that has no metric: a failed
declarative plugin download. OpenBAO exports no gauge for it, and with
`plugin_download_behavior = "continue"` a failed download never crash-loops
the server. It starts, or keeps running, without the plugin until something
sends it a SIGHUP, so nothing else in the install says a word about it.
These two rules make that loud.

The object is a `VMRule` of LogsQL rules (`type: vlogs`) that a log ruler
(vmalert against VictoriaLogs) reads. It carries the label
`observability.rule-type: vlogs` by default, which is what routes it to the
log ruler and away from the metrics ruler; change `labels` if your rulers
select differently. It needs the log fields `kubernetes.pod_namespace`,
`kubernetes.container_name` and `_msg`.

Two signals, deliberately not one:

- **`OpenBAOPluginDownloadFailing`** watches the full lifetime of a pod. A
  download can fail again long after boot, on any later SIGHUP (a
  certificate renewal triggers one). It asks the log store directly: did
  the server container log `failed to download plugin` in the window with
  no `successfully downloaded and validated plugin` in the same window?
  Failures alone would page on every ordinary rollout, because the first
  attempt of a fresh pod can lose a race with the network policy admitting
  it and a retry recovers inside the window. Requiring no success in the
  same window makes it a real-outage-only signal.
- **`OpenBAOPluginDownloadSidecarGaveUp`** is the sharper, boot-time-only
  version: the retry sidecar of `pkg/serverpreset` logs
  `giving up after N attempts` once its budget is spent. It cannot fire on
  the race, which is what those attempts exist to absorb, and it says that
  this pod has stopped retrying until its next certificate rotation.

`for` is unset on both rules (the ruler's default, 0s): the window is the
debounce. The ruler appends `_time: <group interval>` to a LogsQL
expression that has no time filter of its own, so the rules carry none and
`interval` (whole minutes, default `15m`) is the lookback the alert text
names. Re-arming a check that is already one window wide with a second wait
would only slow detection.

`plugin` (for example `auth/aws`) is required: the text names the plugin
whose download is watched. `sidecar.container` and `sidecar.attempts` must
match the retry sidecar the server pod runs, because the second rule matches
the line it logs. `clusterName` sets the `k8s_cluster_name` label of every
rule, for a store that holds several clusters. The expressions select
`kubernetes.pod_namespace` by the namespace the server runs in (`namespace`,
else the release namespace), while the object itself goes to
`serverAlerts.pluginDownload.namespace`.

This is a different thing from the `pluginCatalog` watch: that job asks the
catalog, hourly, whether a plugin ever landed. This alert watches the pod's
log for the whole time it runs. Run both.

To prove it both ways, force a failure (remove the egress the download
needs, or roll a pod while it is unreachable) and confirm
`OpenBAOPluginDownloadFailing` appears within one window and
`OpenBAOPluginDownloadSidecarGaveUp` once the sidecar's attempts elapse;
restore the egress, SIGHUP or roll the pod and confirm both resolve once
`successfully downloaded and validated plugin` is logged.
