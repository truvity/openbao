package estate

import "github.com/truvity/secrets/pkg/model"

// The names and limits charts/openbao-ops defaults to, as Go constants, so
// an estate that runs the chart as shipped neither passes them as values nor
// restates them in code: its Jobs, the Pod Identity trust of each job's
// ServiceAccount and the OpenBAO subjects the roles are bound to are these
// names. A test in this package holds each to the chart's values.yaml.
const (
	// The ServiceAccounts of the chart's jobs and watches. Each is also the
	// OpenBAO role of a job that logs in (OpsJobs), and the CronJob of its
	// own name.
	OpsSnapshotServiceAccount       = "openbao-snapshot"
	OpsRestoreCheckServiceAccount   = "openbao-restore-check"
	OpsTLSExpiryServiceAccount      = "openbao-tls-expiry"
	OpsSnapshotAgeServiceAccount    = "openbao-snapshot-age"
	OpsJobSuccessServiceAccount     = "openbao-job-success"
	OpsRootGenerationServiceAccount = "openbao-root-generation"
	OpsPluginCatalogServiceAccount  = "openbao-plugin-catalog"

	// OpsSnapshotCronJob is the every-6-hours snapshot's CronJob.
	OpsSnapshotCronJob = OpsSnapshotServiceAccount

	// OpsSnapshotPrefix holds the every-6-hours snapshots in the backup
	// store, OpsWeeklyPrefix the long-retention weekly copies.
	OpsSnapshotPrefix = "raft/"
	OpsWeeklyPrefix   = "weekly/"

	// OpsSnapshotMaxAgeSeconds is how old the newest snapshot in a store may
	// be: two missed runs of the every-6-hours job, the limit the restore
	// check refuses to pass on.
	OpsSnapshotMaxAgeSeconds = 12 * 60 * 60

	// OpsTLSExpiryAlertBeforeSeconds is how close to its end the server's
	// certificate may come before the daily check alerts: 21 days.
	OpsTLSExpiryAlertBeforeSeconds = 21 * 24 * 60 * 60
)

// OpsJobs is [Jobs] for the chart's jobs as shipped, in the namespace the
// chart is installed into: each logs in as the role of its ServiceAccount's
// name, with the policy of the same name, and is bound to that
// ServiceAccount's subject. PluginType and PluginName are the estate's.
func OpsJobs(namespace, pluginType, pluginName string) Jobs {
	job := func(serviceAccount string) Job {
		return Job{Role: serviceAccount, Subject: model.ServiceAccountSubject(namespace, serviceAccount), Policy: serviceAccount}
	}

	return Jobs{
		RestoreCheck:   job(OpsRestoreCheckServiceAccount),
		Snapshot:       job(OpsSnapshotServiceAccount),
		RootGeneration: job(OpsRootGenerationServiceAccount),
		PluginCatalog:  job(OpsPluginCatalogServiceAccount),
		PluginType:     pluginType,
		PluginName:     pluginName,
	}
}
