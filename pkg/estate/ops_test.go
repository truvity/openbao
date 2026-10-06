package estate_test

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/pkg/estate"
)

// The constants are the chart's own defaults, not a second opinion.
func TestOpsDefaultsAreTheChartsValues(t *testing.T) {
	raw, err := os.ReadFile("../../charts/openbao-ops/values.yaml")
	require.NoError(t, err)

	var values map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &values))

	at := func(path ...string) any {
		var node any = values
		for _, key := range path {
			node = node.(map[string]any)[key]
		}

		return node
	}

	assert.Equal(t, estate.OpsSnapshotServiceAccount, at("snapshot", "serviceAccountName"))
	assert.Equal(t, estate.OpsSnapshotServiceAccount, at("snapshot", "baoRole"))
	assert.Equal(t, estate.OpsRestoreCheckServiceAccount, at("restoreCheck", "serviceAccountName"))
	assert.Equal(t, estate.OpsRestoreCheckServiceAccount, at("restoreCheck", "baoRole"))
	assert.Equal(t, estate.OpsTLSExpiryServiceAccount, at("certificateExpiry", "name"))
	assert.Equal(t, estate.OpsSnapshotAgeServiceAccount, at("snapshotAge", "name"))
	assert.Equal(t, estate.OpsJobSuccessServiceAccount, at("jobSuccess", "name"))
	assert.Equal(t, estate.OpsRootGenerationServiceAccount, at("rootGeneration", "name"))
	assert.Equal(t, estate.OpsRootGenerationServiceAccount, at("rootGeneration", "baoRole"))
	assert.Equal(t, estate.OpsPluginCatalogServiceAccount, at("pluginCatalog", "name"))
	assert.Equal(t, estate.OpsPluginCatalogServiceAccount, at("pluginCatalog", "baoRole"))

	jobs := at("snapshot", "jobs").([]any)
	assert.Equal(t, estate.OpsSnapshotCronJob, jobs[0].(map[string]any)["name"])
	assert.Equal(t, estate.OpsSnapshotPrefix, jobs[0].(map[string]any)["prefix"])
	assert.Equal(t, estate.OpsWeeklyPrefix, jobs[1].(map[string]any)["prefix"])
	assert.Equal(t, estate.OpsSnapshotPrefix, at("restoreCheck", "fetch", "s3", "prefix"))
	assert.Equal(t, strconv.Itoa(estate.OpsSnapshotMaxAgeSeconds), strconv.Itoa(at("restoreCheck", "maxSnapshotAgeSeconds").(int)))
	assert.Equal(t, strconv.Itoa(estate.OpsTLSExpiryAlertBeforeSeconds), strconv.Itoa(at("certificateExpiry", "alertBeforeSeconds").(int)))
}

func TestOpsJobs(t *testing.T) {
	jobs := estate.OpsJobs("ops-ns", "auth", "aws")
	assert.Equal(t, estate.Job{Role: "openbao-snapshot", Subject: "system:serviceaccount:ops-ns:openbao-snapshot", Policy: "openbao-snapshot"}, jobs.Snapshot)
	assert.Equal(t, "auth", jobs.PluginType)
}
