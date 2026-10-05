package conformance_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/pkg/serverpreset"
)

// TestRestoreCheckSealPluginValues feeds serverpreset's RestoreCheckValues
// through charts/openbao-ops, the way a consumer does, and checks that the
// scratch server gets what the real server gets: the seal and plugin stanza,
// plugin_directory, the init container from the plugin image volume, and a
// plugin directory the server container mounts. Needs `helm`, like the
// alert tests.
func TestRestoreCheckSealPluginValues(t *testing.T) {
	helm := tool(t, "helm")

	c := &serverpreset.Config{
		Arch:          "arm64",
		ServerVersion: "2.7.0",
		Seal: serverpreset.Seal{
			Type: "awskms", Region: "eu-example-1", KMSKeyID: "alias/unseal",
			Plugin: &serverpreset.SealPlugin{
				Image:     "registry.example.com/openbao/openbao-plugin-kms-aws",
				Digest:    "sha256:fe9fb94872048c9474156c044ea8852bb5c2e968fc9304a3725e4d434b488541",
				Version:   "v0.1.0",
				CopyImage: "registry.example.com/openbao/openbao:2.7.0",
			},
		},
	}

	generated, err := c.RestoreCheckValues()
	require.NoError(t, err)

	restoreCheck := map[string]any{
		"enabled":   true,
		"loginOnly": true,
		"canary":    map[string]any{"enabled": false},
		"fetch":     map[string]any{"s3": map[string]any{"enabled": true, "bucket": "b", "region": "r"}},
	}
	for k, v := range generated {
		restoreCheck[k] = v
	}

	values, err := yaml.Marshal(map[string]any{"restoreCheck": restoreCheck})
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "values.yaml")
	require.NoError(t, os.WriteFile(file, values, 0o600))

	rendered, err := exec.Command(helm, "template", "rc", opsChart, "--namespace", "openbao", "-f", file).CombinedOutput()
	require.NoError(t, err, "helm template: %s", rendered)

	var (
		scratch string
		job     struct {
			Spec struct {
				JobTemplate struct {
					Spec struct {
						Template struct {
							Spec struct {
								NodeSelector   map[string]string `yaml:"nodeSelector"`
								InitContainers []map[string]any  `yaml:"initContainers"`
								Volumes        []map[string]any  `yaml:"volumes"`
							} `yaml:"spec"`
						} `yaml:"template"`
					} `yaml:"spec"`
				} `yaml:"jobTemplate"`
			} `yaml:"spec"`
		}
	)

	decoder := yaml.NewDecoder(bytes.NewReader(rendered))

	for {
		var object struct {
			Kind string            `yaml:"kind"`
			Data map[string]string `yaml:"data"`
		}

		var raw yaml.Node

		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)
		require.NoError(t, raw.Decode(&object))

		switch object.Kind {
		case "ConfigMap":
			scratch = object.Data["scratch.hcl"]
		case "CronJob":
			require.NoError(t, raw.Decode(&job))
		}
	}

	seal, err := c.SealHCL()
	require.NoError(t, err)

	assert.Contains(t, scratch, `plugin_directory = "/openbao/plugins"`)
	assert.Contains(t, scratch, `plugin "kms" "awskms"`)
	assert.Contains(t, scratch, `command = "kms-awskms-v0.1.0"`)
	assert.Contains(t, scratch, seal[:len(seal)/2], "the seal stanza is the server's own")

	assert.Equal(t, map[string]string{"kubernetes.io/arch": "arm64"}, job.Spec.JobTemplate.Spec.Template.Spec.NodeSelector,
		"the pod runs on the architecture the plugin checksum belongs to")

	var names []string
	for _, init := range job.Spec.JobTemplate.Spec.Template.Spec.InitContainers {
		names = append(names, init["name"].(string))
	}

	require.NotEmpty(t, names)
	assert.Equal(t, "seal-plugin-install", names[0], "the plugin is installed before anything else starts")

	var volumes []string
	for _, v := range job.Spec.JobTemplate.Spec.Template.Spec.Volumes {
		volumes = append(volumes, v["name"].(string))
	}

	assert.Contains(t, volumes, serverpreset.RestoreCheckPluginVolume)
	assert.Contains(t, volumes, serverpreset.DefaultSealPluginSourceVolume)
}
