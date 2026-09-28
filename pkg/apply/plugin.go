package apply

import (
	"fmt"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/model"
)

// plugins registers every entry in the desired state's plugin catalog.
// The catalog sits above every namespace -- one registry for the whole
// server, not one per namespace -- so this runs once, before a single
// namespace is (Deploy's own call order): a namespace's mount of an
// external plugin type would otherwise race its own registration.
//
// vault.Plugin carries no Namespace argument of its own (the provider's
// underlying `sys/plugins/catalog/:type/:name` is not a namespaced path),
// so every entry here always lands in root, regardless of which
// namespaces later mount it.
func (a *applier) plugins() error {
	base := options(a.opts.ResourceOptions, pulumi.Provider(a.provider))

	for i := range a.desired.Plugins {
		if err := a.plugin(&a.desired.Plugins[i], base); err != nil {
			return err
		}
	}

	return nil
}

// plugin registers one catalog entry for a binary this apply assumes is
// already present, under the server's own `plugin_directory`, as
// desired.Command: placing it there (typically a declarative `plugin`
// block in the server's HCL config) is a different change, reviewed and
// rolled out on its own (model.Plugin's doc comment).
func (a *applier) plugin(desired *model.Plugin, base []pulumi.ResourceOption) error {
	args := &vault.PluginArgs{
		Type:    pulumi.String(desired.Type),
		Name:    pulumi.String(desired.Name),
		Command: pulumi.String(desired.Command),
		Sha256:  pulumi.String(desired.SHA256),
	}

	if _, err := vault.NewPlugin(a.c, a.name("plugin-"+desired.Type+"-"+desired.Name), args, base...); err != nil {
		return fmt.Errorf("plugin catalog %s/%s: %w", desired.Type, desired.Name, err)
	}

	return nil
}
