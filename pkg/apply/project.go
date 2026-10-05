package apply

import (
	"fmt"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/model"
)

// projectNamespace registers one project's namespace, nested one level
// below its environment (parent), and the mounts inside it -- KV and PKI,
// in the same order [applier.namespace] registers an environment's own.
// A project's PKI issuer is signed by an issuer the environment just
// registered (model.Namespace.validateProjects confirmed there is no
// other kind), so this runs after the parent's own PKI mounts, never
// before.
func (a *applier) projectNamespace(parent *scope, project *model.ProjectNamespace) error {
	path := parent.namespace.Name + "/" + project.Name

	created, err := vault.NewNamespace(a.c, a.name("ns-"+parent.namespace.Name+"-"+project.Name), &vault.NamespaceArgs{
		Namespace: parent.arg,
		Path:      pulumi.String(project.Name),
	}, parent.inside...)
	if err != nil {
		return fmt.Errorf("project namespace %s: %w", path, err)
	}

	s := &scope{
		namespace: &model.Namespace{Name: path},
		label:     path,
		arg:       pulumi.String(path),
		created:   created,
		base:      parent.base,
	}
	s.inside = options(s.base, pulumi.DependsOn([]pulumi.Resource{created}))

	a.result.Namespaces = append(a.result.Namespaces, path)

	for i := range project.PKI {
		if err := a.pkiMount(s, &project.PKI[i]); err != nil {
			return err
		}
	}

	for i := range project.KV {
		if err := a.kvMount(s, &project.KV[i]); err != nil {
			return err
		}
	}

	return nil
}
