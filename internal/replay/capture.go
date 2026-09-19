// Package replay writes what pkg/apply would register onto a real OpenBAO
// server over its HTTP API, without Pulumi's engine or the vault provider
// plugin.
//
// [Capture] runs [apply.Deploy] under Pulumi's mocks and keeps every
// resource it registers, with its inputs. [Server.Replay] then turns each
// one into the API calls the vault provider would make for it -- the
// provider's arguments are the API's parameters in camelCase, so the
// translation is mechanical, and a parameter the server does not recognise
// fails the replay rather than being ignored. The values are therefore the
// apply's own: a conformance test that replays them proves the apply's
// choices (claims, audiences, templates, key types, lifetimes) work on a
// server, not a hand-written copy of them.
//
// Only the resource types pkg/apply registers are known, and only what a
// fresh server needs: creation, never update or deletion.
package replay

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/openbao/pkg/apply"
	"github.com/truvity/openbao/pkg/model"
)

type (
	// Resource is one registration: its type token, its logical name and
	// its inputs, as the mocks saw them. An input taken from another
	// resource's output reads `<name>#<output>`, or `<name>_id` for its
	// ID, until Replay substitutes the real value.
	Resource struct {
		Type   string
		Name   string
		Inputs map[string]any
		// DependsOn are the names of the resources this one waits for:
		// the apply's explicit dependencies and every output it reads.
		DependsOn []string
	}

	mocks struct {
		mu        sync.Mutex
		resources []Resource
	}
)

// NewResource records the registration and answers with a placeholder for
// every output a later input may read.
func (m *mocks) NewResource(args pulumi.MockResourceArgs) (string, resource.PropertyMap, error) {
	state := args.Inputs.Copy()

	record := Resource{Type: args.TypeToken, Name: args.Name, Inputs: args.Inputs.Mappable()}
	if rpc := args.RegisterRPC; rpc != nil {
		for _, urn := range rpc.GetDependencies() {
			record.DependsOn = append(record.DependsOn, urn[strings.LastIndex(urn, "::")+2:])
		}
	}

	m.mu.Lock()
	m.resources = append(m.resources, record)
	m.mu.Unlock()

	for _, key := range []resource.PropertyKey{"csr", "issuerId", "accessor", "certificate", "certificateBundle", "publicKey"} {
		if _, ok := state[key]; !ok {
			state[key] = resource.NewStringProperty(args.Name + "#" + string(key))
		}
	}

	state["importedIssuers"] = resource.NewArrayProperty([]resource.PropertyValue{resource.NewStringProperty(args.Name + "#imported")})

	return args.Name + "_id", state, nil
}

func (*mocks) Call(args pulumi.MockCallArgs) (resource.PropertyMap, error) {
	return args.Args, nil
}

// Capture runs the apply for desired under Pulumi's mocks, as an update
// rather than a preview, and returns what it registered, each resource
// after every resource it depends on.
func Capture(desired *model.Desired, opts apply.Options) ([]Resource, error) {
	m := &mocks{}

	err := pulumi.RunErr(func(c *pulumi.Context) error {
		_, err := apply.Deploy(c, desired, opts)

		return err
	}, pulumi.WithMocks("replay", "conformance", m))
	if err != nil {
		return nil, fmt.Errorf("replay: capture the apply: %w", err)
	}

	for _, r := range m.resources {
		if _, known := handlers[r.Type]; !known {
			return nil, fmt.Errorf("replay: the apply registered %s %s, which replay does not know", r.Type, r.Name)
		}
	}

	return ordered(m.resources)
}

// ordered sorts the resources so that each comes after its dependencies,
// keeping registration order among those that are ready together.
func ordered(resources []Resource) ([]Resource, error) {
	pending := slices.Clone(resources)
	done := map[string]bool{}
	out := make([]Resource, 0, len(pending))

	for len(pending) > 0 {
		progressed := false

		for i := 0; i < len(pending); i++ {
			r := pending[i]

			ready := true
			for _, dependency := range r.DependsOn {
				ready = ready && done[dependency]
			}

			if !ready {
				continue
			}

			out = append(out, r)
			done[r.Name] = true
			pending = slices.Delete(pending, i, i+1)
			i--
			progressed = true
		}

		if !progressed {
			return nil, fmt.Errorf("replay: %d resources wait for each other, starting with %s", len(pending), pending[0].Name)
		}
	}

	return out, nil
}

// Tokens is a login token source for apply.Options, for a capture that
// never logs in anywhere.
func Tokens(context.Context) (string, error) { return "capture", nil }
