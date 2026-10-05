package builder

import (
	"fmt"
	"strings"

	"github.com/truvity/secrets/pkg/model"
)

type (
	// SSH is a namespace's SSH engines: a user CA for machines, and a host
	// CA beside it, each on a mount of its own -- a key clients trust for
	// hosts must never also be a key sshd trusts for users
	// (docs/model.md, "SSH").
	SSH struct {
		// Shape is what every role below has in common, so no two roles
		// drift apart on a lifetime or a key type.
		Shape SSHShape `yaml:"shape"`
		// User is the user CA, nil for none.
		User *SSHUser `yaml:"user,omitempty"`
		// Host is the host CA, nil for none.
		Host *SSHHost `yaml:"host,omitempty"`
	}

	// SSHShape is the certificate every role signs.
	SSHShape struct {
		// UserKeyType is the only key type a user role signs.
		UserKeyType string `yaml:"userKeyType"`
		// HostKeyType is the only key type a host role signs.
		HostKeyType string `yaml:"hostKeyType"`
		// KeyIDFormat is the certificate's key id, both kinds: the line an
		// sshd log and the issuer's audit trail have in common, such as
		// `{{token_display_name}}`.
		KeyIDFormat string `yaml:"keyIdFormat"`
		// Extension is the one extension a user certificate carries (a
		// terminal). A forced-command role carries none.
		Extension string `yaml:"extension"`
		// UserTTL and UserMaxTTL bound a user certificate; HostTTL and
		// HostMaxTTL a host certificate. Go durations.
		UserTTL    string `yaml:"userTtl"`
		UserMaxTTL string `yaml:"userMaxTtl"`
		HostTTL    string `yaml:"hostTtl"`
		HostMaxTTL string `yaml:"hostMaxTtl"`
	}

	// SSHUser is a user CA: a key OpenBAO generates and never exports, and
	// the roles that sign certificates for one account each.
	SSHUser struct {
		Mount       string `yaml:"mount"`
		Description string `yaml:"description,omitempty"`
		// KeyType is the CA's own key.
		KeyType string        `yaml:"keyType"`
		Roles   []SSHUserRole `yaml:"roles"`
	}

	// SSHUserRole signs user certificates for ONE account.
	SSHUserRole struct {
		Name string `yaml:"name"`
		// Principal is the account the certificate is for, and the only one
		// it may name: a role has no pattern and refuses root.
		Principal string `yaml:"principal"`
		// ForceCommand is the one command every certificate carries, so a
		// leaked certificate can run it and nothing else. A forced-command
		// role has no extension, and its grant denies `critical_options`.
		ForceCommand string `yaml:"forceCommand,omitempty"`
		// Policy, when set, is declared: `update` on the role's sign path
		// and nothing else. Whoever holds it can sign as this role -- a
		// [Workload] naming it as its Policy, a [Grant] with the same
		// name as a group. Empty declares none.
		Policy string `yaml:"policy,omitempty"`
	}

	// SSHHost is a host CA on a mount of its own: hosts prove a name and get
	// it certified, so clients trust the CA for the hosts it signed.
	SSHHost struct {
		Mount       string `yaml:"mount"`
		Description string `yaml:"description,omitempty"`
		KeyType     string `yaml:"keyType"`
		// Roles are the host roles declared here; every [HostLogin]'s role
		// follows them.
		Roles []SSHHostRole `yaml:"roles,omitempty"`
	}

	// SSHHostRole signs host certificates for names it lists, and no
	// others.
	SSHHostRole struct {
		Name string `yaml:"name"`
		// Domains are the names it may sign.
		Domains []string `yaml:"domains"`
		// Bare admits the domain itself, Subdomains everything below it.
		// One of them, or a role signs nothing.
		Bare       bool `yaml:"bare,omitempty"`
		Subdomains bool `yaml:"subdomains,omitempty"`
	}

	// HostAuth is the AWS IAM auth mount a host with no Kubernetes identity
	// (an EC2 instance) proves itself on: with its IAM instance role, in
	// place of a ServiceAccount token.
	HostAuth struct {
		Mount string `yaml:"mount"`
		// PluginVersion is the versioned catalog entry the mount runs
		// (`aws` is an external plugin): a mount naming no version finds no
		// unversioned entry.
		PluginVersion string `yaml:"pluginVersion,omitempty"`
		Description   string `yaml:"description,omitempty"`
		// ServerID is the header value a signed login must carry, unique per
		// namespace, so a login captured for another mount, or another
		// server, is refused here (docs/safety.md, "AWS IAM auth").
		ServerID string `yaml:"serverId"`
		// TTL is the token's life and its maximum: the login signs one host
		// certificate and is done.
		TTL string `yaml:"ttl"`
	}

	// HostLogin lets one fleet of hosts sign its own host certificates, and
	// nobody else's: a role on the [HostAuth] mount bound to the fleet's
	// instance role, a host role on the host CA for the fleet's domain, and
	// the policy that joins them.
	HostLogin struct {
		// Role is the auth role's name on the HostAuth mount.
		Role string `yaml:"role"`
		// InstanceRoleARN is the fleet's IAM instance role, matched on the
		// ARN's text: resolving it to AWS's unique id would need a grant on
		// the fleet's own account, which an OpenBAO in another account does
		// not have, and an instance role outlives its instances
		// (docs/safety.md, "AWS IAM auth").
		InstanceRoleARN string `yaml:"instanceRoleArn"`
		// SigningRole is the host role the fleet signs with, and Domain the
		// one suffix it allows: the fleet's own, so OpenBAO refuses a name
		// under another's.
		SigningRole string `yaml:"signingRole"`
		Domain      string `yaml:"domain"`
		// Policy is the auth role's policy: `update` on the signing role's
		// sign path.
		Policy string `yaml:"policy"`
	}
)

// userRole is one user-certificate role: one principal, one key type, a
// terminal and nothing else, keyed by the token's display name.
func (s SSHShape) userRole(role *SSHUserRole) model.SSHRole {
	out := model.SSHRole{
		Name:         role.Name,
		AllowedUsers: []string{role.Principal},
		DefaultUser:  role.Principal,
		KeyTypes:     []string{s.UserKeyType},
		KeyIDFormat:  s.KeyIDFormat,
		Extensions:   []string{s.Extension},
		TTL:          s.UserTTL,
		MaxTTL:       s.UserMaxTTL,
	}

	if role.ForceCommand != "" {
		out.Extensions = nil
		out.ForceCommand = role.ForceCommand
	}

	return out
}

func (s SSHShape) hostRole(role *SSHHostRole) model.SSHHostRole {
	return model.SSHHostRole{
		Name:             role.Name,
		AllowedDomains:   append([]string(nil), role.Domains...),
		AllowBareDomains: role.Bare,
		AllowSubdomains:  role.Subdomains,
		KeyTypes:         []string{s.HostKeyType},
		KeyIDFormat:      s.KeyIDFormat,
		TTL:              s.HostTTL,
		MaxTTL:           s.HostMaxTTL,
	}
}

// sshMounts are the namespace's SSH engines, and the policies its user
// roles declare.
func (s *SSH) derive() (user []model.SSHMount, host []model.SSHHostMount, policies []model.Policy) {
	if s == nil {
		return nil, nil, nil
	}

	if s.User != nil {
		mount := model.SSHMount{Path: s.User.Mount, Description: s.User.Description, KeyType: s.User.KeyType}

		for i := range s.User.Roles {
			role := &s.User.Roles[i]
			mount.Roles = append(mount.Roles, s.Shape.userRole(role))

			if role.Policy != "" {
				policies = append(policies, model.Policy{
					Name:  role.Policy,
					Rules: []model.Rule{signRule(s.User.Mount, role.Name, role.ForceCommand != "")},
				})
			}
		}

		user = append(user, mount)
	}

	if s.Host != nil {
		mount := model.SSHHostMount{Path: s.Host.Mount, Description: s.Host.Description, KeyType: s.Host.KeyType}

		for i := range s.Host.Roles {
			mount.Roles = append(mount.Roles, s.Shape.hostRole(&s.Host.Roles[i]))
		}

		host = append(host, mount)
	}

	return user, host, policies
}

// hostLogins is what the namespace's host logins add: the AWS auth mount, a
// host role per fleet on the host CA, and each fleet's policy. The policies
// are returned apart, to be declared after the namespace's sorted ones, in
// declaration order.
func hostLogins(namespace string, auth *HostAuth, logins []HostLogin, ssh *SSH, host *[]model.SSHHostMount) ([]model.AWSAuthMount, []model.Policy, error) {
	if len(logins) == 0 {
		return nil, nil, nil
	}

	if auth == nil {
		return nil, nil, fmt.Errorf("builder: namespace %q has host logins and no AWS auth mount for them", namespace)
	}

	if ssh == nil || ssh.Host == nil || len(*host) == 0 {
		return nil, nil, fmt.Errorf("builder: namespace %q has host logins and no SSH host CA for them to sign with", namespace)
	}

	mount := model.AWSAuthMount{
		Path:                   auth.Mount,
		PluginVersion:          auth.PluginVersion,
		Description:            auth.Description,
		IAMServerIDHeaderValue: auth.ServerID,
	}

	var policies []model.Policy

	for i := range logins {
		login := &logins[i]

		if strings.TrimSpace(login.Role) == "" || strings.TrimSpace(login.SigningRole) == "" || strings.TrimSpace(login.Policy) == "" {
			return nil, nil, fmt.Errorf("builder: namespace %q has a host login with no role, signing role or policy", namespace)
		}

		if strings.TrimSpace(login.InstanceRoleARN) == "" {
			return nil, nil, fmt.Errorf("builder: namespace %q: host login %q has no instance role ARN", namespace, login.Role)
		}

		if strings.TrimSpace(login.Domain) == "" {
			return nil, nil, fmt.Errorf("builder: namespace %q: host login %q has no domain", namespace, login.Role)
		}

		mount.Roles = append(mount.Roles, model.AWSAuthRole{
			Name:                  login.Role,
			BoundIAMPrincipalARNs: []string{login.InstanceRoleARN},
			// See HostLogin.InstanceRoleARN.
			ResolveAWSUniqueIDs: false,
			Policies:            []string{login.Policy},
			TTL:                 auth.TTL,
			MaxTTL:              auth.TTL,
		})

		(*host)[0].Roles = append((*host)[0].Roles, ssh.Shape.hostRole(&SSHHostRole{
			Name:       login.SigningRole,
			Domains:    []string{login.Domain},
			Subdomains: true,
		}))

		policies = append(policies, model.Policy{
			Name:  login.Policy,
			Rules: []model.Rule{signRule(ssh.Host.Mount, login.SigningRole, false)},
		})
	}

	return []model.AWSAuthMount{mount}, policies, nil
}
