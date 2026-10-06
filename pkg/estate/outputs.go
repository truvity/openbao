package estate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ConfigOutputs is the public outputs the configuration stack ([stack.Deploy])
// exports, as an estate commits them next to its code: the file's one
// contract. Nothing in it is secret: certificates, certificate requests and
// public keys.
//
// A deployment that has not run yet commits no outputs, which is valid:
// [ConfigOutputs.Ready] reports it.
type ConfigOutputs struct {
	// InternalCAPEM was the first half of the client trust set while the
	// fleet still trusted a retired cluster CA. The stack no longer exports
	// it; the field stays so a file written before it retired still parses.
	InternalCAPEM string `yaml:"internalCaPem"`
	// TrustRootCAPEM is the legacy trust root's certificate: a public anchor.
	TrustRootCAPEM string `yaml:"trustRootCaPem"`
	// Namespaces are the environment namespaces configured: present once the
	// stack has applied.
	Namespaces []string `yaml:"namespaces"`
	// PrivateDomainIntermediateCSRPEM and OriginDomainIntermediateCSRPEM are
	// the domain intermediates' certificate requests, generated inside their
	// mounts and signed by the root during the ceremony. A request is public
	// and exists long before the chain has a CA.
	PrivateDomainIntermediateCSRPEM string `yaml:"privateDomainIntermediateCsrPem"`
	OriginDomainIntermediateCSRPEM  string `yaml:"originDomainIntermediateCsrPem"`
	// SSHUserCAPublicKeys is each environment's SSH user CA public key, by
	// environment: what a host that admits that environment's certificates
	// lists in TrustedUserCAKeys.
	SSHUserCAPublicKeys map[string]string `yaml:"sshUserCaPublicKeys,omitempty"`
	// SSHHostCAPublicKeys is each environment's SSH host CA public key, by
	// environment. Absent for an environment whose host CA has never been
	// applied: every reader treats a missing entry as "not deployed", never
	// as an error.
	SSHHostCAPublicKeys map[string]string `yaml:"sshHostCaPublicKeys,omitempty"`
}

// Validate refuses outputs that are not what the stack exports: every CA
// output present must be a CA certificate, and every SSH key one plain
// OpenSSH public key. [ConfigOutputs.ValidateSSHKeyTypes] holds the keys to
// the types the estate asked for.
func (o *ConfigOutputs) Validate() error {
	for name, value := range map[string]string{
		"internalCaPem":  o.InternalCAPEM,
		"trustRootCaPem": o.TrustRootCAPEM,
	} {
		if value == "" {
			continue
		}

		block, _ := pem.Decode([]byte(value))
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("%s is not a PEM certificate", name)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		if !cert.IsCA {
			return fmt.Errorf("%s (%s) is not a CA", name, cert.Subject)
		}
	}

	for _, set := range []struct {
		name string
		keys map[string]string
	}{{"sshUserCaPublicKeys", o.SSHUserCAPublicKeys}, {"sshHostCaPublicKeys", o.SSHHostCAPublicKeys}} {
		for env, raw := range set.keys {
			if _, err := plainKey(raw); err != nil {
				return fmt.Errorf("%s.%s is not one plain OpenSSH public key", set.name, env)
			}
		}
	}

	return nil
}

// ValidateSSHKeyTypes holds every exported SSH CA key to the type the
// estate configured its CAs with (ssh.KeyAlgoED25519, for one).
func (o *ConfigOutputs) ValidateSSHKeyTypes(userType, hostType string) error {
	for _, set := range []struct {
		name, want string
		keys       map[string]string
	}{{"sshUserCaPublicKeys", userType, o.SSHUserCAPublicKeys}, {"sshHostCaPublicKeys", hostType, o.SSHHostCAPublicKeys}} {
		for env, raw := range set.keys {
			key, err := plainKey(raw)
			if err != nil {
				return fmt.Errorf("%s.%s is not one plain OpenSSH public key", set.name, env)
			}

			if key.Type() != set.want {
				return fmt.Errorf("%s.%s has type %s, want %s", set.name, env, key.Type(), set.want)
			}
		}
	}

	return nil
}

func plainKey(raw string) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return nil, err
	}

	if len(options) != 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("not one plain key")
	}

	return key, nil
}

// SSHUserCAPublicKey is the environment's SSH user CA public key as one
// authorized_keys line, or "" before the stack has exported it.
func (o *ConfigOutputs) SSHUserCAPublicKey(env string) string {
	if o == nil {
		return ""
	}

	return strings.TrimSpace(o.SSHUserCAPublicKeys[env])
}

// SSHHostCAPublicKey is the environment's SSH host CA public key as one
// authorized_keys line, or "" before the stack has exported it.
func (o *ConfigOutputs) SSHHostCAPublicKey(env string) string {
	if o == nil {
		return ""
	}

	return strings.TrimSpace(o.SSHHostCAPublicKeys[env])
}

// Ready reports whether the stack has run: it exports the namespaces it
// configured on every apply. A file without the retired cluster CA is a
// deployed stack, not an enrolled placeholder.
func (o *ConfigOutputs) Ready() bool {
	return o != nil && (len(o.Namespaces) > 0 || o.InternalCAPEM != "")
}
