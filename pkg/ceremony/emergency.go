package ceremony

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/truvity/openbao/pkg/kmssigner"
)

// THE BREAK-GLASS SERVER CERTIFICATE.
//
// OpenBAO's serving certificate is issued by OpenBAO. Two moments exist in
// which it cannot be: after that certificate has expired (cert-manager can
// no longer reach OpenBAO to renew it), and on a new cluster, before any
// OpenBAO answers. For those, and only those, the KMS root signs ONE leaf
// for ONE name, directly, for a short time. Every OpenBAO client already
// trusts that root, so the leaf verifies everywhere the normal chain does;
// cert-manager replaces it through OpenBAO as soon as OpenBAO answers again.
//
// A leaf straight from the root, not an emergency intermediate, on purpose:
//
//   - the same single KMS signature either way, and the same Sign alarm;
//   - an intermediate would put a CA private key on an operator's laptop,
//     able to sign any name for its whole life, where this puts a key that
//     can serve one name for days -- the smallest thing that restores
//     service;
//   - a root with a path length above zero and no name constraint admits a
//     leaf one level below it as it stands, and nothing new is trusted: no
//     client learns a CA it did not already hold;
//   - a root that publishes no revocation cannot revoke a leaf it signs --
//     which is exactly why the lifetime, not a CRL, is the bound, and why
//     it is a week rather than the months of a normal leaf.
//
// The key and the request are made by the operator (openssl), never here:
// this signs a reviewed template and nothing else, like the intermediate
// ceremony, and its output is an incident artifact, not a committed one.
const (
	// DefaultEmergencyServerLifetime is how long the break-glass leaf
	// lives: long enough to outlast cert-manager's longest retry backoff
	// (32h) with room to repair OpenBAO, short enough that an unrevocable
	// leaf of the root is not a standing credential. Re-sign if the outage
	// is longer.
	DefaultEmergencyServerLifetime = 7 * 24 * time.Hour

	// MaxEmergencyServerLifetime is the refusal: a break-glass leaf that
	// lives longer than this is a standing credential nobody can revoke.
	MaxEmergencyServerLifetime = 30 * 24 * time.Hour
)

type (
	// EmergencyServerSpec is everything the break-glass template is built
	// from; nothing in it comes from the request.
	EmergencyServerSpec struct {
		GenerationID string
		// DNSName is the one name the leaf serves. No wildcard.
		DNSName string
		// NotBefore is pinned by the operator so the template, and so its
		// hash, is reproducible; it is truncated to the second.
		NotBefore        time.Time
		Lifetime         time.Duration
		RootArtifactPath string
		// SerialNamespace is the root's (RootSpec.SerialNamespace).
		SerialNamespace string
	}

	// EmergencyServerPlan is the checked input to the one signing call: what
	// print-template shows and confirm-template binds to.
	EmergencyServerPlan struct {
		Spec         EmergencyServerSpec
		RootArtifact RootArtifact
		Root         *x509.Certificate
		Request      *x509.CertificateRequest
		Template     *x509.Certificate
		// TemplateSHA256 is the lowercase hex SHA-256 of the exact
		// TBSCertificate the root key will sign.
		TemplateSHA256 string
	}

	// EmergencyServerOptions names the KMS key and carries the operator's
	// confirmation of the reviewed template.
	EmergencyServerOptions struct {
		KeyARN                string
		ConfirmTemplateSHA256 string
	}

	// EmergencyServerResult is the signed leaf and what was proven about it.
	EmergencyServerResult struct {
		Certificate    *x509.Certificate
		CertificatePEM []byte
		Proof          []string
	}
)

// PrepareEmergencyServer checks the committed root and the request and
// builds the exact certificate the root key would sign. It signs nothing
// and needs no credential, so a second person can reproduce the hash.
func PrepareEmergencyServer(spec EmergencyServerSpec, root RootArtifact, csrPEM []byte) (*EmergencyServerPlan, error) {
	spec.NotBefore = spec.NotBefore.UTC().Truncate(time.Second)
	if err := spec.validate(); err != nil {
		return nil, err
	}

	rootCertificate, err := parseEmergencyRoot(root, spec)
	if err != nil {
		return nil, fmt.Errorf("root artifact: %w", err)
	}

	request, err := parseEmergencyRequest(csrPEM, spec, rootCertificate)
	if err != nil {
		return nil, fmt.Errorf("certificate request: %w", err)
	}

	template, err := EmergencyServerTemplate(spec, rootCertificate, request.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		return nil, err
	}

	templateSHA256, err := tbsSHA256(template, rootCertificate, request.PublicKey)
	if err != nil {
		return nil, err
	}

	return &EmergencyServerPlan{
		Spec:           spec,
		RootArtifact:   root,
		Root:           rootCertificate,
		Request:        request,
		Template:       template,
		TemplateSHA256: templateSHA256,
	}, nil
}

// SignEmergencyServer performs the one KMS signing call for a prepared
// plan. The confirmation must match the plan, and the KMS key must be the
// committed root's. Every signature fires the root key's Sign alarm
// (pkg/custody): that is intended.
func SignEmergencyServer(
	ctx context.Context, client kmssigner.API, plan *EmergencyServerPlan, options EmergencyServerOptions,
) (*EmergencyServerResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ceremony context is required")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if plan == nil || plan.Template == nil || plan.Root == nil || plan.Request == nil {
		return nil, fmt.Errorf("a prepared break-glass plan is required")
	}

	if options.KeyARN == "" {
		return nil, fmt.Errorf("key ARN is required")
	}

	if !strings.EqualFold(strings.TrimSpace(options.ConfirmTemplateSHA256), plan.TemplateSHA256) {
		return nil, fmt.Errorf("template confirmation %q does not match the template to be signed (%s); "+
			"review --print-template and confirm that exact hash", options.ConfirmTemplateSHA256, plan.TemplateSHA256)
	}

	signer, err := kmssigner.New(ctx, client, options.KeyARN)
	if err != nil {
		return nil, err
	}

	rootKey, ok := plan.Root.PublicKey.(*ecdsa.PublicKey)
	if !ok || !rootKey.Equal(signer.Public()) {
		return nil, fmt.Errorf("KMS key %s is not the key behind the committed root artifact %s; refusing to sign",
			options.KeyARN, plan.Spec.RootArtifactPath)
	}

	der, err := x509.CreateCertificate(rand.Reader, plan.Template, issuerFor(plan.Root, signer.Public()), plan.Request.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("sign the break-glass certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse the signed break-glass certificate: %w", err)
	}

	proof, err := verifyEmergencyServer(certificate, plan)
	if err != nil {
		return nil, fmt.Errorf("validate the signed break-glass certificate: %w", err)
	}

	return &EmergencyServerResult{
		Certificate:    certificate,
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: der}),
		Proof:          proof,
	}, nil
}

// Text renders the template the way an operator reviews it.
func (p *EmergencyServerPlan) Text() string {
	template := p.Template

	var b strings.Builder

	line := func(label, value string) {
		fmt.Fprintf(&b, "  %-21s%s\n", label+":", value)
	}

	b.WriteString("break-glass server certificate template (signed DIRECTLY by the root)\n")
	line("root generation", p.Spec.GenerationID)
	line("root artifact", p.Spec.RootArtifactPath)
	line("csr public key", "ECDSA P-384, SPKI SHA-256 "+strings.ToUpper(hex.EncodeToString(spkiHash(p.Request.PublicKey))))
	line("version", "3")
	line("serial", strings.ToUpper(hex.EncodeToString(template.SerialNumber.Bytes())))
	line("signature algorithm", template.SignatureAlgorithm.String())
	line("issuer", p.Root.Subject.String())
	line("subject", template.Subject.String())
	line("dns names", strings.Join(template.DNSNames, ", "))
	line("not before", template.NotBefore.UTC().Format(time.RFC3339))
	line("not after", template.NotAfter.UTC().Format(time.RFC3339)+" ("+p.Spec.Lifetime.String()+")")
	line("basic constraints", "critical, CA:FALSE")
	line("key usage", "critical, Digital Signature")
	line("extended key usage", "TLS Web Server Authentication")
	line("subject key id", strings.ToUpper(hex.EncodeToString(template.SubjectKeyId)))
	line("authority key id", strings.ToUpper(hex.EncodeToString(template.AuthorityKeyId)))
	line("template sha256", p.TemplateSHA256)

	return b.String()
}

// EmergencyServerTemplate is the exact leaf the spec, the root and the
// request's public key determine.
func EmergencyServerTemplate(spec EmergencyServerSpec, root *x509.Certificate, publicKey *ecdsa.PublicKey) (*x509.Certificate, error) {
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CSR public key: %w", err)
	}

	spkiDigest := sha256.Sum256(spki)

	return &x509.Certificate{
		SerialNumber: deterministicSerial(serialLabel(spec.SerialNamespace, "emergency-server"), spec.GenerationID, spec.DNSName,
			spec.NotBefore.Format(time.RFC3339), spki),
		Subject:               pkix.Name{CommonName: spec.DNSName},
		DNSNames:              []string{spec.DNSName},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotBefore.Add(spec.Lifetime),
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          append([]byte(nil), spkiDigest[:20]...),
		AuthorityKeyId:        append([]byte(nil), root.SubjectKeyId...),
	}, nil
}

func (s EmergencyServerSpec) validate() error {
	if s.GenerationID == "" || s.RootArtifactPath == "" {
		return fmt.Errorf("break-glass spec requires a generation and the root artifact path")
	}

	if !isDNSName(s.DNSName) {
		return fmt.Errorf("%q is not a single DNS name (no wildcard, at least two labels)", s.DNSName)
	}

	if s.NotBefore.IsZero() {
		return fmt.Errorf("notBefore is required: the template, and so its hash, must be reproducible")
	}

	if s.Lifetime <= 0 || s.Lifetime > MaxEmergencyServerLifetime {
		return fmt.Errorf("break-glass lifetime %s must be positive and at most %s", s.Lifetime, MaxEmergencyServerLifetime)
	}

	return nil
}

// parseEmergencyRoot re-parses the committed root and checks the leaf's
// validity and name fit inside it.
func parseEmergencyRoot(artifact RootArtifact, spec EmergencyServerSpec) (*x509.Certificate, error) {
	if artifact.GenerationID != spec.GenerationID {
		return nil, fmt.Errorf("artifact belongs to generation %q, not %q", artifact.GenerationID, spec.GenerationID)
	}

	root, err := parseRoot(artifact)
	if err != nil {
		return nil, err
	}

	if len(root.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("root is not a certificate-signing CA with a subject key identifier")
	}

	notAfter := spec.NotBefore.Add(spec.Lifetime)
	if spec.NotBefore.Before(root.NotBefore) || notAfter.After(root.NotAfter) {
		return nil, fmt.Errorf("break-glass validity %s..%s is not within the root's %s..%s",
			spec.NotBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339),
			root.NotBefore.UTC().Format(time.RFC3339), root.NotAfter.UTC().Format(time.RFC3339))
	}

	if len(root.PermittedDNSDomains) > 0 && !slices.ContainsFunc(root.PermittedDNSDomains, func(domain string) bool {
		return dnsNameWithin(spec.DNSName, domain)
	}) {
		return nil, fmt.Errorf("root permits only %v; %q would fail every verifier", root.PermittedDNSDomains, spec.DNSName)
	}

	return root, nil
}

// parseEmergencyRequest accepts a P-384 request, self-signed, that asks for
// nothing but the declared name: an empty subject or CN=<name>, and no SAN
// other than DNS:<name>. What it asks for is checked, never copied: the
// template is built from the spec.
func parseEmergencyRequest(csrPEM []byte, spec EmergencyServerSpec, root *x509.Certificate) (*x509.CertificateRequest, error) {
	request, err := parseRequest(csrPEM)
	if err != nil {
		return nil, err
	}

	key, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || request.PublicKeyAlgorithm != x509.ECDSA || key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("public key must be ECDSA P-384, got %s", request.PublicKeyAlgorithm)
	}

	if key.Equal(root.PublicKey) {
		return nil, fmt.Errorf("public key is the root's own key")
	}

	if len(request.Subject.Names) != 0 && !sameSubject(request.Subject, pkix.Name{CommonName: spec.DNSName}) {
		return nil, fmt.Errorf("subject %q must be empty or exactly CN=%s", request.Subject.String(), spec.DNSName)
	}

	for _, name := range request.DNSNames {
		if name != spec.DNSName {
			return nil, fmt.Errorf("requests DNS name %q; only %s is signed", name, spec.DNSName)
		}
	}

	if len(request.EmailAddresses)+len(request.IPAddresses)+len(request.URIs) != 0 {
		return nil, fmt.Errorf("must not request IP, e-mail or URI names")
	}

	return request, nil
}

// verifyEmergencyServer checks the signed leaf the way a client will --
// chained to the root alone, for the declared name, as a server -- and
// against the plan it was signed from.
func verifyEmergencyServer(certificate *x509.Certificate, plan *EmergencyServerPlan) ([]string, error) {
	var proof []string

	prove := func(ok bool, statement, failure string) error {
		if !ok {
			return errors.New(failure)
		}

		proof = append(proof, statement)

		return nil
	}

	roots := x509.NewCertPool()
	roots.AddCert(plan.Root)

	_, err := certificate.Verify(x509.VerifyOptions{
		DNSName:     plan.Spec.DNSName,
		Roots:       roots,
		CurrentTime: plan.Spec.NotBefore.Add(time.Minute),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	tbs := sha256.Sum256(certificate.RawTBSCertificate)

	for _, check := range []error{
		prove(err == nil, "chains to "+plan.Root.Subject.String()+" alone, for "+plan.Spec.DNSName+", as a TLS server",
			fmt.Sprintf("does not verify against the root for %s: %v", plan.Spec.DNSName, err)),
		prove(hex.EncodeToString(tbs[:]) == plan.TemplateSHA256, "is exactly the reviewed template (sha256 "+plan.TemplateSHA256+")",
			"the signed TBSCertificate is not the reviewed template"),
		prove(!certificate.IsCA && certificate.BasicConstraintsValid, "is not a CA", "is a CA"),
		prove(slices.Equal(certificate.DNSNames, []string{plan.Spec.DNSName}) && len(certificate.IPAddresses) == 0,
			"names "+plan.Spec.DNSName+" and nothing else", "carries names beyond the declared one"),
		prove(certificate.NotAfter.Sub(certificate.NotBefore) == plan.Spec.Lifetime,
			"lives "+plan.Spec.Lifetime.String()+", until "+certificate.NotAfter.UTC().Format(time.RFC3339),
			"its lifetime is not the declared one"),
		prove(certificate.PublicKey.(*ecdsa.PublicKey).Equal(plan.Request.PublicKey), "certifies the request's key",
			"certifies a key other than the request's"),
	} {
		if check != nil {
			return nil, check
		}
	}

	return proof, nil
}

// isDNSName reports whether name is one concrete DNS name of at least two
// labels: no wildcard, no empty label, nothing that is not a hostname.
func isDNSName(name string) bool {
	labels := strings.Split(name, ".")
	if len(labels) < 2 || len(name) > 253 {
		return false
	}

	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}

		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}

	return true
}
