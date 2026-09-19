package ceremony

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/truvity/openbao/pkg/kmssigner"
)

const (
	allIPv4 = "0.0.0.0/0"
	allIPv6 = "::/0"
)

var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

type (
	// IntermediateSpec is everything a domain intermediate's template is
	// built from. All of it is authored: nothing here comes from the CSR,
	// which contributes its public key and nothing else.
	IntermediateSpec struct {
		// TrustDomain names the intermediate below its root ("private",
		// "origin", ...). It is part of the serial and of the artifact.
		TrustDomain  string
		GenerationID string
		CommonName   string
		// Organization is omitted from the subject when empty.
		Organization string
		NotBefore    time.Time
		Lifetime     time.Duration
		// MaxPathLen must be exactly one less than the root's.
		MaxPathLen int
		// PermittedDNSDomains nil means no name-constraints extension at
		// all. When set, the constraint is critical and every IP address
		// is excluded.
		PermittedDNSDomains []string
		RootArtifactPath    string
		ArtifactPath        string
		// SerialNamespace is the root's (RootSpec.SerialNamespace).
		SerialNamespace string
	}

	// IntermediatePlan is the fully checked input to one signing call. It is
	// what print-template shows and what confirm-template binds to.
	IntermediatePlan struct {
		Spec         IntermediateSpec
		RootArtifact RootArtifact
		Root         *x509.Certificate
		Request      *x509.CertificateRequest
		Template     *x509.Certificate
		// TemplateSHA256 is the lowercase hex SHA-256 of the exact
		// TBSCertificate the root key will sign.
		TemplateSHA256 string
	}

	// IntermediateOptions names the KMS key and carries the operator's
	// confirmation of the template they reviewed.
	IntermediateOptions struct {
		KeyARN                string
		ConfirmTemplateSHA256 string
	}

	// IntermediateResult reports the artifact, whether this invocation
	// signed, and every property that was proven about the certificate.
	IntermediateResult struct {
		Artifact    IntermediateArtifact
		Certificate *x509.Certificate
		Signed      bool
		Proof       []string
	}
)

// PrepareIntermediate checks the root, checks the CSR, and builds the exact
// certificate the root key would sign. It performs no signing and needs no
// credential, so a second reviewer can reproduce TemplateSHA256 offline.
func PrepareIntermediate(spec IntermediateSpec, root RootArtifact, csrPEM []byte) (*IntermediatePlan, error) {
	if err := spec.validate(); err != nil {
		return nil, err
	}
	rootCertificate, err := parseIntermediateRoot(root, spec)
	if err != nil {
		return nil, fmt.Errorf("root artifact: %w", err)
	}
	request, err := parseIntermediateRequest(csrPEM, spec, rootCertificate)
	if err != nil {
		return nil, fmt.Errorf("certificate request: %w", err)
	}
	template, err := IntermediateTemplate(spec, rootCertificate, request.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		return nil, err
	}
	templateSHA256, err := tbsSHA256(template, rootCertificate, request.PublicKey)
	if err != nil {
		return nil, err
	}
	return &IntermediatePlan{
		Spec:           spec,
		RootArtifact:   root,
		Root:           rootCertificate,
		Request:        request,
		Template:       template,
		TemplateSHA256: templateSHA256,
	}, nil
}

// SignIntermediate performs the one KMS signing call for a prepared plan,
// or re-validates an existing artifact without signing. The confirmation
// hash must match the plan; the KMS public key must match the committed
// root.
func SignIntermediate(ctx context.Context, client kmssigner.API, plan *IntermediatePlan, options IntermediateOptions) (*IntermediateResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ceremony context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if plan == nil || plan.Template == nil || plan.Root == nil || plan.Request == nil {
		return nil, fmt.Errorf("a prepared intermediate plan is required")
	}
	if options.KeyARN == "" {
		return nil, fmt.Errorf("key ARN is required")
	}
	if !strings.EqualFold(strings.TrimSpace(options.ConfirmTemplateSHA256), plan.TemplateSHA256) {
		return nil, fmt.Errorf("template confirmation %q does not match the template to be signed (%s); "+
			"review --print-template and confirm that exact hash", options.ConfirmTemplateSHA256, plan.TemplateSHA256)
	}

	artifactPath := plan.Spec.ArtifactPath
	existing, err := LoadIntermediateArtifact(artifactPath)
	if err == nil {
		result, err := validateIntermediateArtifact(existing, plan, options.KeyARN)
		if err != nil {
			return nil, fmt.Errorf("existing intermediate state is invalid: %w", err)
		}
		return result, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read intermediate state: %w", err)
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

	attempt := Attempt{
		GenerationID: plan.Spec.GenerationID,
		TrustDomain:  plan.Spec.TrustDomain,
		KeyARN:       options.KeyARN,
		StatePath:    artifactPath,
		Status:       AttemptStatusReserved,
	}
	certificateDER, err := signOnce(artifactPath, attempt, plan.Template, issuerFor(plan.Root, signer.Public()), plan.Request.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("%s intermediate certificate: %w", plan.Spec.TrustDomain, err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse signed intermediate certificate: %w", err)
	}
	proof, err := verifyIntermediate(certificate, plan)
	if err != nil {
		return nil, fmt.Errorf("validate signed intermediate certificate: %w", err)
	}

	artifact := intermediateArtifactFromCertificate(certificate, plan, options.KeyARN)
	if err := writeArtifactExclusive(artifactPath, artifact); err != nil {
		return nil, err
	}
	return &IntermediateResult{Artifact: artifact, Certificate: certificate, Signed: true, Proof: proof}, nil
}

// Text renders the template the way an operator reviews it: every field
// that ends up in the certificate, then the hash confirm-template takes.
func (p *IntermediatePlan) Text() string {
	template := p.Template
	var b strings.Builder
	line := func(label, value string) {
		fmt.Fprintf(&b, "  %-21s%s\n", label+":", value)
	}
	fmt.Fprintf(&b, "%s intermediate certificate template\n", p.Spec.TrustDomain)
	line("root generation", p.Spec.GenerationID)
	line("root artifact", p.Spec.RootArtifactPath)
	line("artifact", p.Spec.ArtifactPath)
	line("csr public key", "ECDSA P-384, SPKI SHA-256 "+strings.ToUpper(hex.EncodeToString(spkiHash(p.Request.PublicKey))))
	line("version", "3")
	line("serial", strings.ToUpper(hex.EncodeToString(template.SerialNumber.Bytes())))
	line("signature algorithm", template.SignatureAlgorithm.String())
	line("issuer", p.Root.Subject.String())
	line("subject", template.Subject.String())
	line("not before", template.NotBefore.UTC().Format(time.RFC3339))
	line("not after", template.NotAfter.UTC().Format(time.RFC3339))
	line("basic constraints", fmt.Sprintf("critical, CA:TRUE, pathlen:%d", template.MaxPathLen))
	line("key usage", "critical, Certificate Sign, CRL Sign")
	line("subject key id", strings.ToUpper(hex.EncodeToString(template.SubjectKeyId)))
	line("authority key id", strings.ToUpper(hex.EncodeToString(template.AuthorityKeyId)))
	if len(template.PermittedDNSDomains) == 0 {
		line("name constraints", "none (names are constrained by role policy only)")
	} else {
		line("name constraints", "critical, permitted DNS: "+strings.Join(template.PermittedDNSDomains, ", ")+
			"; excluded IP: "+strings.Join(ipRangeStrings(template.ExcludedIPRanges), ", "))
	}
	line("template sha256", p.TemplateSHA256)
	return b.String()
}

// IntermediateTemplate is the exact intermediate certificate the spec, the
// root and the CSR's public key determine.
func IntermediateTemplate(spec IntermediateSpec, root *x509.Certificate, publicKey *ecdsa.PublicKey) (*x509.Certificate, error) {
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal CSR public key: %w", err)
	}
	spkiDigest := sha256.Sum256(spki)
	ski := append([]byte(nil), spkiDigest[:20]...)

	template := &x509.Certificate{
		SerialNumber:          deterministicSerial(serialLabel(spec.SerialNamespace, "intermediate"), spec.GenerationID, spec.TrustDomain, spki),
		Subject:               spec.subject(),
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotBefore.Add(spec.Lifetime),
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            spec.MaxPathLen,
		MaxPathLenZero:        spec.MaxPathLen == 0,
		SubjectKeyId:          ski,
		AuthorityKeyId:        append([]byte(nil), root.SubjectKeyId...),
	}
	if len(spec.PermittedDNSDomains) > 0 {
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = append([]string(nil), spec.PermittedDNSDomains...)
		template.ExcludedIPRanges = mustIPRanges(allIPv4, allIPv6)
	}
	return template, nil
}

func (s IntermediateSpec) validate() error {
	if s.TrustDomain == "" || strings.ContainsAny(s.TrustDomain, " /\x00") {
		return fmt.Errorf("intermediate spec requires a trust domain name without spaces or slashes, got %q", s.TrustDomain)
	}
	if s.GenerationID == "" || s.CommonName == "" || s.RootArtifactPath == "" || s.ArtifactPath == "" {
		return fmt.Errorf("intermediate declaration requires generation, common name, and artifact paths")
	}
	if s.NotBefore.IsZero() || s.Lifetime <= 0 {
		return fmt.Errorf("intermediate declaration requires a fixed notBefore and a positive lifetime")
	}
	if s.MaxPathLen < 0 {
		return fmt.Errorf("intermediate maxPathLen must be bounded (0 or more), got %d", s.MaxPathLen)
	}
	return nil
}

func (s IntermediateSpec) subject() pkix.Name {
	return subject(s.CommonName, s.Organization)
}

// parseIntermediateRoot re-parses the committed root and checks that this
// intermediate can legitimately sit below it.
func parseIntermediateRoot(artifact RootArtifact, spec IntermediateSpec) (*x509.Certificate, error) {
	if artifact.GenerationID != spec.GenerationID {
		return nil, fmt.Errorf("artifact belongs to generation %q, not %q", artifact.GenerationID, spec.GenerationID)
	}
	root, err := parseRoot(artifact)
	if err != nil {
		return nil, err
	}
	if len(root.SubjectKeyId) == 0 {
		return nil, fmt.Errorf("root carries no subject key identifier")
	}

	notAfter := spec.NotBefore.Add(spec.Lifetime)
	if spec.NotBefore.Before(root.NotBefore) || notAfter.After(root.NotAfter) {
		return nil, fmt.Errorf("intermediate validity %s..%s is not within the root's %s..%s",
			spec.NotBefore.UTC().Format(time.RFC3339), notAfter.UTC().Format(time.RFC3339),
			root.NotBefore.UTC().Format(time.RFC3339), root.NotAfter.UTC().Format(time.RFC3339))
	}
	rootBounded := root.MaxPathLen > 0 || root.MaxPathLenZero
	if !rootBounded || root.MaxPathLen != spec.MaxPathLen+1 {
		return nil, fmt.Errorf("root maxPathLen must be exactly %d for a domain intermediate with maxPathLen %d, got %d",
			spec.MaxPathLen+1, spec.MaxPathLen, root.MaxPathLen)
	}
	if len(root.PermittedDNSDomains) > 0 {
		for _, permitted := range spec.PermittedDNSDomains {
			if !slices.ContainsFunc(root.PermittedDNSDomains, func(rootDomain string) bool {
				return dnsNameWithin(permitted, rootDomain)
			}) {
				return nil, fmt.Errorf("root permits only %v; the %s intermediate would permit %q, which every leaf would then fail",
					root.PermittedDNSDomains, spec.TrustDomain, permitted)
			}
		}
	}
	return root, nil
}

// parseRoot is what every ceremony below a root checks first: the committed
// artifact is internally consistent, P-384 with SHA-384, self-signed, and a
// certificate-signing CA.
func parseRoot(artifact RootArtifact) (*x509.Certificate, error) {
	root, err := artifact.Certificate()
	if err != nil {
		return nil, err
	}
	rootKey, ok := root.PublicKey.(*ecdsa.PublicKey)
	if !ok || rootKey.Curve != elliptic.P384() || root.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return nil, fmt.Errorf("root must be ECDSA P-384 signed with SHA-384")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("root self-signature verification failed: %w", err)
	}
	if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("root is not a certificate-signing CA")
	}
	return root, nil
}

// parseIntermediateRequest is the one place the P-384 policy is enforced
// cryptographically: the CSR must be self-signed by a P-384 key and ask for
// exactly the authored subject, nothing more.
func parseIntermediateRequest(csrPEM []byte, spec IntermediateSpec, root *x509.Certificate) (*x509.CertificateRequest, error) {
	request, err := parseRequest(csrPEM)
	if err != nil {
		return nil, err
	}
	key, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || request.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("public key must be ECDSA, got %s", request.PublicKeyAlgorithm)
	}
	if key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("public key must be on P-384, got %s", key.Curve.Params().Name)
	}
	if key.Equal(root.PublicKey) {
		return nil, fmt.Errorf("public key is the root's own key")
	}
	if !sameSubject(request.Subject, spec.subject()) {
		return nil, fmt.Errorf("subject %q does not match the authored %s intermediate subject %q",
			request.Subject.String(), spec.TrustDomain, spec.subject().String())
	}
	if len(request.DNSNames)+len(request.EmailAddresses)+len(request.IPAddresses)+len(request.URIs) != 0 {
		return nil, fmt.Errorf("must not request subject alternative names")
	}
	return request, nil
}

func parseRequest(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != certificateRequestPEMType || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("must contain exactly one %s PEM block", certificateRequestPEMType)
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("self-signature verification failed: %w", err)
	}
	return request, nil
}

// tbsSHA256 is the hash of the exact TBSCertificate the root key will
// sign. The TBSCertificate depends on the template, the issuer and the
// subject key, never on which private key signs it, so a throwaway P-384
// key yields byte for byte the bytes KMS will sign.
func tbsSHA256(template, root *x509.Certificate, subjectKey crypto.PublicKey) (string, error) {
	throwaway, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate throwaway key for the template preview: %w", err)
	}
	previewDER, err := x509.CreateCertificate(rand.Reader, template, issuerFor(root, &throwaway.PublicKey), subjectKey, throwaway)
	if err != nil {
		return "", fmt.Errorf("render template preview: %w", err)
	}
	preview, err := x509.ParseCertificate(previewDER)
	if err != nil {
		return "", fmt.Errorf("parse template preview: %w", err)
	}
	tbs := sha256.Sum256(preview.RawTBSCertificate)
	return hex.EncodeToString(tbs[:]), nil
}

// issuerFor is the parent x509.CreateCertificate needs: the root's exact
// encoded subject and its SKI. The public key is the signer's, so the
// standard library's key check still runs.
func issuerFor(root *x509.Certificate, signerPublic crypto.PublicKey) *x509.Certificate {
	return &x509.Certificate{
		RawSubject:   root.RawSubject,
		Subject:      root.Subject,
		SubjectKeyId: root.SubjectKeyId,
		PublicKey:    signerPublic,
	}
}

// verifyIntermediate checks the signed certificate against the plan and
// against the root, and returns one line per property proven.
func verifyIntermediate(certificate *x509.Certificate, plan *IntermediatePlan) ([]string, error) {
	template, root, spec := plan.Template, plan.Root, plan.Spec
	var proof []string
	prove := func(ok bool, statement, failure string) error {
		if !ok {
			return errors.New(failure)
		}
		proof = append(proof, statement)
		return nil
	}

	tbs := sha256.Sum256(certificate.RawTBSCertificate)
	if err := prove(hex.EncodeToString(tbs[:]) == plan.TemplateSHA256,
		"signed TBSCertificate SHA-256 equals the confirmed template hash "+plan.TemplateSHA256,
		"signed certificate body differs from the confirmed template"); err != nil {
		return nil, err
	}
	if err := certificate.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("signature does not verify with the root: %w", err)
	}
	proof = append(proof, "signature verifies with the root's P-384 key (ECDSA-SHA384)")

	roots := x509.NewCertPool()
	roots.AddCert(root)
	chains, err := certificate.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: certificate.NotBefore,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("chain to the committed root does not verify: %w", err)
	}
	if err := prove(len(chains) == 1 && len(chains[0]) == 2,
		"chains to the committed root "+spec.RootArtifactPath+" (fingerprint "+plan.RootArtifact.FingerprintSHA256+")",
		"chain to the committed root is not exactly intermediate -> root"); err != nil {
		return nil, err
	}

	checks := []struct {
		ok                 bool
		statement, failure string
	}{
		{certificate.SignatureAlgorithm == x509.ECDSAWithSHA384 && certificate.PublicKeyAlgorithm == x509.ECDSA,
			"algorithms are ECDSA P-384 with SHA-384", "certificate must use ECDSA with SHA-384"},
		{certificate.PublicKey.(*ecdsa.PublicKey).Equal(plan.Request.PublicKey),
			"public key is the CSR's key (the private half never left OpenBAO)", "certificate public key does not match the CSR"},
		{sameSubject(certificate.Issuer, root.Subject) && bytes.Equal(certificate.AuthorityKeyId, root.SubjectKeyId),
			"issuer and AKI name the root (AKI " + strings.ToUpper(hex.EncodeToString(root.SubjectKeyId)) + ")",
			"issuer or authority key identifier does not name the root"},
		{bytes.Equal(certificate.SubjectKeyId, template.SubjectKeyId),
			"SKI is SHA-256[:20] of the CSR public key (" + strings.ToUpper(hex.EncodeToString(certificate.SubjectKeyId)) + ")",
			"subject key identifier does not derive from the CSR key"},
		{certificate.SerialNumber.Cmp(template.SerialNumber) == 0 && sameSubject(certificate.Subject, template.Subject),
			"subject and deterministic serial match the authored template", "certificate identity or deterministic serial does not match the authored template"},
		{certificate.NotBefore.Equal(template.NotBefore) && certificate.NotAfter.Equal(template.NotAfter),
			"validity is " + certificate.NotBefore.UTC().Format(time.RFC3339) + " to " + certificate.NotAfter.UTC().Format(time.RFC3339) + ", within the root's",
			"certificate validity does not match the authored template"},
		{certificate.IsCA && certificate.BasicConstraintsValid && certificate.MaxPathLen == spec.MaxPathLen && certificate.MaxPathLenZero == (spec.MaxPathLen == 0),
			fmt.Sprintf("CA:TRUE with pathlen %d below a root pathlen %d", certificate.MaxPathLen, root.MaxPathLen),
			"certificate CA constraints do not match the authored template"},
		{certificate.KeyUsage == x509.KeyUsageCertSign|x509.KeyUsageCRLSign && len(certificate.ExtKeyUsage) == 0 && len(certificate.UnknownExtKeyUsage) == 0,
			"key usage is exactly certSign and crlSign", "certificate key usage does not match the authored template"},
	}
	for _, check := range checks {
		if err := prove(check.ok, check.statement, check.failure); err != nil {
			return nil, err
		}
	}

	hasConstraints := slices.ContainsFunc(certificate.Extensions, func(extension pkix.Extension) bool {
		return extension.Id.Equal(oidNameConstraints)
	})
	if len(spec.PermittedDNSDomains) == 0 {
		if err := prove(!hasConstraints && len(certificate.PermittedDNSDomains) == 0 && len(certificate.ExcludedIPRanges) == 0,
			"no name-constraints extension (the "+spec.TrustDomain+" domain is constrained by role policy only)",
			"certificate carries name constraints the "+spec.TrustDomain+" domain must not have"); err != nil {
			return nil, err
		}
	} else {
		constrained := hasConstraints && certificate.PermittedDNSDomainsCritical &&
			reflect.DeepEqual(certificate.PermittedDNSDomains, template.PermittedDNSDomains) &&
			reflect.DeepEqual(ipRangeStrings(certificate.ExcludedIPRanges), ipRangeStrings(template.ExcludedIPRanges)) &&
			len(certificate.ExcludedDNSDomains)+len(certificate.PermittedIPRanges)+len(certificate.PermittedEmailAddresses)+
				len(certificate.ExcludedEmailAddresses)+len(certificate.PermittedURIDomains)+len(certificate.ExcludedURIDomains) == 0
		if err := prove(constrained,
			"critical name constraints permit DNS "+strings.Join(certificate.PermittedDNSDomains, ", ")+
				" and exclude IP "+strings.Join(ipRangeStrings(certificate.ExcludedIPRanges), ", "),
			"certificate name constraints do not match the authored template"); err != nil {
			return nil, err
		}
	}
	return proof, nil
}

func intermediateArtifactFromCertificate(certificate *x509.Certificate, plan *IntermediatePlan, keyARN string) IntermediateArtifact {
	fingerprint := sha256.Sum256(certificate.Raw)
	return IntermediateArtifact{
		GenerationID:           plan.Spec.GenerationID,
		TrustDomain:            plan.Spec.TrustDomain,
		KeyARN:                 keyARN,
		CertificatePEM:         string(pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: certificate.Raw})),
		FingerprintSHA256:      strings.ToUpper(hex.EncodeToString(fingerprint[:])),
		SubjectKeyIdentifier:   strings.ToUpper(hex.EncodeToString(certificate.SubjectKeyId)),
		AuthorityKeyIdentifier: strings.ToUpper(hex.EncodeToString(certificate.AuthorityKeyId)),
		TemplateSHA256:         plan.TemplateSHA256,
		NotAfter:               certificate.NotAfter.UTC().Format(time.RFC3339),
	}
}

func validateIntermediateArtifact(artifact IntermediateArtifact, plan *IntermediatePlan, keyARN string) (*IntermediateResult, error) {
	certificate, err := decodeSingleCertificate([]byte(artifact.CertificatePEM))
	if err != nil {
		return nil, err
	}
	proof, err := verifyIntermediate(certificate, plan)
	if err != nil {
		return nil, err
	}
	if expected := intermediateArtifactFromCertificate(certificate, plan, keyARN); artifact != expected {
		return nil, fmt.Errorf("public metadata does not match certificatePem")
	}
	return &IntermediateResult{Artifact: artifact, Certificate: certificate, Signed: false, Proof: proof}, nil
}

func spkiHash(publicKey crypto.PublicKey) []byte {
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(spki)
	return digest[:]
}

// dnsNameWithin reports whether name is domain or a subdomain of it, the
// way an RFC 5280 permitted subtree admits names.
func dnsNameWithin(name, domain string) bool {
	name, domain = strings.ToLower(name), strings.ToLower(domain)
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func mustIPRanges(cidrs ...string) []*net.IPNet {
	ranges := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("ceremony: invalid CIDR " + cidr)
		}
		ranges = append(ranges, network)
	}
	return ranges
}

func ipRangeStrings(ranges []*net.IPNet) []string {
	out := make([]string, 0, len(ranges))
	for _, network := range ranges {
		out = append(out, network.String())
	}
	return out
}
