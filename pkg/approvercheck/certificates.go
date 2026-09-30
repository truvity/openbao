package approvercheck

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// LoadCertificates reads every cert-manager Certificate of a
// multi-document YAML/JSON stream (`helm template ... --show-only
// templates/certificates.yaml`, or a `kubectl get certificates -o yaml`
// list), ignoring every other kind.
func LoadCertificates(path string) ([]cmapi.Certificate, error) {
	objs, err := DecodeDocuments(path)
	if err != nil {
		return nil, err
	}

	var certs []cmapi.Certificate
	for _, obj := range objs {
		switch obj.GetKind() {
		case "Certificate":
			var crt cmapi.Certificate
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &crt); err != nil {
				return nil, fmt.Errorf("decode Certificate %s: %w", obj.GetName(), err)
			}
			certs = append(certs, crt)
		case "List", "CertificateList":
			items, _ := obj.Object["items"].([]any)
			for _, item := range items {
				m, ok := item.(map[string]any)
				if !ok || m["kind"] != "Certificate" {
					continue
				}
				var crt cmapi.Certificate
				if err := runtime.DefaultUnstructuredConverter.FromUnstructured(m, &crt); err != nil {
					return nil, fmt.Errorf("decode Certificate: %w", err)
				}
				certs = append(certs, crt)
			}
		}
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no Certificate documents found", path)
	}

	return certs, nil
}

// RequestsForCertificates builds the CertificateRequest cert-manager would
// create for each Certificate, so the requests of a tenant that does not
// exist yet (a CI namespace that mints its own Issuers under a fresh name
// each run) can be proven against the policies before it ever runs. A live
// run cannot see them; this is the offline half of "prove every request
// shape that can ever arrive".
//
// The CSR carries what cert-manager's pki.GenerateCSR puts there for the
// spec: subject, DNS, URI and email SANs, and a critical basicConstraints
// extension on a CA. The key is generated per the spec's privateKey
// (cert-manager's default, RSA 2048, when it names none). isCA, usages,
// duration and issuerRef ride on the request's spec, which is where the
// evaluator reads them. A Certificate that names no duration gets none, so
// a policy's maxDuration is only proven against a duration the Certificate
// states. namespace, when non-empty, replaces every Certificate's own
// (a rendered chart carries none, or the release's). The request is named
// "<certificate>-1", as cert-manager names a first revision.
//
// pki.GenerateCSR itself is not imported, for the reason decodeCSR gives.
func RequestsForCertificates(certs []cmapi.Certificate, namespace string) ([]cmapi.CertificateRequest, error) {
	var requests []cmapi.CertificateRequest
	for i := range certs {
		crt := &certs[i]
		ns := crt.Namespace
		if namespace != "" {
			ns = namespace
		}

		der, err := csrForCertificate(crt)
		if err != nil {
			return nil, fmt.Errorf("certificate %s: %w", crt.Name, err)
		}

		cr := cmapi.CertificateRequest{}
		cr.Name = crt.Name + "-1"
		cr.Namespace = ns
		cr.Spec = cmapi.CertificateRequestSpec{
			Request:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}),
			IsCA:      crt.Spec.IsCA,
			Usages:    crt.Spec.Usages,
			IssuerRef: crt.Spec.IssuerRef,
			Duration:  crt.Spec.Duration,
		}
		requests = append(requests, cr)
	}

	return requests, nil
}

// csrForCertificate builds the DER CSR for a Certificate spec.
func csrForCertificate(crt *cmapi.Certificate) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: crt.Spec.CommonName},
		DNSNames:       crt.Spec.DNSNames,
		EmailAddresses: crt.Spec.EmailAddresses,
	}
	if s := crt.Spec.Subject; s != nil {
		template.Subject.Organization = s.Organizations
		template.Subject.Country = s.Countries
		template.Subject.OrganizationalUnit = s.OrganizationalUnits
		template.Subject.Locality = s.Localities
		template.Subject.Province = s.Provinces
		template.Subject.StreetAddress = s.StreetAddresses
		template.Subject.PostalCode = s.PostalCodes
		template.Subject.SerialNumber = s.SerialNumber
	}
	for _, raw := range crt.Spec.URIs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("uri %q: %w", raw, err)
		}
		template.URIs = append(template.URIs, u)
	}
	for _, raw := range crt.Spec.IPAddresses {
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, fmt.Errorf("ipAddress %q is not an IP address", raw)
		}
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	if crt.Spec.IsCA {
		value, err := asn1.Marshal(struct {
			IsCA bool `asn1:"optional"`
		}{IsCA: true})
		if err != nil {
			return nil, fmt.Errorf("basicConstraints: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: value,
		})
	}

	key, err := generateKey(crt.Spec.PrivateKey)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	return der, nil
}

// generateKey makes the key a Certificate's privateKey asks for, with
// cert-manager's defaults: RSA 2048 when no algorithm is named, and the
// smallest size of the algorithm (ECDSA 256) when only the size is missing.
func generateKey(spec *cmapi.CertificatePrivateKey) (crypto.Signer, error) {
	alg, size := cmapi.RSAKeyAlgorithm, 0
	if spec != nil {
		if spec.Algorithm != "" {
			alg = spec.Algorithm
		}
		size = spec.Size
	}

	switch alg {
	case cmapi.RSAKeyAlgorithm:
		if size == 0 {
			size = 2048
		}
		// cert-manager refuses RSA keys below 2048 bits, so no real
		// request could carry one: refuse it here too rather than
		// generate a weak key for a request that cannot exist.
		if size < 2048 {
			return nil, fmt.Errorf("privateKey.size %d is below RSA's minimum of 2048", size)
		}
		return rsa.GenerateKey(rand.Reader, size)
	case cmapi.ECDSAKeyAlgorithm:
		var curve elliptic.Curve
		switch size {
		case 0, 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("privateKey.size %d is not an ECDSA curve size (256, 384, 521)", size)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case cmapi.Ed25519KeyAlgorithm:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, errors.New("privateKey.algorithm " + string(alg) + " is not RSA, ECDSA or Ed25519")
	}
}
