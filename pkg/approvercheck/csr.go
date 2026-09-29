package approvercheck

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// decodeCSR parses the PEM-encoded X.509 CertificateRequest a
// cert-manager CertificateRequest's spec.request carries. A deliberately
// small stand-in for cert-manager's own
// pkg/util/pki.DecodeX509CertificateRequestBytes: that helper package is
// public, but importing it for three lines drags heavy dependencies
// (component-base, prometheus, ldap) into the module.
func decodeCSR(raw []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("spec.request is not PEM-encoded")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}

	return csr, nil
}

// publicKeyAlgorithmAndSize mirrors approver-policy's
// pkg/internal/approver/constraints decodePublicKey: the algorithm and bit
// size of a CSR's public key, as the constraints.privateKey check compares
// against.
func publicKeyAlgorithmAndSize(pub any) (cmapi.PrivateKeyAlgorithm, int, error) {
	switch pubKey := pub.(type) {
	case *rsa.PublicKey:
		return cmapi.RSAKeyAlgorithm, pubKey.N.BitLen(), nil
	case *ecdsa.PublicKey:
		return cmapi.ECDSAKeyAlgorithm, pubKey.Curve.Params().BitSize, nil
	case ed25519.PublicKey:
		return cmapi.Ed25519KeyAlgorithm, -1, nil
	default:
		return "", -1, fmt.Errorf("unrecognized public key type %T", pub)
	}
}
