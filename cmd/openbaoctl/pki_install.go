package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/truvity/openbao/pkg/ceremony"
)

// THE OTHER HALF OF THE BREAK-GLASS CEREMONY.
//
// `pki sign-emergency-server` produces a leaf and needs no cluster.
// Getting that leaf, its key and the root into the Secret OpenBAO mounts
// is its own, unprivileged step -- no KMS credential, just a kubeconfig --
// and it is the one place the files the operator's machine is holding
// (docs/ceremony.md §4) turn into cluster state. Two moments need it: an
// expired serving certificate on a running cluster (the Secret already
// exists, cert-manager's annotations and all) and a new or restored
// cluster (the Secret does not exist yet, and nothing can issue one
// through OpenBAO until this command has).
//
// Everything here is a refusal until the operator has reviewed what is
// about to be written: the certificate must chain to the given bundle,
// the key must be the certificate's, the leaf must not be expired or
// outlive the 30-day break-glass cap, and either --yes or a typed "yes"
// must confirm it. The private key is read to prove it matches the
// certificate and is never otherwise inspected or printed.
const (
	flagCertificate = "certificate"
	flagPrivateKey  = "private-key"
	flagCABundle    = "ca-bundle"
	flagNamespace   = "namespace"
	flagSecretName  = "secret-name"
	flagCertDataKey = "cert-key"
	flagKeyDataKey  = "key-key"
	flagCADataKey   = "ca-key"
	flagKubeconfig  = "kubeconfig"
	flagKubeContext = "kube-context"
	flagYes         = "yes"

	// defaultSecretName, defaultCertDataKey and defaultKeyDataKey match
	// what docs/server.md documents as the upstream chart's
	// extraVolumes secret and the kubernetes.io/tls keys it expects;
	// defaultCADataKey matches BAO_CACERT there.
	defaultSecretName  = "openbao-tls"
	defaultCertDataKey = "tls.crt"
	defaultKeyDataKey  = "tls.key"
	defaultCADataKey   = "ca.crt"

	confirmPhrase = "yes"
)

type (
	// kubeFactory builds the Kubernetes client for a kubeconfig path and
	// context. Tests replace it with a fake clientset; nothing else does.
	kubeFactory func(kubeconfigPath, kubeContext string) (kubernetes.Interface, error)

	installEmergencyServerOptions struct {
		certificatePath string
		privateKeyPath  string
		caBundlePath    string

		namespace  string
		secretName string
		certKey    string
		keyKey     string
		caKey      string

		kubeconfigPath string
		kubeContext    string

		yes  bool
		in   io.Reader
		now  func() time.Time
		kube kubeFactory
	}
)

func pkiInstallEmergencyServerCommand() *cli.Command {
	return &cli.Command{
		Name:  "install-emergency-server",
		Usage: "BREAK-GLASS: write a signed break-glass leaf into the Secret OpenBAO mounts",
		Description: "Reads the leaf sign-emergency-server produced, the private key generated alongside its\n" +
			"CSR, and the root as a CA bundle; refuses a leaf that does not chain to that bundle, a key\n" +
			"that is not the leaf's, or a leaf that is expired or lives past the 30-day break-glass cap.\n" +
			"Prints what it will write -- never the key -- and requires --yes or a typed confirmation\n" +
			"before creating or updating the Secret. An existing Secret keeps its type, annotations,\n" +
			"labels and every other data key; only the certificate, key and CA entries are replaced. A\n" +
			"missing Secret (a new or restored cluster, before OpenBAO or cert-manager exist) is created\n" +
			"as kubernetes.io/tls when the data key names are the chart's defaults.",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: flagCertificate, Usage: "the signed break-glass leaf (PEM, one certificate)", Required: true},
			&cli.StringFlag{Name: flagPrivateKey, Usage: "the private key generated for the CSR (PEM)", Required: true},
			&cli.StringFlag{Name: flagCABundle, Usage: "the root certificate(s) the leaf must chain to (PEM)", Required: true},
			&cli.StringFlag{Name: flagNamespace, Usage: "namespace the Secret lives (or will be created) in", Required: true},
			&cli.StringFlag{Name: flagSecretName, Usage: "Secret name", Value: defaultSecretName},
			&cli.StringFlag{Name: flagCertDataKey, Usage: "Secret data key for the certificate", Value: defaultCertDataKey},
			&cli.StringFlag{Name: flagKeyDataKey, Usage: "Secret data key for the private key", Value: defaultKeyDataKey},
			&cli.StringFlag{Name: flagCADataKey, Usage: "Secret data key for the CA bundle", Value: defaultCADataKey},
			&cli.StringFlag{Name: flagKubeconfig, Usage: "kubeconfig path (default: KUBECONFIG or ~/.kube/config)"},
			&cli.StringFlag{Name: flagKubeContext, Usage: "kubeconfig context (default: its current-context)"},
			&cli.BoolFlag{Name: flagYes, Usage: "write without an interactive confirmation"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runInstallEmergencyServer(ctx, os.Stdout, installEmergencyServerOptions{
				certificatePath: cmd.String(flagCertificate),
				privateKeyPath:  cmd.String(flagPrivateKey),
				caBundlePath:    cmd.String(flagCABundle),
				namespace:       cmd.String(flagNamespace),
				secretName:      cmd.String(flagSecretName),
				certKey:         cmd.String(flagCertDataKey),
				keyKey:          cmd.String(flagKeyDataKey),
				caKey:           cmd.String(flagCADataKey),
				kubeconfigPath:  cmd.String(flagKubeconfig),
				kubeContext:     cmd.String(flagKubeContext),
				yes:             cmd.Bool(flagYes),
				in:              os.Stdin,
				now:             time.Now,
				kube:            defaultKubeFactory,
			})
		},
	}
}

func runInstallEmergencyServer(ctx context.Context, out io.Writer, options installEmergencyServerOptions) error {
	certificate, certificatePEM, err := loadSingleCertificate(options.certificatePath)
	if err != nil {
		return err
	}

	privateKey, privateKeyPEM, err := loadECPrivateKey(options.privateKeyPath)
	if err != nil {
		return err
	}

	roots, caBundlePEM, err := loadCABundle(options.caBundlePath)
	if err != nil {
		return err
	}

	if err := verifyEmergencyLeaf(certificate, privateKey, roots, options.now()); err != nil {
		return err
	}

	if _, err := fmt.Fprint(out, describeInstallPlan(options, certificate, len(privateKeyPEM))); err != nil {
		return err
	}

	if !options.yes {
		confirmed, err := confirm(options.in, out)
		if err != nil {
			return err
		}

		if !confirmed {
			return fmt.Errorf("not confirmed: nothing written")
		}
	}

	client, err := options.kube(options.kubeconfigPath, options.kubeContext)
	if err != nil {
		return err
	}

	data := map[string][]byte{
		options.certKey: certificatePEM,
		options.keyKey:  privateKeyPEM,
		options.caKey:   caBundlePEM,
	}

	defaultType := corev1.SecretTypeOpaque
	if options.certKey == defaultCertDataKey && options.keyKey == defaultKeyDataKey {
		defaultType = corev1.SecretTypeTLS
	}

	created, err := applyEmergencyServerSecret(ctx, client, options.namespace, options.secretName, data, defaultType)
	if err != nil {
		return err
	}

	verb := "updated"
	if created {
		verb = "created"
	}

	slog.New(slog.NewTextHandler(os.Stderr, nil)).WarnContext(ctx, "installed a break-glass server certificate into a Secret",
		slog.String("namespace", options.namespace), slog.String("secret", options.secretName),
		slog.String("verb", verb), slog.String("not_after", certificate.NotAfter.UTC().Format(time.RFC3339)))

	_, err = fmt.Fprintf(out, "%s Secret %s/%s\n", verb, options.namespace, options.secretName)

	return err
}

// verifyEmergencyLeaf refuses everything install-emergency-server must
// refuse before it ever contacts the cluster: a certificate whose public
// key is not the given private key's, one that has expired or is not yet
// valid, one whose declared lifetime exceeds the break-glass cap
// (ceremony.MaxEmergencyServerLifetime), and one that does not chain to
// the given bundle alone, as a TLS server, for its own name.
func verifyEmergencyLeaf(certificate *x509.Certificate, privateKey *ecdsa.PrivateKey, roots *x509.CertPool, now time.Time) error {
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&privateKey.PublicKey) {
		return fmt.Errorf("the private key does not match the certificate's public key; refusing to install a mismatched pair")
	}

	if now.Before(certificate.NotBefore) {
		return fmt.Errorf("the certificate is not valid until %s", certificate.NotBefore.UTC().Format(time.RFC3339))
	}

	if now.After(certificate.NotAfter) {
		return fmt.Errorf("the certificate expired at %s; sign a fresh break-glass leaf", certificate.NotAfter.UTC().Format(time.RFC3339))
	}

	if lifetime := certificate.NotAfter.Sub(certificate.NotBefore); lifetime > ceremony.MaxEmergencyServerLifetime {
		return fmt.Errorf("the certificate's lifetime %s exceeds the %s break-glass cap; refusing to install a standing credential",
			lifetime, ceremony.MaxEmergencyServerLifetime)
	}

	if len(certificate.DNSNames) != 1 {
		return fmt.Errorf("the certificate names %v; a break-glass leaf must carry exactly one DNS name", certificate.DNSNames)
	}

	if _, err := certificate.Verify(x509.VerifyOptions{
		DNSName:     certificate.DNSNames[0],
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("the certificate does not chain to the given CA bundle alone: %w", err)
	}

	return nil
}

func describeInstallPlan(options installEmergencyServerOptions, certificate *x509.Certificate, privateKeyBytes int) string {
	fingerprint := sha256.Sum256(certificate.Raw)

	var b strings.Builder

	line := func(label, value string) {
		fmt.Fprintf(&b, "  %-16s%s\n", label+":", value)
	}

	b.WriteString("about to write a break-glass server certificate into a Secret\n")
	line("secret", fmt.Sprintf("%s/%s", options.namespace, options.secretName))
	line("data keys", fmt.Sprintf("%s (certificate), %s (private key, %d bytes, not printed), %s (CA bundle)",
		options.certKey, options.keyKey, privateKeyBytes, options.caKey))
	line("subject", certificate.Subject.String())
	line("dns names", strings.Join(certificate.DNSNames, ", "))
	line("serial", strings.ToUpper(hex.EncodeToString(certificate.SerialNumber.Bytes())))
	line("not before", certificate.NotBefore.UTC().Format(time.RFC3339))
	line("not after", certificate.NotAfter.UTC().Format(time.RFC3339))
	line("fingerprint", "SHA256 "+strings.ToUpper(hex.EncodeToString(fingerprint[:])))

	return b.String()
}

// confirm prints the phrase to type and reads exactly one line from in.
func confirm(in io.Reader, out io.Writer) (bool, error) {
	if _, err := fmt.Fprintf(out, "type %q to write this: ", confirmPhrase); err != nil {
		return false, err
	}

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("read confirmation: %w", err)
	}

	return strings.TrimSpace(line) == confirmPhrase, nil
}

func loadSingleCertificate(path string) (*x509.Certificate, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read certificate %s: %w", path, err)
	}

	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("%s does not hold a PEM certificate", path)
	}

	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("%s holds more than one PEM block; the break-glass leaf alone is expected", path)
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}

	return certificate, raw, nil
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key %s: %w", path, err)
	}

	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, nil, fmt.Errorf("%s does not hold a PEM block", path)
	}

	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, fmt.Errorf("%s holds more than one PEM block; the CSR's key alone is expected", path)
	}

	var key any

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, nil, fmt.Errorf("%s is a %q PEM block; expected EC PRIVATE KEY or PRIVATE KEY", path, block.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("parse private key %s: %w", path, err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("%s is not an ECDSA private key", path)
	}

	return ecKey, raw, nil
}

func loadCABundle(path string) (*x509.CertPool, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, nil, fmt.Errorf("%s holds no PEM certificates", path)
	}

	return pool, raw, nil
}

// defaultKubeFactory is the real kubeFactory: the caller's kubeconfig and
// context, never a hardcoded one.
func defaultKubeFactory(kubeconfigPath, kubeContext string) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}

	overrides := &clientcmd.ConfigOverrides{}
	if kubeContext != "" {
		overrides.CurrentContext = kubeContext
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes client: %w", err)
	}

	return client, nil
}

// applyEmergencyServerSecret creates the Secret if it does not exist, with
// defaultType, or updates only data's keys on the one that does -- its
// type, annotations, labels and every other data key untouched.
func applyEmergencyServerSecret(
	ctx context.Context, client kubernetes.Interface, namespace, name string, data map[string][]byte, defaultType corev1.SecretType,
) (created bool, err error) {
	secrets := client.CoreV1().Secrets(namespace)

	existing, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Type:       defaultType,
			Data:       data,
		}

		if _, err := secrets.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return false, fmt.Errorf("create Secret %s/%s: %w", namespace, name, err)
		}

		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("get Secret %s/%s: %w", namespace, name, err)
	}

	updated := existing.DeepCopy()
	if updated.Data == nil {
		updated.Data = map[string][]byte{}
	}

	for key, value := range data {
		updated.Data[key] = value
	}

	if _, err := secrets.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return false, fmt.Errorf("update Secret %s/%s: %w", namespace, name, err)
	}

	return false, nil
}
