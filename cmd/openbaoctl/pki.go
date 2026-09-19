package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v3"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/openbao/pkg/ceremony"
	"github.com/truvity/openbao/pkg/kmssigner"
)

const (
	flagHierarchy         = "hierarchy"
	flagTrustDomain       = "trust-domain"
	flagCSR               = "csr"
	flagKeyARN            = "key-arn"
	flagImportCertificate = "import-certificate"
	flagAWSProfile        = "aws-profile"
	flagRoleARN           = "role-arn"
	flagPrintTemplate     = "print-template"
	flagConfirmTemplate   = "confirm-template"
	flagNotBefore         = "not-before"
	flagOut               = "out"
	flagChainOut          = "chain-out"
)

var errChooseMode = errors.New("choose one: --print-template to review the exact template, or --confirm-template <sha256> to sign it")

type (
	// kmsFactory builds the KMS client for a key's region. Tests replace it
	// with a double; nothing else does.
	kmsFactory func(ctx context.Context, region string) (kmssigner.API, error)

	signingOptions struct {
		keyARN     string
		awsProfile string
		roleARN    string
		kms        kmsFactory
	}

	createRootOptions struct {
		hierarchy         string
		importCertificate string
		signing           signingOptions
	}

	signIntermediateOptions struct {
		hierarchy       string
		trustDomain     string
		csrPath         string
		printTemplate   bool
		confirmTemplate string
		signing         signingOptions
	}

	signEmergencyServerOptions struct {
		hierarchy       string
		csrPath         string
		notBefore       string
		printTemplate   bool
		confirmTemplate string
		outPath         string
		now             func() time.Time
		signing         signingOptions
	}

	verifyIntermediateOptions struct {
		hierarchy   string
		trustDomain string
		chainOut    string
	}
)

func pkiCommand() *cli.Command {
	hierarchyFlag := &cli.StringFlag{Name: flagHierarchy, Usage: "the PKI hierarchy file (docs/ceremony.md); artifact paths are relative to it", Required: true}
	signingFlags := []cli.Flag{
		&cli.StringFlag{Name: flagAWSProfile, Usage: "AWS shared-config profile to start from (default: the SDK's default chain)"},
		&cli.StringFlag{Name: flagRoleARN, Usage: "ceremony role to assume on top of the profile before signing"},
	}
	signing := func(cmd *cli.Command) signingOptions {
		return signingOptions{
			keyARN:     cmd.String(flagKeyARN),
			awsProfile: cmd.String(flagAWSProfile),
			roleARN:    cmd.String(flagRoleARN),
		}
	}

	return &cli.Command{
		Name:  "pki",
		Usage: "the KMS-rooted CA ceremony",
		Commands: []*cli.Command{
			{
				Name:  "create-root",
				Usage: "create (or verify, or import) the root certificate with the KMS root key",
				Description: "Builds the root template from the hierarchy file and the KMS key's public key, reserves\n" +
					"<artifact>.attempt, and asks KMS for the one self-signature. An existing artifact is\n" +
					"verified instead and nothing is signed; --import-certificate records an existing root.",
				Flags: append([]cli.Flag{
					hierarchyFlag,
					&cli.StringFlag{Name: flagKeyARN, Usage: "the root generation's KMS primary key ARN", Required: true},
					&cli.StringFlag{Name: flagImportCertificate, Usage: "verify and record this existing root certificate (PEM) instead of signing"},
				}, signingFlags...),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return runCreateRoot(ctx, os.Stdout, createRootOptions{
						hierarchy:         cmd.String(flagHierarchy),
						importCertificate: cmd.String(flagImportCertificate),
						signing:           signing(cmd),
					})
				},
			},
			{
				Name:  "sign-intermediate",
				Usage: "sign a domain intermediate's CSR (exported from OpenBAO) with the KMS root",
				Description: "Reads the CSR, checks it (P-384, self-signature, the authored subject, no SAN), builds the\n" +
					"intermediate template from the hierarchy file and the committed root artifact, and either\n" +
					"prints that template (--print-template, no credential) or signs it once with the KMS root\n" +
					"(--confirm-template <sha256 from --print-template>). The signed certificate is written next\n" +
					"to the root with a .attempt reservation that makes any rerun fail closed.",
				Flags: append([]cli.Flag{
					hierarchyFlag,
					&cli.StringFlag{Name: flagTrustDomain, Usage: "which intermediate of the hierarchy", Required: true},
					&cli.StringFlag{Name: flagCSR, Usage: "PEM certificate request exported from the OpenBAO mount", Required: true},
					&cli.BoolFlag{Name: flagPrintTemplate, Usage: "print the exact template and its sha256, sign nothing, need no credential"},
					&cli.StringFlag{Name: flagConfirmTemplate, Usage: "sha256 printed by --print-template; required to sign"},
					&cli.StringFlag{Name: flagKeyARN, Usage: "KMS key to sign with (default: the root artifact's keyArn)"},
				}, signingFlags...),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return runSignIntermediate(ctx, os.Stdout, signIntermediateOptions{
						hierarchy:       cmd.String(flagHierarchy),
						trustDomain:     cmd.String(flagTrustDomain),
						csrPath:         cmd.String(flagCSR),
						printTemplate:   cmd.Bool(flagPrintTemplate),
						confirmTemplate: cmd.String(flagConfirmTemplate),
						signing:         signing(cmd),
					})
				},
			},
			{
				Name:  "verify-intermediate",
				Usage: "prove a committed intermediate against the hierarchy and the root; print the chain to install",
				Description: "Offline and without a credential: re-derives the template, checks the committed artifact\n" +
					"against it and against the root, and prints what was proven. The chain (the intermediate,\n" +
					"then the root) is what OpenBAO's <mount>/intermediate/set-signed takes; --chain-out writes it.",
				Flags: []cli.Flag{
					hierarchyFlag,
					&cli.StringFlag{Name: flagTrustDomain, Usage: "which intermediate of the hierarchy", Required: true},
					&cli.StringFlag{Name: flagChainOut, Usage: "write the chain (PEM) here; must not exist"},
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					return runVerifyIntermediate(os.Stdout, verifyIntermediateOptions{
						hierarchy:   cmd.String(flagHierarchy),
						trustDomain: cmd.String(flagTrustDomain),
						chainOut:    cmd.String(flagChainOut),
					})
				},
			},
			{
				Name:  "sign-emergency-server",
				Usage: "BREAK-GLASS: sign a short-lived certificate for OpenBAO's endpoint directly with the KMS root",
				Description: "For the two moments OpenBAO cannot issue its own certificate: its serving certificate has\n" +
					"expired, or no OpenBAO exists yet. Reads a locally generated P-384 CSR for the hierarchy's\n" +
					"emergencyServer.dnsName, builds a leaf template (server auth, that one name, issued by the\n" +
					"root itself) and either prints it (--print-template, no credential, with the --not-before\n" +
					"to pin) or signs it once with the KMS root (--confirm-template <sha256>). The root key's\n" +
					"Sign alarm fires: tell whoever receives it first. Nothing is committed.",
				Flags: append([]cli.Flag{
					hierarchyFlag,
					&cli.StringFlag{Name: flagCSR, Usage: "PEM certificate request made locally for the emergency name", Required: true},
					&cli.StringFlag{Name: flagNotBefore, Usage: "RFC 3339 start of validity; --print-template chooses one and prints it, signing needs it"},
					&cli.BoolFlag{Name: flagPrintTemplate, Usage: "print the exact template and its sha256, sign nothing, need no credential"},
					&cli.StringFlag{Name: flagConfirmTemplate, Usage: "sha256 printed by --print-template; required to sign"},
					&cli.StringFlag{Name: flagOut, Usage: "where to write the signed leaf (PEM); must not exist", Value: "openbao-emergency.crt"},
					&cli.StringFlag{Name: flagKeyARN, Usage: "KMS key to sign with (default: the root artifact's keyArn)"},
				}, signingFlags...),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return runSignEmergencyServer(ctx, os.Stdout, signEmergencyServerOptions{
						hierarchy:       cmd.String(flagHierarchy),
						csrPath:         cmd.String(flagCSR),
						notBefore:       cmd.String(flagNotBefore),
						printTemplate:   cmd.Bool(flagPrintTemplate),
						confirmTemplate: cmd.String(flagConfirmTemplate),
						outPath:         cmd.String(flagOut),
						now:             time.Now,
						signing:         signing(cmd),
					})
				},
			},
		},
	}
}

func runCreateRoot(ctx context.Context, out io.Writer, options createRootOptions) error {
	hierarchy, err := ceremony.LoadHierarchy(options.hierarchy)
	if err != nil {
		return err
	}

	spec, err := hierarchy.RootSpec()
	if err != nil {
		return err
	}

	client, err := options.signing.client(ctx, options.signing.keyARN)
	if err != nil {
		return err
	}

	result, err := ceremony.CreateRoot(ctx, client, spec, ceremony.RootOptions{
		KeyARN:                options.signing.keyARN,
		ArtifactPath:          hierarchy.Root.Artifact,
		ImportCertificatePath: options.importCertificate,
	})
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if result.Signed {
		logger.InfoContext(ctx, "created root certificate and public ceremony state", slog.String("state", hierarchy.Root.Artifact))
	} else {
		logger.InfoContext(ctx, "verified root certificate ceremony state without signing", slog.String("state", hierarchy.Root.Artifact))
	}

	raw, err := yaml.Marshal(result.Artifact)
	if err != nil {
		return fmt.Errorf("marshal public ceremony output: %w", err)
	}

	_, err = out.Write(raw)

	return err
}

func runSignIntermediate(ctx context.Context, out io.Writer, options signIntermediateOptions) error {
	if options.printTemplate == (options.confirmTemplate != "") {
		return errChooseMode
	}

	hierarchy, err := ceremony.LoadHierarchy(options.hierarchy)
	if err != nil {
		return err
	}

	spec, err := hierarchy.Intermediate(options.trustDomain)
	if err != nil {
		return err
	}

	root, err := ceremony.LoadRootArtifact(spec.RootArtifactPath)
	if err != nil {
		return fmt.Errorf("the committed root artifact is required (run create-root first): %w", err)
	}

	csrPEM, err := os.ReadFile(options.csrPath)
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}

	plan, err := ceremony.PrepareIntermediate(spec, root, csrPEM)
	if err != nil {
		return err
	}

	if options.printTemplate {
		var text strings.Builder
		fmt.Fprintf(&text, "root artifact %s, fingerprint SHA256 %s\n\n", spec.RootArtifactPath, root.FingerprintSHA256)
		text.WriteString(plan.Text())
		fmt.Fprintf(&text, "\nnothing was signed; to sign exactly this, rerun with --%s %s\n", flagConfirmTemplate, plan.TemplateSHA256)
		_, err = io.WriteString(out, text.String())

		return err
	}

	keyARN := options.signing.keyARNOr(root.KeyARN)

	client, err := options.signing.client(ctx, keyARN)
	if err != nil {
		return err
	}

	result, err := ceremony.SignIntermediate(ctx, client, plan, ceremony.IntermediateOptions{
		KeyARN:                keyARN,
		ConfirmTemplateSHA256: options.confirmTemplate,
	})
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if result.Signed {
		logger.InfoContext(ctx, "signed intermediate certificate and wrote its public artifact",
			slog.String("trust_domain", options.trustDomain), slog.String("artifact", spec.ArtifactPath))
	} else {
		logger.InfoContext(ctx, "verified existing intermediate artifact without signing",
			slog.String("trust_domain", options.trustDomain), slog.String("artifact", spec.ArtifactPath))
	}

	raw, err := yaml.Marshal(result.Artifact)
	if err != nil {
		return fmt.Errorf("marshal public ceremony output: %w", err)
	}

	_, err = io.WriteString(out, proofText(result.Proof)+"\n"+string(raw))

	return err
}

func runVerifyIntermediate(out io.Writer, options verifyIntermediateOptions) error {
	hierarchy, err := ceremony.LoadHierarchy(options.hierarchy)
	if err != nil {
		return err
	}

	spec, err := hierarchy.Intermediate(options.trustDomain)
	if err != nil {
		return err
	}

	signed, err := ceremony.LoadSignedIntermediate(spec, "")
	if err != nil {
		return err
	}

	if options.chainOut != "" {
		if err := writeNew(options.chainOut, []byte(signed.ChainPEM)); err != nil {
			return err
		}
	}

	text := proofText(signed.Proof)
	if options.chainOut != "" {
		text += "\nchain (intermediate, then root) written: " + options.chainOut + "\n"
	} else {
		text += "\n" + signed.ChainPEM
	}

	_, err = io.WriteString(out, text)

	return err
}

func runSignEmergencyServer(ctx context.Context, out io.Writer, options signEmergencyServerOptions) error {
	if options.printTemplate == (options.confirmTemplate != "") {
		return errChooseMode
	}

	notBefore := options.now().UTC().Truncate(time.Minute)
	if options.notBefore != "" {
		parsed, err := time.Parse(time.RFC3339, options.notBefore)
		if err != nil {
			return fmt.Errorf("--%s: %w", flagNotBefore, err)
		}

		notBefore = parsed
	} else if !options.printTemplate {
		return fmt.Errorf("--%s is required to sign: pass the value --print-template printed, so the signed template is the reviewed one", flagNotBefore)
	}

	hierarchy, err := ceremony.LoadHierarchy(options.hierarchy)
	if err != nil {
		return err
	}

	spec, err := hierarchy.EmergencyServerSpec(notBefore)
	if err != nil {
		return err
	}

	root, err := ceremony.LoadRootArtifact(spec.RootArtifactPath)
	if err != nil {
		return fmt.Errorf("the committed root artifact is required: %w", err)
	}

	csrPEM, err := os.ReadFile(options.csrPath)
	if err != nil {
		return fmt.Errorf("read CSR: %w", err)
	}

	plan, err := ceremony.PrepareEmergencyServer(spec, root, csrPEM)
	if err != nil {
		return err
	}

	if options.printTemplate {
		var text strings.Builder
		fmt.Fprintf(&text, "root artifact %s, fingerprint SHA256 %s\n\n", spec.RootArtifactPath, root.FingerprintSHA256)
		text.WriteString(plan.Text())
		fmt.Fprintf(&text, "\nnothing was signed. Signing fires the root key's Sign alarm. To sign exactly this, rerun with\n"+
			"  --%s %s --%s %s\n", flagNotBefore, plan.Spec.NotBefore.Format(time.RFC3339), flagConfirmTemplate, plan.TemplateSHA256)
		_, err = io.WriteString(out, text.String())

		return err
	}

	// Refuse before signing, not after: a signature is an alarm, and one
	// whose output cannot be written is an alarm for nothing.
	if _, err := os.Stat(options.outPath); err == nil {
		return fmt.Errorf("--%s %s exists; refusing to overwrite a signed certificate", flagOut, options.outPath)
	}

	keyARN := options.signing.keyARNOr(root.KeyARN)

	client, err := options.signing.client(ctx, keyARN)
	if err != nil {
		return err
	}

	result, err := ceremony.SignEmergencyServer(ctx, client, plan, ceremony.EmergencyServerOptions{
		KeyARN:                keyARN,
		ConfirmTemplateSHA256: options.confirmTemplate,
	})
	if err != nil {
		return err
	}

	if err := writeNew(options.outPath, result.CertificatePEM); err != nil {
		return fmt.Errorf("%w (the signed leaf, PEM, is below -- save it by hand)\n%s", err, result.CertificatePEM)
	}

	slog.New(slog.NewTextHandler(os.Stderr, nil)).WarnContext(ctx, "signed a break-glass certificate with the KMS root",
		slog.String("name", spec.DNSName),
		slog.String("not_after", result.Certificate.NotAfter.UTC().Format(time.RFC3339)),
		slog.String("out", options.outPath))

	_, err = io.WriteString(out, proofText(result.Proof)+"\nwritten: "+options.outPath+"\n")

	return err
}

func (s signingOptions) keyARNOr(fallback string) string {
	if s.keyARN != "" {
		return s.keyARN
	}

	return fallback
}

func (s signingOptions) client(ctx context.Context, keyARN string) (kmssigner.API, error) {
	region, err := ceremony.KeyRegion(keyARN)
	if err != nil {
		return nil, err
	}

	if s.kms != nil {
		return s.kms(ctx, region)
	}

	return ceremony.KMSClient(ctx, ceremony.KMSClientOptions{Profile: s.awsProfile, Region: region, RoleARN: s.roleARN})
}

func proofText(proof []string) string {
	var text strings.Builder

	text.WriteString("proven:\n")

	for _, statement := range proof {
		fmt.Fprintf(&text, "  - %s\n", statement)
	}

	return text.String()
}

// writeNew writes a public certificate file that must not exist yet.
func writeNew(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // a public certificate
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	if _, err := file.Write(content); err != nil {
		_ = file.Close()

		return fmt.Errorf("write %s: %w", path, err)
	}

	return file.Close()
}
