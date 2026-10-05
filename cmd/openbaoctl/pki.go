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

	"github.com/truvity/secrets/pkg/ceremony"
	"github.com/truvity/secrets/pkg/kmssigner"
	"github.com/truvity/secrets/pkg/pki"
)

const (
	flagHierarchy         = "hierarchy"
	flagContract          = "contract"
	flagArtifacts         = "artifacts"
	flagGeneration        = "generation"
	flagTrustDomain       = "trust-domain"
	flagEnvironment       = "environment"
	flagZone              = "zone"
	flagCSR               = "csr"
	flagKeyARN            = "key-arn"
	flagImportCertificate = "import-certificate"
	flagAWSProfile        = "aws-profile"
	flagRoleARN           = "role-arn"
	flagCustodyOutputs    = "custody-outputs"
	flagSkipCustodyCheck  = "skip-custody-check"
	flagPrintTemplate     = "print-template"
	flagConfirmTemplate   = "confirm-template"
	flagNotBefore         = "not-before"
	flagOut               = "out"
	flagChainOut          = "chain-out"
	flagDNSName           = "dns-name"
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
		// custodyOutputs is the synced custody outputs file, and
		// skipCustody the reason to sign without checking against it
		// (custody_check.go); a --contract source needs one of the two.
		custodyOutputs string
		skipCustody    string
	}

	// sourceOptions names either a hierarchy file or a pki.Contract file
	// (docs/pki.md); loadSource refuses anything but exactly one of the
	// two. generation is required with contract (a Contract may declare
	// several root generations; a hierarchy file names exactly one).
	// artifacts overrides the contract's own artifact directory; it has
	// no meaning with hierarchy, whose artifact paths are already
	// resolved against the hierarchy file's own directory.
	sourceOptions struct {
		hierarchy  string
		contract   string
		artifacts  string
		generation string
	}

	createRootOptions struct {
		source            sourceOptions
		importCertificate string
		signing           signingOptions
	}

	signIntermediateOptions struct {
		source          sourceOptions
		trustDomain     string
		environment     string
		zone            string
		csrPath         string
		printTemplate   bool
		confirmTemplate string
		signing         signingOptions
	}

	signEmergencyServerOptions struct {
		source          sourceOptions
		dnsName         string
		csrPath         string
		notBefore       string
		printTemplate   bool
		confirmTemplate string
		outPath         string
		now             func() time.Time
		signing         signingOptions
	}

	verifyIntermediateOptions struct {
		source      sourceOptions
		trustDomain string
		environment string
		zone        string
		chainOut    string
	}

	// pkiSource is a hierarchy file or a pki.Contract, behind the one
	// shape every pki command needs: a root spec, an intermediate spec
	// (by trust domain, and optionally by environment for a
	// root-signed CA), and an emergency-server spec. Every openbaoctl pki
	// command is written once, against this, rather than twice.
	pkiSource struct {
		hierarchy  *ceremony.Hierarchy
		contract   *pki.Contract
		generation string
	}
)

// loadSource reads exactly one of a hierarchy file or a contract file.
func loadSource(options sourceOptions) (*pkiSource, error) {
	if (options.hierarchy == "") == (options.contract == "") {
		return nil, fmt.Errorf("choose exactly one of --%s or --%s", flagHierarchy, flagContract)
	}

	if options.hierarchy != "" {
		if options.artifacts != "" {
			return nil, fmt.Errorf(
				"--%s has no meaning with --%s: a hierarchy file's artifact paths are already resolved against its own directory",
				flagArtifacts, flagHierarchy)
		}

		if options.generation != "" {
			return nil, fmt.Errorf("--%s has no meaning with --%s: a hierarchy file names exactly one root generation", flagGeneration, flagHierarchy)
		}

		hierarchy, err := ceremony.LoadHierarchy(options.hierarchy)
		if err != nil {
			return nil, err
		}

		return &pkiSource{hierarchy: hierarchy}, nil
	}

	contract, err := pki.Load(options.contract)
	if err != nil {
		return nil, err
	}

	if options.artifacts != "" {
		contract.ArtifactDir = options.artifacts
	}

	if options.generation == "" {
		return nil, fmt.Errorf("--%s is required with --%s", flagGeneration, flagContract)
	}

	return &pkiSource{contract: contract, generation: options.generation}, nil
}

func (s *pkiSource) rootSpec() (ceremony.RootSpec, error) {
	if s.hierarchy != nil {
		return s.hierarchy.RootSpec()
	}

	return s.contract.RootSpec(s.generation)
}

func (s *pkiSource) rootArtifactPath() string {
	if s.hierarchy != nil {
		return s.hierarchy.Root.Artifact
	}

	return s.contract.RootArtifactPath(s.generation)
}

// intermediateSpec resolves a domain intermediate (environment == "") or,
// with --contract only, one environment's own root-signed CA under a
// workload-identity domain (environment != "", zone its value for
// [pki.ZonePlaceholder]).
func (s *pkiSource) intermediateSpec(domain, environment, zone string) (ceremony.IntermediateSpec, error) {
	if s.hierarchy != nil {
		if environment != "" {
			return ceremony.IntermediateSpec{}, fmt.Errorf("--%s is only for --%s, not --%s", flagEnvironment, flagContract, flagHierarchy)
		}

		return s.hierarchy.Intermediate(domain)
	}

	if environment != "" {
		if zone == "" {
			return ceremony.IntermediateSpec{}, fmt.Errorf("--%s is required with --%s", flagZone, flagEnvironment)
		}

		return s.contract.EnvironmentCASpec(domain, environment, zone, s.generation)
	}

	if zone != "" {
		return ceremony.IntermediateSpec{}, fmt.Errorf("--%s is only for a root-signed environment CA (with --%s)", flagZone, flagEnvironment)
	}

	if s.contract.DNSTrustDomain(domain) != nil {
		return s.contract.DNSIntermediateSpec(domain, s.generation)
	}

	if s.contract.URITrustDomain(domain) != nil {
		return s.contract.URIIntermediateSpec(domain, s.generation)
	}

	return ceremony.IntermediateSpec{}, fmt.Errorf("--%s %q names no trust domain in %s", flagTrustDomain, domain, s.generation)
}

func (s *pkiSource) emergencyServerSpec(dnsName string, notBefore time.Time) (ceremony.EmergencyServerSpec, error) {
	if s.hierarchy != nil {
		if dnsName != "" {
			return ceremony.EmergencyServerSpec{}, fmt.Errorf(
				"--%s is only for --%s: a hierarchy file's own emergencyServer.dnsName is used with --%s",
				flagDNSName, flagContract, flagHierarchy)
		}

		return s.hierarchy.EmergencyServerSpec(notBefore)
	}

	if dnsName == "" {
		return ceremony.EmergencyServerSpec{}, fmt.Errorf("--%s is required with --%s", flagDNSName, flagContract)
	}

	return s.contract.EmergencyServerSpec(s.generation, dnsName, notBefore)
}

func pkiCommand() *cli.Command {
	sourceFlags := []cli.Flag{
		&cli.StringFlag{Name: flagHierarchy, Usage: "the PKI hierarchy file (docs/ceremony.md); mutually exclusive with --" + flagContract},
		&cli.StringFlag{Name: flagContract, Usage: "the private-PKI contract file (docs/pki.md); mutually exclusive with --" + flagHierarchy},
		&cli.StringFlag{Name: flagArtifacts, Usage: "override --" + flagContract + "'s own artifact directory"},
		&cli.StringFlag{Name: flagGeneration, Usage: "root generation ID; required with --" + flagContract},
	}
	source := func(cmd *cli.Command) sourceOptions {
		return sourceOptions{
			hierarchy:  cmd.String(flagHierarchy),
			contract:   cmd.String(flagContract),
			artifacts:  cmd.String(flagArtifacts),
			generation: cmd.String(flagGeneration),
		}
	}
	signingFlags := []cli.Flag{
		&cli.StringFlag{Name: flagAWSProfile, Usage: "AWS shared-config profile to start from (default: the SDK's default chain)"},
		&cli.StringFlag{
			Name: flagRoleARN,
			Usage: "ceremony role to assume on top of the profile before signing " +
				"(with --" + flagCustodyOutputs + ": must be the published one, and defaults to it)",
		},
		&cli.StringFlag{
			Name: flagCustodyOutputs,
			Usage: "the synced custody outputs file (docs/pki.md, \"The custody cross-check\"); the key, its region and replica, the generation, the role and " +
				"the profile are verified against it and the contract before anything is signed; required with --" + flagContract + " unless --" + flagSkipCustodyCheck,
		},
		&cli.StringFlag{
			Name: flagSkipCustodyCheck,
			Usage: "sign without the custody cross-check, for this REASON (printed with the template review and logged); " +
				"excludes --" + flagCustodyOutputs,
		},
	}
	signing := func(cmd *cli.Command) signingOptions {
		return signingOptions{
			keyARN:     cmd.String(flagKeyARN),
			awsProfile: cmd.String(flagAWSProfile),
			roleARN:    cmd.String(flagRoleARN),

			custodyOutputs: cmd.String(flagCustodyOutputs),
			skipCustody:    cmd.String(flagSkipCustodyCheck),
		}
	}

	return &cli.Command{
		Name:  "pki",
		Usage: "the KMS-rooted CA ceremony",
		Commands: []*cli.Command{
			{
				Name:  "create-root",
				Usage: "create (or verify, or import) the root certificate with the KMS root key",
				Description: "Builds the root template from --hierarchy or --contract/--generation and the KMS key's\n" +
					"public key, reserves <artifact>.attempt, and asks KMS for the one self-signature. An\n" +
					"existing artifact is verified instead and nothing is signed; --import-certificate records\n" +
					"an existing root.",
				Flags: append(append([]cli.Flag{
					&cli.StringFlag{Name: flagKeyARN, Usage: "the root generation's KMS primary key ARN", Required: true},
					&cli.StringFlag{Name: flagImportCertificate, Usage: "verify and record this existing root certificate (PEM) instead of signing"},
				}, sourceFlags...), signingFlags...),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return runCreateRoot(ctx, os.Stdout, createRootOptions{
						source:            source(cmd),
						importCertificate: cmd.String(flagImportCertificate),
						signing:           signing(cmd),
					})
				},
			},
			{
				Name:  "sign-intermediate",
				Usage: "sign a domain intermediate's CSR (exported from OpenBAO) with the KMS root",
				Description: "Reads the CSR, checks it (P-384, self-signature, the authored subject, no SAN), builds the\n" +
					"intermediate template from --hierarchy or --contract/--generation and the committed root\n" +
					"artifact, and either prints that template (--print-template, no credential) or signs it\n" +
					"once with the KMS root (--confirm-template <sha256 from --print-template>). The signed\n" +
					"certificate is written next to the root with a .attempt reservation that makes any rerun\n" +
					"fail closed.\n\n" +
					"--environment <env> (--contract only) signs that environment's OWN root-signed CA under a\n" +
					"workload-identity trust domain instead of the domain's shared intermediate -- see\n" +
					"docs/pki.md, \"per-environment identity CAs\". --zone gives that environment's own value\n" +
					"for {zone} (its SPIFFE trust domain, typically); required with --environment.",
				Flags: append(append([]cli.Flag{
					&cli.StringFlag{Name: flagTrustDomain, Usage: "which trust domain", Required: true},
					&cli.StringFlag{Name: flagEnvironment, Usage: "sign this environment's own CA instead of the shared intermediate (--" + flagContract + " only)"},
					&cli.StringFlag{Name: flagZone, Usage: "the environment's own value for {zone}; required with --" + flagEnvironment},
					&cli.StringFlag{Name: flagCSR, Usage: "PEM certificate request exported from the OpenBAO mount", Required: true},
					&cli.BoolFlag{Name: flagPrintTemplate, Usage: "print the exact template and its sha256, sign nothing, need no credential"},
					&cli.StringFlag{Name: flagConfirmTemplate, Usage: "sha256 printed by --print-template; required to sign"},
					&cli.StringFlag{Name: flagKeyARN, Usage: "KMS key to sign with (default: the root artifact's keyArn)"},
				}, sourceFlags...), signingFlags...),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return runSignIntermediate(ctx, os.Stdout, signIntermediateOptions{
						source:          source(cmd),
						trustDomain:     cmd.String(flagTrustDomain),
						environment:     cmd.String(flagEnvironment),
						zone:            cmd.String(flagZone),
						csrPath:         cmd.String(flagCSR),
						printTemplate:   cmd.Bool(flagPrintTemplate),
						confirmTemplate: cmd.String(flagConfirmTemplate),
						signing:         signing(cmd),
					})
				},
			},
			{
				Name:  "verify-intermediate",
				Usage: "prove a committed intermediate against the hierarchy or contract and the root; print the chain to install",
				Description: "Offline and without a credential: re-derives the template, checks the committed artifact\n" +
					"against it and against the root, and prints what was proven. The chain (the intermediate,\n" +
					"then the root) is what OpenBAO's <mount>/intermediate/set-signed takes; --chain-out writes\n" +
					"it. --environment/--zone select a root-signed environment CA, the same as sign-intermediate.",
				Flags: append([]cli.Flag{
					&cli.StringFlag{Name: flagTrustDomain, Usage: "which trust domain", Required: true},
					&cli.StringFlag{Name: flagEnvironment, Usage: "verify this environment's own CA instead of the shared intermediate (--" + flagContract + " only)"},
					&cli.StringFlag{Name: flagZone, Usage: "the environment's own value for {zone}; required with --" + flagEnvironment},
					&cli.StringFlag{Name: flagChainOut, Usage: "write the chain (PEM) here; must not exist"},
				}, sourceFlags...),
				Action: func(_ context.Context, cmd *cli.Command) error {
					return runVerifyIntermediate(os.Stdout, verifyIntermediateOptions{
						source:      source(cmd),
						trustDomain: cmd.String(flagTrustDomain),
						environment: cmd.String(flagEnvironment),
						zone:        cmd.String(flagZone),
						chainOut:    cmd.String(flagChainOut),
					})
				},
			},
			pkiInstallEmergencyServerCommand(),
			{
				Name:  "sign-emergency-server",
				Usage: "BREAK-GLASS: sign a short-lived certificate for OpenBAO's endpoint directly with the KMS root",
				Description: "For the two moments OpenBAO cannot issue its own certificate: its serving certificate has\n" +
					"expired, or no OpenBAO exists yet. Reads a locally generated P-384 CSR for the emergency\n" +
					"name (--hierarchy's own emergencyServer.dnsName, or --contract's --dns-name), builds a leaf\n" +
					"template (server auth, that one name, issued by the root itself) and either prints it\n" +
					"(--print-template, no credential, with the --not-before to pin) or signs it once with the\n" +
					"KMS root (--confirm-template <sha256>). The root key's Sign alarm fires: tell whoever\n" +
					"receives it first. Nothing is committed.",
				Flags: append(append([]cli.Flag{
					&cli.StringFlag{Name: flagDNSName, Usage: "the emergency name to sign for; required with --" + flagContract},
					&cli.StringFlag{Name: flagCSR, Usage: "PEM certificate request made locally for the emergency name", Required: true},
					&cli.StringFlag{Name: flagNotBefore, Usage: "RFC 3339 start of validity; --print-template chooses one and prints it, signing needs it"},
					&cli.BoolFlag{Name: flagPrintTemplate, Usage: "print the exact template and its sha256, sign nothing, need no credential"},
					&cli.StringFlag{Name: flagConfirmTemplate, Usage: "sha256 printed by --print-template; required to sign"},
					&cli.StringFlag{Name: flagOut, Usage: "where to write the signed leaf (PEM); must not exist", Value: "openbao-emergency.crt"},
					&cli.StringFlag{Name: flagKeyARN, Usage: "KMS key to sign with (default: the root artifact's keyArn)"},
				}, sourceFlags...), signingFlags...),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return runSignEmergencyServer(ctx, os.Stdout, signEmergencyServerOptions{
						source:          source(cmd),
						dnsName:         cmd.String(flagDNSName),
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
	pkiSource, err := loadSource(options.source)
	if err != nil {
		return err
	}

	spec, err := pkiSource.rootSpec()
	if err != nil {
		return err
	}

	signing, check, err := options.signing.withCustody(pkiSource, "")
	if err != nil {
		return err
	}

	// The result on stdout is the artifact's YAML alone, so the check
	// reports on stderr.
	fmt.Fprint(os.Stderr, check.text)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	check.log(ctx, logger)

	client, err := signing.client(ctx, signing.keyARN)
	if err != nil {
		return err
	}

	artifactPath := pkiSource.rootArtifactPath()

	result, err := ceremony.CreateRoot(ctx, client, spec, ceremony.RootOptions{
		KeyARN:                signing.keyARN,
		ArtifactPath:          artifactPath,
		ImportCertificatePath: options.importCertificate,
	})
	if err != nil {
		return err
	}

	if result.Signed {
		logger.InfoContext(ctx, "created root certificate and public ceremony state", slog.String("state", artifactPath))
	} else {
		logger.InfoContext(ctx, "verified root certificate ceremony state without signing", slog.String("state", artifactPath))
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

	pkiSource, err := loadSource(options.source)
	if err != nil {
		return err
	}

	spec, err := pkiSource.intermediateSpec(options.trustDomain, options.environment, options.zone)
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

	// The custody check is offline, so the review shows it: what an
	// operator confirms with the template hash is the template and this.
	signing, check, err := options.signing.withCustody(pkiSource, root.KeyARN)
	if err != nil {
		return err
	}

	if options.printTemplate {
		var text strings.Builder
		fmt.Fprintf(&text, "root artifact %s, fingerprint SHA256 %s\n\n", spec.RootArtifactPath, root.FingerprintSHA256)
		text.WriteString(plan.Text())
		text.WriteString("\n" + check.text)
		fmt.Fprintf(&text, "\nnothing was signed; to sign exactly this, rerun with --%s %s%s\n", flagConfirmTemplate, plan.TemplateSHA256, check.rerun)
		_, err = io.WriteString(out, text.String())

		return err
	}

	keyARN := signing.keyARNOr(root.KeyARN)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	check.log(ctx, logger)

	client, err := signing.client(ctx, keyARN)
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

	if result.Signed {
		logger.InfoContext(ctx, "signed intermediate certificate and wrote its public artifact",
			slog.String("trust_domain", spec.TrustDomain), slog.String("artifact", spec.ArtifactPath))
	} else {
		logger.InfoContext(ctx, "verified existing intermediate artifact without signing",
			slog.String("trust_domain", spec.TrustDomain), slog.String("artifact", spec.ArtifactPath))
	}

	raw, err := yaml.Marshal(result.Artifact)
	if err != nil {
		return fmt.Errorf("marshal public ceremony output: %w", err)
	}

	_, err = io.WriteString(out, check.text+"\n"+proofText(result.Proof)+"\n"+string(raw))

	return err
}

func runVerifyIntermediate(out io.Writer, options verifyIntermediateOptions) error {
	pkiSource, err := loadSource(options.source)
	if err != nil {
		return err
	}

	spec, err := pkiSource.intermediateSpec(options.trustDomain, options.environment, options.zone)
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

	pkiSource, err := loadSource(options.source)
	if err != nil {
		return err
	}

	spec, err := pkiSource.emergencyServerSpec(options.dnsName, notBefore)
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

	signing, check, err := options.signing.withCustody(pkiSource, root.KeyARN)
	if err != nil {
		return err
	}

	if options.printTemplate {
		var text strings.Builder
		fmt.Fprintf(&text, "root artifact %s, fingerprint SHA256 %s\n\n", spec.RootArtifactPath, root.FingerprintSHA256)
		text.WriteString(plan.Text())
		text.WriteString("\n" + check.text)
		fmt.Fprintf(&text, "\nnothing was signed. Signing fires the root key's Sign alarm. To sign exactly this, rerun with\n"+
			"  --%s %s --%s %s%s\n", flagNotBefore, plan.Spec.NotBefore.Format(time.RFC3339), flagConfirmTemplate, plan.TemplateSHA256, check.rerun)
		_, err = io.WriteString(out, text.String())

		return err
	}

	// Refuse before signing, not after: a signature is an alarm, and one
	// whose output cannot be written is an alarm for nothing.
	if _, err := os.Stat(options.outPath); err == nil {
		return fmt.Errorf("--%s %s exists; refusing to overwrite a signed certificate", flagOut, options.outPath)
	}

	keyARN := signing.keyARNOr(root.KeyARN)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	check.log(ctx, logger)

	client, err := signing.client(ctx, keyARN)
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

	logger.WarnContext(ctx, "signed a break-glass certificate with the KMS root",
		slog.String("name", spec.DNSName),
		slog.String("not_after", result.Certificate.NotAfter.UTC().Format(time.RFC3339)),
		slog.String("out", options.outPath))

	_, err = io.WriteString(out, check.text+"\n"+proofText(result.Proof)+"\nwritten: "+options.outPath+"\n")

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
