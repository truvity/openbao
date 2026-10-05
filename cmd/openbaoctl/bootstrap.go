package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/truvity/secrets/pkg/bootstrap"
	"github.com/truvity/secrets/pkg/bootstrap/filekeeper"
)

const (
	flagAddr             = "addr"
	flagCAFile           = "ca-file"
	flagTLSServerName    = "tls-server-name"
	flagPortForward      = "port-forward"
	flagPod              = "pod"
	flagTLSSecret        = "tls-secret"
	flagAPIPort          = "api-port"
	flagKeeperDir        = "keeper-dir"
	flagAgeIdentity      = "age-identity-file"
	flagAgeRecipient     = "age-recipient"
	flagRecoveryShares   = "recovery-shares"
	flagRecoveryTh       = "recovery-threshold"
	flagVoters           = "voters"
	flagAuditDevice      = "audit-device"
	flagDescription      = "description"
	flagIssuer           = "issuer"
	flagOperatorGroup    = "operator-group"
	flagTokenTTL         = "token-ttl"
	flagAllowNonEmpty    = "allow-non-empty"
	flagRecordSplit      = "record-recovery-split"
	flagOperatorJWT      = "operator-jwt-file"
	flagMembershipOnly   = "membership-evidence-only"
	flagPrintShares      = "insecure-print-recovery-shares-to-stdout"
	flagReadyTimeout     = "ready-timeout"
	flagDrillPod         = "drill-pod"
	flagDrillCronJob     = "restore-check-cronjob"
	flagDrillContainer   = "restore-check-container"
	flagDrillLocalPort   = "local-port"
	flagDrillHold        = "hold"
	defaultTLSSecretName = "openbao-tls"
	defaultBootstrapPod  = "openbao-0"
)

// bootstrapEnv is everything the bootstrap commands reach outside the
// process through; tests replace it.
type bootstrapEnv struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	logger *slog.Logger
	now    func() time.Time
}

func defaultBootstrapEnv() bootstrapEnv {
	return bootstrapEnv{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
		logger: slog.New(slog.NewTextHandler(os.Stderr, nil)),
		now:    time.Now,
	}
}

func connectionFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  flagAddr,
			Usage: "the API's https base URL; must be the bootstrap node (the first Raft voter), not a load balancer or a follower; needs --" + flagCAFile,
		},
		&cli.StringFlag{Name: flagCAFile, Usage: "PEM file of the CA the server's certificate chains to; TLS is always verified"},
		&cli.StringFlag{Name: flagTLSServerName, Usage: "a name the server certificate holds (needed with --" + flagPortForward + ")"},
		&cli.BoolFlag{Name: flagPortForward, Usage: "reach the bootstrap pod through kubectl port-forward instead of --" + flagAddr},
		&cli.StringFlag{Name: flagKubeconfig, Usage: "kubeconfig for kubectl (default: KUBECONFIG)"},
		&cli.StringFlag{Name: flagKubeContext, Usage: "kube context for kubectl; no current-context fallback with --" + flagPortForward},
		&cli.StringFlag{Name: flagNamespace, Usage: "namespace of the install (with --" + flagPortForward + ")"},
		&cli.StringFlag{Name: flagPod, Usage: "the bootstrap pod, the first Raft voter", Value: defaultBootstrapPod},
		&cli.StringFlag{Name: flagTLSSecret, Usage: "Secret holding ca.crt of the serving certificate", Value: defaultTLSSecretName},
		&cli.IntFlag{Name: flagAPIPort, Usage: "the API port inside the pod", Value: bootstrap.DefaultAPIPort},
	}
}

func keeperFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: flagKeeperDir, Usage: "directory the recovery shares and root token are kept in, one age-encrypted file each", Required: true},
		&cli.StringFlag{Name: flagAgeIdentity, Usage: "age identity file (the private key): items are read back with it to prove them", Required: true},
		&cli.StringSliceFlag{Name: flagAgeRecipient, Usage: "age recipient (age1...) to encrypt to, repeatable; default: the identity's own public key"},
	}
}

func settingsFlags() []cli.Flag {
	return []cli.Flag{
		&cli.IntFlag{Name: flagRecoveryShares, Usage: "recovery key shares", Value: bootstrap.DefaultRecoveryShares},
		&cli.IntFlag{Name: flagRecoveryTh, Usage: "shares that reconstruct the recovery key", Value: bootstrap.DefaultRecoveryThreshold},
		&cli.IntFlag{Name: flagVoters, Usage: "Raft voters configure waits for", Value: bootstrap.DefaultVoters},
		&cli.StringFlag{
			Name:  flagAuditDevice,
			Usage: "the audit device the server config declares; configure refuses without it",
			Value: bootstrap.DefaultAuditDevice,
		},
		&cli.StringFlag{Name: flagDescription, Usage: "names the install in the keeper items' notes (free text, never a secret)"},
		&cli.DurationFlag{Name: flagReadyTimeout, Usage: "how long to wait for an unsealed, fully joined cluster", Value: bootstrap.DefaultReadyTimeout},
	}
}

func bootstrapCommands() []*cli.Command {
	return []*cli.Command{
		bootstrapInitCommand(),
		bootstrapConfigureCommand(),
		bootstrapRevokeRootCommand(),
		drillCommand(),
	}
}

func bootstrapInitCommand() *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "initialize a fresh OpenBAO once and hand its recovery shares and root token to the keeper",
		Description: "Verifies the keeper first (writes, reads back and deletes a canary), refuses a shamir seal and\n" +
			"stale items of an earlier install, then initializes and stores every share and the root token,\n" +
			"each read back. Run again on an initialized server it only verifies every share is on file.\n\n" +
			"The recovery shares and the root token are NEVER printed. --" + flagPrintShares + " prints the shares\n" +
			"to stdout, once, after they are stored: use it only to move them into a custody this tool does not\n" +
			"reach, never in a shared terminal, a CI log or a recorded session. The root token is never printed.\n" +
			"If init succeeds and storing fails, the shares are lost: the error says how to wipe the empty install.",
		Flags: append(append(append(connectionFlags(), keeperFlags()...), settingsFlags()...),
			&cli.BoolFlag{Name: flagPrintShares, Usage: "DANGEROUS: print the recovery shares to stdout after storing them"},
			&cli.BoolFlag{Name: flagRecordSplit, Usage: "on an initialized server, write the missing recovery-split item (every configured share must be on file)"}),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runInit(ctx, defaultBootstrapEnv(), cmd)
		},
	}
}

func bootstrapConfigureCommand() *cli.Command {
	return &cli.Command{
		Name:  "configure",
		Usage: "open operator login (the roster JWT door, operator policy and group) with the bootstrap root token",
		Description: "Reads the root token from the keeper, waits for an unsealed, fully joined cluster, refuses an\n" +
			"unaudited one and a non-empty one (--" + flagAllowNonEmpty + " says it is deliberate), then converges the\n" +
			"door. Run again, it repairs drift and changes nothing else.",
		Flags: append(append(append(connectionFlags(), keeperFlags()...), settingsFlags()...),
			&cli.StringFlag{Name: flagIssuer, Usage: "the roster issuer URL OpenBAO discovers keys from", Required: true},
			&cli.StringFlag{Name: flagOperatorGroup, Usage: "internal group whose members operate OpenBAO", Required: true},
			&cli.StringFlag{Name: flagTokenTTL, Usage: "an operator login token's whole life", Value: bootstrap.DefaultTokenTTL},
			&cli.BoolFlag{Name: flagAllowNonEmpty, Usage: "configure a server that already has mounts beyond the door"}),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runConfigure(ctx, defaultBootstrapEnv(), cmd)
		},
	}
}

func bootstrapRevokeRootCommand() *cli.Command {
	return &cli.Command{
		Name:  "revoke-root",
		Usage: "prove the recovery shares, then revoke the bootstrap root token",
		Description: "Refuses until an operator login through the door is proven: --" + flagOperatorJWT + " (a roster token for\n" +
			"the OpenBAO audience, a file or - for stdin) is used to log in here, and the login must return the\n" +
			"operator policy. --" + flagMembershipOnly + " settles for a member on file in the operator group instead\n" +
			"(weaker: it proves someone logged in once, not that the door works now). Then it generates a root\n" +
			"token from the shares until every share has been submitted, revoking each at once, and only then\n" +
			"revokes the bootstrap token and archives its keeper item. With no root token on file it does nothing.",
		Flags: append(append(append(connectionFlags(), keeperFlags()...), settingsFlags()...),
			&cli.StringFlag{Name: flagOperatorGroup, Usage: "internal group whose members operate OpenBAO", Required: true},
			&cli.StringFlag{Name: flagOperatorJWT, Usage: "a roster token for the OpenBAO audience, to prove the door works ('-' reads stdin)"},
			&cli.BoolFlag{Name: flagMembershipOnly, Usage: "WEAKER: accept a group member on file instead of a login proof"}),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runRevokeRoot(ctx, defaultBootstrapEnv(), cmd)
		},
	}
}

func settingsFrom(cmd *cli.Command) bootstrap.Settings {
	return bootstrap.Settings{
		RecoveryShares:    cmd.Int(flagRecoveryShares),
		RecoveryThreshold: cmd.Int(flagRecoveryTh),
		Voters:            cmd.Int(flagVoters),
		AuditDevice:       cmd.String(flagAuditDevice),
		ReadyTimeout:      cmd.Duration(flagReadyTimeout),
		Description:       cmd.String(flagDescription),
		AllowNonEmpty:     cmd.Bool(flagAllowNonEmpty),
		RecordSplit:       cmd.Bool(flagRecordSplit),
	}
}

func keeperFrom(cmd *cli.Command) (bootstrap.Keeper, error) {
	return filekeeper.New(cmd.String(flagKeeperDir), cmd.StringSlice(flagAgeRecipient), cmd.String(flagAgeIdentity))
}

// connect opens the API client the command's connection flags describe and
// returns the function that closes it.
func connect(ctx context.Context, cmd *cli.Command) (*bootstrap.Client, func(), error) {
	forward := cmd.Bool(flagPortForward)

	switch {
	case forward && cmd.String(flagAddr) != "":
		return nil, nil, fmt.Errorf("--%s and --%s are two ways to reach the server: choose one", flagPortForward, flagAddr)
	case forward:
		if cmd.String(flagTLSServerName) == "" {
			return nil, nil, fmt.Errorf("--%s is required with --%s: the forward is on 127.0.0.1, which the serving certificate does not hold",
				flagTLSServerName, flagPortForward)
		}

		if cmd.String(flagKubeContext) == "" {
			return nil, nil, fmt.Errorf("--%s is required with --%s: a bootstrap goes to the cluster named here, never the current kube context",
				flagKubeContext, flagPortForward)
		}

		return bootstrap.PortForward{
			Kubeconfig:    cmd.String(flagKubeconfig),
			Context:       cmd.String(flagKubeContext),
			Namespace:     cmd.String(flagNamespace),
			Pod:           cmd.String(flagPod),
			Port:          cmd.Int(flagAPIPort),
			TLSSecret:     cmd.String(flagTLSSecret),
			TLSServerName: cmd.String(flagTLSServerName),
		}.Connect(ctx)
	case cmd.String(flagAddr) == "":
		return nil, nil, fmt.Errorf("say how to reach the server: --%s with --%s, or --%s", flagAddr, flagCAFile, flagPortForward)
	case cmd.String(flagCAFile) == "":
		return nil, nil, fmt.Errorf("--%s needs --%s: TLS is always verified, there is no insecure mode", flagAddr, flagCAFile)
	}

	pem, err := os.ReadFile(cmd.String(flagCAFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read the CA file: %w", err)
	}

	client, err := bootstrap.NewTLSClient(cmd.String(flagAddr), pem, cmd.String(flagTLSServerName))
	if err != nil {
		return nil, nil, err
	}

	return client, func() {}, nil
}

func newBootstrap(env bootstrapEnv, cmd *cli.Command, api *bootstrap.Client, keeper bootstrap.Keeper) *bootstrap.Bootstrap {
	return &bootstrap.Bootstrap{
		API:      api,
		Keeper:   keeper,
		Logger:   env.logger,
		Poll:     5 * time.Second,
		Now:      env.now,
		Settings: settingsFrom(cmd),
	}
}

func runInit(ctx context.Context, env bootstrapEnv, cmd *cli.Command) error {
	api, closeAPI, err := connect(ctx, cmd)
	if err != nil {
		return err
	}
	defer closeAPI()

	// The keeper directory is created here and nowhere else, and only for a
	// server that is not initialized: a typo in --keeper-dir against a live
	// install must fail, not yield an empty keeper that looks like a lost one.
	dir := cmd.String(flagKeeperDir)
	if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
		initialized, err := api.Initialized(ctx)
		if err != nil {
			return err
		}

		if initialized {
			return fmt.Errorf("the server is already initialized and --%s %s does not exist: refusing to create an empty keeper "+
				"for a live install. Is --%s a typo, or the wrong machine?", flagKeeperDir, dir, flagKeeperDir)
		}

		if err := filekeeper.Prepare(dir); err != nil {
			return err
		}
	}

	keeper, err := keeperFrom(cmd)
	if err != nil {
		return err
	}

	b := newBootstrap(env, cmd, api, keeper)
	if err := b.Initialize(ctx); err != nil {
		return err
	}

	return maybePrintShares(ctx, env, cmd.Bool(flagPrintShares), b, keeper)
}

// maybePrintShares prints the shares only when asked AND only when this very
// run initialized the server: the flag is "print what you just made", never a
// way to dump the shares of an install that was initialized earlier.
func maybePrintShares(ctx context.Context, env bootstrapEnv, asked bool, b *bootstrap.Bootstrap, keeper bootstrap.Keeper) error {
	switch {
	case !asked:
		return nil
	case !b.Founded:
		_, _ = fmt.Fprintln(env.stderr, "the recovery shares were NOT printed: this run did not initialize the server, "+
			"and --"+flagPrintShares+" only prints the shares of the run that creates them")

		return nil
	default:
		return printShares(ctx, env, keeper, b.Settings)
	}
}

// printShares is the one place a recovery share leaves the keeper, and only
// because the operator asked with a flag that says so.
func printShares(ctx context.Context, env bootstrapEnv, keeper bootstrap.Keeper, settings bootstrap.Settings) error {
	titles, err := keeper.Titles(ctx)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(env.stderr, "WARNING: printing the recovery shares to stdout because --"+flagPrintShares+" was given. "+
		"Anyone who sees this output and holds enough of them can generate a root token. Clear it from your terminal and scrollback.")

	shares := settings.RecoveryShares
	if shares == 0 {
		shares = bootstrap.DefaultRecoveryShares
	}

	for n := 1; n <= shares; n++ {
		title := bootstrap.RecoveryItem(n)
		if !titles[title] {
			return fmt.Errorf("the keeper holds no %s: nothing printed for it", title)
		}

		share, err := keeper.Reveal(ctx, title)
		if err != nil {
			return fmt.Errorf("read %s: %w", title, err)
		}

		_, err = fmt.Fprintf(env.stdout, "%s %s\n", title, share)

		clear(share)

		if err != nil {
			return err
		}
	}

	return nil
}

func runConfigure(ctx context.Context, env bootstrapEnv, cmd *cli.Command) error {
	keeper, err := keeperFrom(cmd)
	if err != nil {
		return err
	}

	api, closeAPI, err := connect(ctx, cmd)
	if err != nil {
		return err
	}
	defer closeAPI()

	return newBootstrap(env, cmd, api, keeper).Configure(ctx, bootstrap.OperatorLogin{
		Issuer: cmd.String(flagIssuer),
		Group:  cmd.String(flagOperatorGroup),
		TTL:    cmd.String(flagTokenTTL),
	})
}

var errNoLoginProof = fmt.Errorf("revoke-root needs a login proof: pass --%s (a roster token for the OpenBAO audience), "+
	"or --%s to settle for a group member on file", flagOperatorJWT, flagMembershipOnly)

func runRevokeRoot(ctx context.Context, env bootstrapEnv, cmd *cli.Command) error {
	jwtPath := cmd.String(flagOperatorJWT)

	switch {
	case jwtPath == "" && !cmd.Bool(flagMembershipOnly):
		return errNoLoginProof
	case jwtPath != "" && cmd.Bool(flagMembershipOnly):
		return fmt.Errorf("--%s and --%s contradict: choose the proof or the weaker evidence", flagOperatorJWT, flagMembershipOnly)
	}

	keeper, err := keeperFrom(cmd)
	if err != nil {
		return err
	}

	api, closeAPI, err := connect(ctx, cmd)
	if err != nil {
		return err
	}
	defer closeAPI()

	b := newBootstrap(env, cmd, api, keeper)

	if jwtPath != "" {
		token, err := readToken(env.stdin, jwtPath)
		if err != nil {
			return err
		}
		defer clear(token)

		b.OperatorJWT = token
	}

	return b.RevokeRoot(ctx, cmd.String(flagOperatorGroup))
}

// readToken reads a token from a file ("-" is stdin), trimming one trailing
// newline. It never puts the content in an error.
func readToken(stdin io.Reader, path string) ([]byte, error) {
	var (
		raw []byte
		err error
	)

	if path == "-" {
		raw, err = io.ReadAll(io.LimitReader(stdin, 1<<20))
	} else {
		raw, err = os.ReadFile(path)
	}

	if err != nil {
		return nil, fmt.Errorf("read the operator token: %w", err)
	}

	for len(raw) > 0 && (raw[len(raw)-1] == '\n' || raw[len(raw)-1] == '\r' || raw[len(raw)-1] == ' ') {
		raw = raw[:len(raw)-1]
	}

	if len(raw) == 0 {
		return nil, errors.New("the operator token is empty")
	}

	return raw, nil
}

func drillCommand() *cli.Command {
	flags := func() []cli.Flag {
		return []cli.Flag{
			&cli.StringFlag{Name: flagKubeContext, Usage: "kube context; required, no current-context fallback", Required: true},
			&cli.StringFlag{Name: flagNamespace, Usage: "namespace of the install", Required: true},
			&cli.StringFlag{Name: flagDrillPod, Usage: "the scratch pod's name", Value: "openbao-drill"},
		}
	}

	return &cli.Command{
		Name:  "drill",
		Usage: "the rebuild drill: restore the newest snapshot into a scratch pod (start, forward, stop)",
		Description: "The pod is the weekly restore check's own pod spec, read from the live CronJob, with a last\n" +
			"container that restores and waits. The copy holds every secret in the snapshot: it listens on\n" +
			"loopback, should admit no ingress, and dies with the pod. No secret passes through this command.",
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "restore the newest snapshot into a scratch pod and wait until it is ready",
				Flags: append(flags(),
					&cli.StringFlag{Name: flagDrillCronJob, Usage: "the restore check CronJob to copy", Value: "openbao-restore-check"},
					&cli.StringFlag{Name: flagDrillContainer, Usage: "its checking container", Value: "check"},
					&cli.DurationFlag{Name: flagDrillHold, Usage: "the pod's longest life", Value: bootstrap.DefaultDrillHold}),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return restoreDrillFrom(cmd).Start(ctx)
				},
			},
			{
				Name:  "forward",
				Usage: "port-forward the scratch pod's loopback API to 127.0.0.1",
				Flags: append(flags(),
					&cli.IntFlag{Name: flagDrillLocalPort, Usage: "local port", Value: 18200},
					&cli.IntFlag{Name: flagAPIPort, Usage: "the API port inside the pod", Value: bootstrap.DefaultAPIPort}),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return restoreDrillFrom(cmd).Forward(ctx)
				},
			},
			{
				Name:  "stop",
				Usage: "delete the scratch pod, and the copy with it",
				Flags: flags(),
				Action: func(ctx context.Context, cmd *cli.Command) error {
					return restoreDrillFrom(cmd).Stop(ctx)
				},
			},
		},
	}
}

func restoreDrillFrom(cmd *cli.Command) bootstrap.RestoreDrill {
	return bootstrap.RestoreDrill{
		Context:    cmd.String(flagKubeContext),
		Namespace:  cmd.String(flagNamespace),
		Pod:        cmd.String(flagDrillPod),
		CronJob:    cmd.String(flagDrillCronJob),
		Container:  cmd.String(flagDrillContainer),
		LocalPort:  cmd.Int(flagDrillLocalPort),
		RemotePort: cmd.Int(flagAPIPort),
		Hold:       cmd.Duration(flagDrillHold),
	}
}
