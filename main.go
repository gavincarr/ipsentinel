// Command ipsentinel reads hostname,ip pairs on stdin, runs
// `ssh -o HostName=<ip> <hostname> ip address` for each (honouring
// ~/.ssh/config for everything but the address), and confirms the ip is still
// present in that output. Per-host config can change how ssh reaches the host
// (connect: ip, the default, dials the expected ip itself so the verified host
// key proves it reaches the host; ssh_config sshes to the name) and what is checked
// (check: iproute2, aws, ifconfig, or none to pass on ssh success alone, with
// connect: ip). Any failure — ssh error, timeout, or a missing ip — is posted
// to an Alerter for attention.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kong"
	helpcolours "github.com/gavincarr/kong-help-colours"
	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	"golang.org/x/term"
)

// CLI holds the command-line configuration. The root flags are shared by
// every command; the per-command settings live on the command structs.
type CLI struct {
	Config         string `kong:"name='config',short='c',placeholder='PATH',help='Path to a YAML config file mapping hostnames to per-host settings (see README).'"`
	ConnectDefault string `kong:"name='connect-default',enum='ip,ssh_config',default='ip',help='Connect mode for hosts that do not set connect in the config file (including hosts with no entry): ip (ssh to the expected ip itself) or ssh_config (ssh to the hostname as resolved via ~/.ssh/config and DNS).'"`
	Verbose        int    `kong:"name='verbose',short='v',type='counter',help='Increase verbosity: absent prints only warnings and alerts, -v adds run progress, -vv adds per-check detail.'"`

	// check is the default command, and "withargs" lets its flags be given
	// without naming it, so `ipsentinel -i KEY -c CFG -s DOMAIN < hosts`
	// still works.
	Check          CheckCmd          `kong:"cmd,name='check',default='withargs',help='Check each hostname,ip pair on stdin via ssh, alerting on any failure (the default command).'"`
	AuthorizedKeys AuthorizedKeysCmd `kong:"cmd,name='authorized-keys',help='Run no checks, and read no stdin. Instead print a table of authorized_keys lines that lock the key down to exactly the command ipsentinel would run: one per HOST given, or one per check variant if none. Requires OpenSSH 7.2+ on the targets; see README.'"`
	KnownHosts     KnownHostsCmd     `kong:"cmd,name='known-hosts',help='Run no checks and connect to nothing. Instead, for each connect: ip hostname,ip pair on stdin, print known_hosts lines recording the host key already trusted for the host under its ip name ([ip]:port, or ip on port 22), ready to append to known_hosts. See README.'"`
}

// CheckCmd holds the settings for the check command.
type CheckCmd struct {
	Identity    string        `kong:"name='identity',short='i',placeholder='PATH',help='SSH identity (private key) to use for every check. Also sets IdentitiesOnly=yes so only this key is offered — useful under cron, where no agent is present and the default keys need a passphrase.'"`
	Strip       string        `kong:"name='strip',short='s',xor='strip',placeholder='DOMAIN',help='Strip the given domain suffix from each hostname before the ssh check (a leading dot is added if absent, so example.com strips .example.com from foo.example.com => foo).'"`
	StripAll    bool          `kong:"name='strip-all',short='S',xor='strip',help='Strip trailing labels from each hostname, keeping only the leftmost label (foo.example.com => foo).'"`
	Concurrency int           `kong:"name='concurrency',short='C',default='8',help='Number of ssh checks to run in parallel.'"`
	Timeout     time.Duration `kong:"name='timeout',short='t',default='10s',help='Per-check ssh timeout.'"`
	Retries     int           `kong:"name='retries',short='r',default='2',help='Number of retry passes for transient (soft) ssh failures.'"`
	RetryDelay  time.Duration `kong:"name='retry-delay',default='5s',help='Base backoff before the first retry pass; pass N waits delay*2^(N-1).'"`
}

// AuthorizedKeysCmd holds the settings for the authorized-keys command:
// generate forced-command lines instead of checking. It never reads stdin:
// the hosts, if any, are positional arguments.
type AuthorizedKeysCmd struct {
	Pubkey string   `kong:"arg,name='pubkey',placeholder='PUBKEY',help='OpenSSH public key file to lock down (the .pub, not the private key).'"`
	Hosts  []string `kong:"arg,optional,name='host',placeholder='HOST',help='Hosts to generate lines for, labelled exactly as given. Each is matched to a config entry by exact key, else by the keys starting with HOST followed by a dot (which must agree on the forced command). With none, print one line per check variant instead.'"`
	From   string   `kong:"name='from',env='IPSENTINEL_FROM',placeholder='PATTERNS',help='Comma-separated sshd from= patterns (IPs, CIDRs, hostname patterns, !negations) restricting where the key may be used from. An explicit --from overrides the environment variable.'"`
}

// AfterApply rejects check flags given before the authorized-keys command
// name (see rejectCheckFlags).
func (a *AuthorizedKeysCmd) AfterApply(kctx *kong.Context) error {
	return rejectCheckFlags(kctx, "authorized-keys")
}

// rejectCheckFlags rejects check flags given before the name of another
// command, cmdName. Because check is the "withargs" default, kong accepts
// its flags ahead of any command, so `ipsentinel -s x authorized-keys k.pub`
// would otherwise parse and silently ignore -s.
func rejectCheckFlags(kctx *kong.Context, cmdName string) error {
	var check *kong.Node
	for _, n := range kctx.Model.Children {
		if n.Name == "check" {
			check = n
		}
	}
	if check == nil {
		return nil
	}
	for _, p := range kctx.Path {
		if p.Flag != nil && slices.Contains(check.Flags, p.Flag) {
			return fmt.Errorf("--%s is a check flag and cannot be used with %s", p.Flag.Name, cmdName)
		}
	}
	return nil
}

// Check is a single hostname,ip pair to verify.
type Check struct {
	Hostname  string
	IP        string
	Connect   string // connect mode: a connectModes value, resolved by parseInput
	CheckName string // check: a checkCommands key, resolved by parseInput
}

// validHostname guards against argv flag smuggling: a hostname read from stdin
// must not begin with '-' (or it could be parsed as an ssh option, e.g.
// -oProxyCommand=...), and is restricted to characters valid in hostnames and
// ~/.ssh/config Host aliases.
var validHostname = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*$`)

// stripHostname returns the leftmost DNS label of host (foo.example.com => foo).
// A host with no dot is returned unchanged. Used by the -S/--strip-all flag so
// fully-qualified input names can drive ssh via short ~/.ssh/config aliases.
func stripHostname(host string) string {
	label, _, _ := strings.Cut(host, ".")
	return label
}

// stripDomain removes the domain suffix from host (foo.example.com, example.com
// => foo). A leading dot is added to domain when absent so the match is on a
// label boundary. A host that does not carry the suffix is returned unchanged.
// Used by the -s/--strip flag so fully-qualified input names can drive ssh via
// short ~/.ssh/config aliases.
func stripDomain(host, domain string) string {
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}
	return strings.TrimSuffix(host, domain)
}

// Alerter posts alerts about failed checks. The MVP ships a LogAlerter; real
// sinks (Slack, email, ...) can be added as drop-in implementations.
type Alerter interface {
	Alert(c Check, reason string, err error)
}

// LogAlerter reports alerts via slog at Error level, so they are always shown.
type LogAlerter struct {
	log *slog.Logger
}

func (a LogAlerter) Alert(c Check, reason string, err error) {
	attrs := []any{"hostname", c.Hostname, "ip", c.IP, "reason", reason}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	a.log.Error("ALERT", attrs...)
}

func main() {
	// Load .env then .env.local (secrets/local overrides). Absence is fine.
	_ = godotenv.Load(".env")
	_ = godotenv.Load(".env.local")

	var cli CLI
	kctx := kong.Parse(&cli,
		kong.Name("ipsentinel"),
		kong.Description("Verify that hosts still hold their expected IP addresses via ssh, "+
			"reading hostname,ip pairs on stdin.\n\n"+
			"With no command, runs check, whose flags (-i, -s, -S, -C, -t, -r, --retry-delay) "+
			"may then be given without naming it: see \"ipsentinel check --help\"."),
		kong.Help(helpcolours.Help),
		kong.ShortHelp(helpcolours.ShortHelp),
	)

	// Default to Warn so a clean run is silent and cron only mails on a real
	// problem: alerts are Error, malformed input is Warn. -v adds the run
	// summary (Info), -vv the per-check and per-pass detail (Debug).
	level := slog.LevelWarn
	switch {
	case cli.Verbose == 1:
		level = slog.LevelInfo
	case cli.Verbose >= 2:
		level = slog.LevelDebug
	}
	// Colourise only when stderr is a terminal, with two env overrides:
	// FORCE_COLOR forces colour on (e.g. piping to `less -R`), NO_COLOR
	// (https://no-color.org) forces it off. FORCE_COLOR wins if both are set,
	// as it's usually a deliberate per-command override. Without any of this
	// tint emits ANSI codes unconditionally, polluting cron mail and redirects.
	var noColor bool
	switch {
	case os.Getenv("FORCE_COLOR") != "":
		noColor = false
	case os.Getenv("NO_COLOR") != "":
		noColor = true
	default:
		noColor = !term.IsTerminal(int(os.Stderr.Fd()))
	}
	// Drop the timestamp: these logs go to a terminal or to cron mail, both of
	// which already carry their own timing, so the leading time just adds noise.
	stripTime := func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}
	log := slog.New(tint.NewTextHandler(os.Stderr, &tint.Options{Level: level, NoColor: noColor, ReplaceAttr: stripTime}))

	cli.Check.Concurrency = max(cli.Check.Concurrency, 1)
	cli.Check.Retries = max(cli.Check.Retries, 0)

	config := Config{ConnectDefault: cli.ConnectDefault}
	if cli.Config != "" {
		var err error
		config, err = loadConfig(cli.Config, cli.ConnectDefault)
		if err != nil {
			log.Error("loading config", "err", err)
			os.Exit(1)
		}
	}

	switch cmd := kctx.Selected().Name; cmd {
	case "check":
		os.Exit(run(cli, config, log, os.Stdin))
	case "authorized-keys":
		// Parsed only here: kong may fill From from $IPSENTINEL_FROM whatever
		// the command, and a bad value must not break check runs.
		var from []string
		if cli.AuthorizedKeys.From != "" {
			var err error
			from, err = parseFrom(cli.AuthorizedKeys.From)
			if err != nil {
				log.Error("parsing --from / IPSENTINEL_FROM", "err", err)
				os.Exit(1)
			}
		}
		pubkey, err := loadPubkey(cli.AuthorizedKeys.Pubkey)
		if err != nil {
			log.Error("loading public key", "err", err)
			os.Exit(1)
		}
		os.Exit(runAuthorizedKeys(cli.AuthorizedKeys.Hosts, config, log, os.Stdout, pubkey, from))
	case "known-hosts":
		os.Exit(runKnownHosts(os.Stdin, cli.KnownHosts.StripAll, cli.KnownHosts.Strip, config, log, os.Stdout, realKnownHostsEnv()))
	default:
		log.Error("unknown command", "command", kctx.Command())
		os.Exit(1)
	}
}

// run reads checks from r, runs them (with retries for transient failures),
// and returns the process exit code (0 = all passed, 1 = one or more failures).
func run(cli CLI, config Config, log *slog.Logger, r io.Reader) int {
	alerter := LogAlerter{log: log}

	checks, parseFailures := parseInput(r, alerter, cli.Check.StripAll, cli.Check.Strip, config)
	if parseFailures > 0 {
		log.Warn("input had malformed lines", "count", parseFailures)
	}
	// Info: with the closing summary, this is the pair -v exists to show.
	log.Info("parsed input", "checks", len(checks))

	return runChecks(context.Background(), cli.Check, checks, parseFailures, alerter, log, runCheckWith(cli.Check.Identity))
}

// parseInput reads hostname,ip pairs from r, one per line. Blank lines and
// lines beginning with '#' are ignored. Malformed lines, invalid hostnames, and
// unparseable ips are alerted and counted; it returns the valid checks plus the
// failure count. Each ip is parsed and stored in its canonical text form. When
// domain is non-empty, that suffix is stripped from each validated hostname
// (see stripDomain); when stripAll is set, the hostname is then reduced to its
// leftmost DNS label (see stripHostname). Each check's Connect and CheckName
// are resolved from config — keyed by the unstripped hostname — before any
// stripping (see Config.check for the defaults).
func parseInput(r io.Reader, alerter Alerter, stripAll bool, domain string, config Config) ([]Check, int) {
	var checks []Check
	var failures int

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, ip, ok := strings.Cut(line, ",")
		host = strings.TrimSpace(host)
		ip = strings.TrimSpace(ip)
		if !ok || host == "" || ip == "" {
			alerter.Alert(Check{}, "malformed input line", fmt.Errorf("%q", line))
			failures++
			continue
		}
		if !validHostname.MatchString(host) {
			alerter.Alert(Check{Hostname: host, IP: ip}, "invalid hostname", fmt.Errorf("%q", host))
			failures++
			continue
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			alerter.Alert(Check{Hostname: host, IP: ip}, "invalid ip", fmt.Errorf("%q", ip))
			failures++
			continue
		}
		// Store the canonical text form so matching against `ip address`
		// output is spelling-insensitive (e.g. FE80::1 => fe80::1).
		ip = addr.String()
		// Look up the host's settings before stripping: config is keyed by
		// the hostname as it appears on stdin.
		hc := config.Hosts[host] // zero value (defaults) when absent
		if domain != "" {
			host = stripDomain(host, domain)
		}
		if stripAll {
			host = stripHostname(host)
		}
		c := config.check(host, hc)
		c.IP = ip
		checks = append(checks, c)
	}
	if err := sc.Err(); err != nil {
		alerter.Alert(Check{}, "error reading stdin", err)
		failures++
	}
	return checks, failures
}

// sshArgs builds the ssh argv for c: batch-mode options, a HostName override
// for connect: ip, the target host, and the remote command for c's check (see
// remoteCommand).
func sshArgs(c Check, connectTimeoutSeconds int, identityFile string) []string {
	args := []string{
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeoutSeconds),
	}
	// connect: ip dials the expected IP itself rather than whatever the
	// alias resolves to, whatever the check. A command-line -o overrides ~/.ssh/config only for
	// the option given, so Port, User, IdentityFile etc. still come from the
	// alias's config; and the host key is still verified (under BatchMode an
	// unknown or changed key fails), which is what proves the IP still
	// reaches this host. c.IP is safe in argv: parseInput validated and
	// canonicalised it with netip, and IPv6 needs no brackets here.
	if c.Connect == connectIP {
		args = append(args, "-o", "HostName="+c.IP)
	}
	// A forced identity pins ssh to this one key. IdentitiesOnly=yes stops it
	// from first offering agent/default keys, which under BatchMode can exhaust
	// the server's auth attempts ("Too many authentication failures") before
	// this key is ever tried.
	if identityFile != "" {
		args = append(args, "-i", identityFile, "-o", "IdentitiesOnly=yes")
	}
	return append(args, "--", c.Hostname, remoteCommand(c))
}

// remoteCommand returns the shell command run on the target for c's check.
// It is the single source of truth shared by the check path (sshArgs) and the
// authorized-keys path (forcedCommand), so a host's forced command is always
// exactly what ipsentinel sends it. It depends only on the check, never the
// connect mode. Unknown or empty checks fall back to the default.
func remoteCommand(c Check) string {
	if command, ok := checkCommands[c.CheckName]; ok {
		return command
	}
	return checkCommands[defaultCheck]
}

// softErrorPatterns are the known-transient ssh failure signatures. A check
// error whose message contains any of these (case-insensitive) is retried;
// every other failure — including unrecognised ones — is treated as hard and
// alerted immediately. "connection closed by" is intentionally broader than
// the "remote host" variant so it also catches ssh's "Connection closed by
// <addr> port 22" form; both are transient handshake aborts.
var softErrorPatterns = []string{
	"ssh timed out after",         // our own context-deadline message
	"kex_exchange_identification", // early key-exchange abort by the server
	"connection closed by",
	"connection reset by peer",
	"connection timed out", // ssh's own network-level timeout
}

// retryable reports whether err is a known-transient ssh failure worth a
// retry pass. Unknown errors return false (hard) by design; see
// softErrorPatterns for the whitelist and the design doc for the rationale.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, p := range softErrorPatterns {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}

// softFail pairs a check with the retryable error from its most recent
// attempt, so a survivor of the retry loop can be alerted with its last
// real error.
type softFail struct {
	c   Check
	err error
}

// checker runs a single check. runCheck is the production implementation;
// tests substitute a fake so the retry loop can be exercised without ssh.
type checker func(ctx context.Context, timeout time.Duration, c Check) error

// runChecks runs the initial pass over checks, then up to cmd.Retries further
// passes over the checks that failed with a retryable error, sleeping
// cmd.RetryDelay*2^(N-1) before pass N (skipped when the delay is 0). Any soft
// failure still failing after the last pass is alerted (reason "check failed
// (after retries)") and counted. Returns the process exit code: 0 iff every
// check ultimately passed. parseFailures pre-seeds the failure count and is
// excluded from the success tally.
func runChecks(ctx context.Context, cmd CheckCmd, checks []Check, parseFailures int,
	alerter Alerter, log *slog.Logger, checkFn checker) int {
	var failures atomic.Int64
	failures.Add(int64(parseFailures))

	soft := runPass(ctx, cmd, checks, checkFn, alerter, log, &failures)
	for attempt := 1; attempt <= cmd.Retries && len(soft) > 0; attempt++ {
		if delay := cmd.RetryDelay * time.Duration(1<<(attempt-1)); delay > 0 {
			time.Sleep(delay)
		}
		log.Debug("retry pass", "attempt", attempt, "pending", len(soft))
		retry := make([]Check, len(soft))
		for i, sf := range soft {
			retry[i] = sf.c
		}
		soft = runPass(ctx, cmd, retry, checkFn, alerter, log, &failures)
	}
	for _, sf := range soft {
		alerter.Alert(sf.c, "check failed (after retries)", sf.err)
		failures.Add(1)
	}

	n := failures.Load()
	successes := len(checks) - (int(n) - parseFailures)
	if n > 0 {
		// Warn, not Info: this summary must survive the default log level so a
		// failing run says something even when -v is absent.
		log.Warn("finished with failures", "checks", len(checks), "successes", successes, "failures", n)
		return 1
	}
	log.Info("all checks passed", "checks", len(checks), "successes", successes)
	return 0
}

// runPass runs every check in checks concurrently (bounded by cmd.Concurrency).
// A hard (non-retryable) failure is alerted and counted in failures at once;
// a retryable failure is returned in the slice — not yet alerted or counted —
// for the caller to retry. Successful checks are logged at debug.
func runPass(ctx context.Context, cmd CheckCmd, checks []Check, checkFn checker,
	alerter Alerter, log *slog.Logger, failures *atomic.Int64) []softFail {
	var (
		mu   sync.Mutex
		soft []softFail
	)
	jobs := make(chan Check)
	var wg sync.WaitGroup
	for range cmd.Concurrency {
		wg.Go(func() {
			for c := range jobs {
				err := checkFn(ctx, cmd.Timeout, c)
				if err == nil {
					log.Debug("ok", "hostname", c.Hostname, "ip", c.IP)
					continue
				}
				if retryable(err) {
					mu.Lock()
					soft = append(soft, softFail{c, err})
					mu.Unlock()
					continue
				}
				alerter.Alert(c, "check failed", err)
				failures.Add(1)
			}
		})
	}
	for _, c := range checks {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	return soft
}

// runCheckWith adapts runCheck to the checker signature, capturing the global
// identityFile so it need not be threaded through every per-check call.
func runCheckWith(identityFile string) checker {
	return func(ctx context.Context, timeout time.Duration, c Check) error {
		return runCheck(ctx, timeout, c, identityFile)
	}
}

// runCheck runs the check's remote command via ssh (see checkCommands) and
// verifies the result (see verifyOutput). BatchMode avoids
// password prompts so an unreachable or auth-failing host fails fast rather
// than hanging. ~/.ssh/config is honoured because we invoke the real ssh
// binary. identityFile, when non-empty, forces ssh to that key (see sshArgs).
func runCheck(ctx context.Context, timeout time.Duration, c Check, identityFile string) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	seconds := max(int(timeout.Seconds()), 1)
	cmd := exec.CommandContext(ctx, "ssh", sshArgs(c, seconds, identityFile)...)

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("ssh timed out after %s", timeout)
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return fmt.Errorf("ssh failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("ssh failed: %w", err)
	}

	return verifyOutput(c, string(out))
}

// verifyOutput checks the output of c's successful ssh run. check: none
// passes on the successful connection alone: loadConfig guarantees it comes
// with connect: ip, so ssh dialled the expected IP and the verified host key
// is the proof (typically the IP is a forwarded ingress address that never
// appears on the target's interfaces). Every other check requires the
// expected ip in out, whatever the connect mode.
func verifyOutput(c Check, out string) error {
	if c.CheckName == checkNone {
		return nil
	}
	if !ipPresent(out, c.IP) {
		return fmt.Errorf("ip %s not found in `ip address` output", c.IP)
	}
	return nil
}

// ipPresent reports whether ip appears as a distinct address token in the
// `ip address` output. Matching whole tokens (split on non-address characters)
// avoids false positives like 10.0.0.1 matching 10.0.0.10.
func ipPresent(output, ip string) bool {
	isAddrChar := func(r rune) bool {
		return r >= '0' && r <= '9' ||
			r >= 'a' && r <= 'f' ||
			r >= 'A' && r <= 'F' ||
			r == '.' || r == ':'
	}
	tokens := strings.FieldsFunc(output, func(r rune) bool { return !isAddrChar(r) })
	return slices.Contains(tokens, ip)
}
