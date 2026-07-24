// Command ipsentinel reads hostname,ip pairs on stdin, runs
// `ssh <hostname> ip address` for each (honouring ~/.ssh/config), and confirms
// the ip is still present in that output. Any failure — ssh error, timeout, or
// a missing ip — is posted to an Alerter for attention.
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

// CLI holds the command-line configuration.
type CLI struct {
	Config      string        `kong:"short='c',placeholder='PATH',help='Path to a YAML config file mapping hostnames to per-host settings (see README).'"`
	Concurrency int           `kong:"short='C',default='8',help='Number of ssh checks to run in parallel.'"`
	Timeout     time.Duration `kong:"short='t',default='10s',help='Per-check ssh timeout.'"`
	Retries     int           `kong:"short='r',default='2',help='Number of retry passes for transient (soft) ssh failures.'"`
	RetryDelay  time.Duration `kong:"name='retry-delay',default='5s',help='Base backoff before the first retry pass; pass N waits delay*2^(N-1).'"`
	Strip       string        `kong:"short='s',xor='strip',placeholder='DOMAIN',help='Strip the given domain suffix from each hostname before the ssh check (a leading dot is added if absent, so example.com strips .example.com from foo.example.com => foo).'"`
	StripAll    bool          `kong:"short='S',name='strip-all',xor='strip',help='Strip trailing labels from each hostname, keeping only the leftmost label (foo.example.com => foo).'"`
	Verbose     int           `kong:"short='v',type='counter',help='Increase verbosity: absent prints only warnings and alerts, -v adds run progress, -vv adds per-check detail.'"`
}

// Check is a single hostname,ip pair to verify.
type Check struct {
	Hostname  string
	IP        string
	Type      string // check type: a checkCommands key, resolved by parseInput
	IPVersion string // "4"/"6" to force the ifconfig curl's family, else ""
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
	kong.Parse(&cli,
		kong.Name("ipsentinel"),
		kong.Description("Verify that hosts still hold their expected IP addresses via ssh."),
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

	cli.Concurrency = max(cli.Concurrency, 1)
	cli.Retries = max(cli.Retries, 0)

	var config map[string]HostConfig
	if cli.Config != "" {
		var err error
		config, err = loadConfig(cli.Config)
		if err != nil {
			log.Error("loading config", "err", err)
			os.Exit(1)
		}
	}

	os.Exit(run(cli, config, log, os.Stdin))
}

// run reads checks from r, runs them (with retries for transient failures),
// and returns the process exit code (0 = all passed, 1 = one or more failures).
func run(cli CLI, config map[string]HostConfig, log *slog.Logger, r io.Reader) int {
	alerter := LogAlerter{log: log}

	checks, parseFailures := parseInput(r, alerter, cli.StripAll, cli.Strip, config)
	if parseFailures > 0 {
		log.Warn("input had malformed lines", "count", parseFailures)
	}
	// Info: with the closing summary, this is the pair -v exists to show.
	log.Info("parsed input", "checks", len(checks))

	return runChecks(context.Background(), cli, checks, parseFailures, alerter, log, runCheck)
}

// parseInput reads hostname,ip pairs from r, one per line. Blank lines and
// lines beginning with '#' are ignored. Malformed lines, invalid hostnames, and
// unparseable ips are alerted and counted; it returns the valid checks plus the
// failure count. Each ip is parsed and stored in its canonical text form. When
// domain is non-empty, that suffix is stripped from each validated hostname
// (see stripDomain); when stripAll is set, the hostname is then reduced to its
// leftmost DNS label (see stripHostname). Each check's Type is resolved from
// config — keyed by the unstripped hostname — before any stripping, defaulting
// to defaultCheckType for absent hosts or empty types.
func parseInput(r io.Reader, alerter Alerter, stripAll bool, domain string, config map[string]HostConfig) ([]Check, int) {
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
		// Resolve the check type before stripping: config is keyed by the
		// hostname as it appears on stdin.
		ctype := defaultCheckType
		var ipVersion string
		if hc, ok := config[host]; ok {
			if hc.Type != "" {
				ctype = hc.Type
			}
			ipVersion = hc.IPVersion
		}
		if domain != "" {
			host = stripDomain(host, domain)
		}
		if stripAll {
			host = stripHostname(host)
		}
		checks = append(checks, Check{Hostname: host, IP: ip, Type: ctype, IPVersion: ipVersion})
	}
	if err := sc.Err(); err != nil {
		alerter.Alert(Check{}, "error reading stdin", err)
		failures++
	}
	return checks, failures
}

// sshArgs builds the ssh argv for c: batch-mode options, the target host,
// and the remote command for the check's type. Unknown or empty types fall
// back to the default so a zero-value Check still runs a sane command.
func sshArgs(c Check, connectTimeoutSeconds int) []string {
	command, ok := checkCommands[c.Type]
	if !ok {
		command = checkCommands[defaultCheckType]
	}
	// ip_version only shapes the ifconfig curl; loadConfig rejects it for
	// any other type, so this stays scoped to ifconfig.
	if c.Type == "ifconfig" && c.IPVersion != "" {
		command = ifconfigCommand(c.IPVersion)
	}
	return []string{
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeoutSeconds),
		"--", c.Hostname, command,
	}
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

// runChecks runs the initial pass over checks, then up to cli.Retries further
// passes over the checks that failed with a retryable error, sleeping
// cli.RetryDelay*2^(N-1) before pass N (skipped when the delay is 0). Any soft
// failure still failing after the last pass is alerted (reason "check failed
// (after retries)") and counted. Returns the process exit code: 0 iff every
// check ultimately passed. parseFailures pre-seeds the failure count and is
// excluded from the success tally.
func runChecks(ctx context.Context, cli CLI, checks []Check, parseFailures int,
	alerter Alerter, log *slog.Logger, checkFn checker) int {
	var failures atomic.Int64
	failures.Add(int64(parseFailures))

	soft := runPass(ctx, cli, checks, checkFn, alerter, log, &failures)
	for attempt := 1; attempt <= cli.Retries && len(soft) > 0; attempt++ {
		if delay := cli.RetryDelay * time.Duration(1<<(attempt-1)); delay > 0 {
			time.Sleep(delay)
		}
		log.Debug("retry pass", "attempt", attempt, "pending", len(soft))
		retry := make([]Check, len(soft))
		for i, sf := range soft {
			retry[i] = sf.c
		}
		soft = runPass(ctx, cli, retry, checkFn, alerter, log, &failures)
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

// runPass runs every check in checks concurrently (bounded by cli.Concurrency).
// A hard (non-retryable) failure is alerted and counted in failures at once;
// a retryable failure is returned in the slice — not yet alerted or counted —
// for the caller to retry. Successful checks are logged at debug.
func runPass(ctx context.Context, cli CLI, checks []Check, checkFn checker,
	alerter Alerter, log *slog.Logger, failures *atomic.Int64) []softFail {
	var (
		mu   sync.Mutex
		soft []softFail
	)
	jobs := make(chan Check)
	var wg sync.WaitGroup
	for range cli.Concurrency {
		wg.Go(func() {
			for c := range jobs {
				err := checkFn(ctx, cli.Timeout, c)
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

// runCheck runs the check's remote command via ssh (see checkCommands) and
// confirms the expected ip is present in the output. BatchMode avoids
// password prompts so an unreachable or auth-failing host fails fast rather
// than hanging. ~/.ssh/config is honoured because we invoke the real ssh
// binary.
func runCheck(ctx context.Context, timeout time.Duration, c Check) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	seconds := max(int(timeout.Seconds()), 1)
	cmd := exec.CommandContext(ctx, "ssh", sshArgs(c, seconds)...)

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

	if !ipPresent(string(out), c.IP) {
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
