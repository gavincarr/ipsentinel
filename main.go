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
)

// CLI holds the command-line configuration.
type CLI struct {
	Concurrency int           `kong:"short='c',default='8',help='Number of ssh checks to run in parallel.'"`
	Timeout     time.Duration `kong:"short='t',default='10s',help='Per-check ssh timeout.'"`
	Strip       string        `kong:"short='s',xor='strip',placeholder='DOMAIN',help='Strip the given domain suffix from each hostname before the ssh check (a leading dot is added if absent, so example.com strips .example.com from foo.example.com => foo).'"`
	StripAll    bool          `kong:"short='S',name='strip-all',xor='strip',help='Strip trailing labels from each hostname, keeping only the leftmost label (foo.example.com => foo).'"`
	Verbose     bool          `kong:"short='v',help='Enable verbose (debug) logging.'"`
}

// Check is a single hostname,ip pair to verify.
type Check struct {
	Hostname string
	IP       string
	Type     string // check type: a checkCommands key, resolved by parseInput
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

	level := slog.LevelInfo
	if cli.Verbose {
		level = slog.LevelDebug
	}
	log := slog.New(tint.NewTextHandler(os.Stderr, &tint.Options{Level: level}))

	cli.Concurrency = max(cli.Concurrency, 1)

	os.Exit(run(cli, nil, log, os.Stdin))
}

// run reads checks from r, runs them, and returns the process exit code
// (0 = all passed, 1 = one or more failures).
func run(cli CLI, config map[string]HostConfig, log *slog.Logger, r io.Reader) int {
	alerter := LogAlerter{log: log}

	checks, parseFailures := parseInput(r, alerter, cli.StripAll, cli.Strip, config)
	if parseFailures > 0 {
		log.Warn("input had malformed lines", "count", parseFailures)
	}
	log.Debug("parsed input", "checks", len(checks))

	var failures atomic.Int64
	failures.Add(int64(parseFailures))

	jobs := make(chan Check)
	var wg sync.WaitGroup
	for range cli.Concurrency {
		wg.Go(func() {
			for c := range jobs {
				if err := runCheck(context.Background(), cli.Timeout, c); err != nil {
					alerter.Alert(c, "check failed", err)
					failures.Add(1)
					continue
				}
				log.Debug("ok", "hostname", c.Hostname, "ip", c.IP)
			}
		})
	}
	for _, c := range checks {
		jobs <- c
	}
	close(jobs)
	wg.Wait()

	n := failures.Load()
	successes := len(checks) - (int(n) - parseFailures)
	if n > 0 {
		log.Info("finished with failures", "checks", len(checks), "successes", successes, "failures", n)
		return 1
	}
	log.Info("all checks passed", "checks", len(checks), "successes", successes)
	return 0
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
		if hc, ok := config[host]; ok && hc.Type != "" {
			ctype = hc.Type
		}
		if domain != "" {
			host = stripDomain(host, domain)
		}
		if stripAll {
			host = stripHostname(host)
		}
		checks = append(checks, Check{Hostname: host, IP: ip, Type: ctype})
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
	return []string{
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeoutSeconds),
		"--", c.Hostname, command,
	}
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
