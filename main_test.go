package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// captureAlerter records alerts for assertions in tests. The mutex guards
// alerts because runPass calls Alert concurrently from its worker goroutines.
type captureAlerter struct {
	mu     sync.Mutex
	alerts []struct {
		check  Check
		reason string
	}
}

func (a *captureAlerter) Alert(c Check, reason string, _ error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alerts = append(a.alerts, struct {
		check  Check
		reason string
	}{c, reason})
}

func TestParseInput(t *testing.T) {
	input := strings.Join([]string{
		"# a comment",
		"",
		"  host1 , 10.0.0.1 ", // whitespace trimmed
		"host2,10.0.0.2",
		"badline-no-comma",                      // malformed: no comma
		"host3,",                                // malformed: empty ip
		",10.0.0.4",                             // malformed: empty host
		"-oProxyCommand=touch /pwned,10.0.0.5",  // flag smuggling: leading dash
		"host;rm -rf,10.0.0.6",                  // invalid: shell metachars
		"sub.host_alias-1.example.com,10.0.0.7", // valid dotted/underscore/dash alias
	}, "\n")

	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "", nil)

	wantChecks := []Check{
		{"host1", "10.0.0.1", "iproute2", ""},
		{"host2", "10.0.0.2", "iproute2", ""},
		{"sub.host_alias-1.example.com", "10.0.0.7", "iproute2", ""},
	}
	if len(checks) != len(wantChecks) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(wantChecks), checks)
	}
	for i, want := range wantChecks {
		if checks[i] != want {
			t.Errorf("check[%d] = %+v, want %+v", i, checks[i], want)
		}
	}

	// 5 malformed/invalid lines: no-comma, empty ip, empty host, and two
	// invalid hostnames (leading dash + shell metachars).
	const wantFailures = 5
	if failures != wantFailures {
		t.Errorf("got %d failures, want %d", failures, wantFailures)
	}
	if len(alerter.alerts) != wantFailures {
		t.Errorf("got %d alerts, want %d", len(alerter.alerts), wantFailures)
	}
}

func TestParseInputRejectsFlagSmuggling(t *testing.T) {
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader("-oProxyCommand=evil,10.0.0.1\n"), &alerter, false, "", nil)

	if len(checks) != 0 {
		t.Fatalf("flag-smuggling host was accepted as a check: %+v", checks)
	}
	if failures != 1 {
		t.Errorf("got %d failures, want 1", failures)
	}
	if len(alerter.alerts) != 1 || alerter.alerts[0].reason != "invalid hostname" {
		t.Errorf("expected one 'invalid hostname' alert, got %+v", alerter.alerts)
	}
}

func TestStripHostname(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"foo.example.com", "foo"},
		{"a.b.example.com", "a"},
		{"host", "host"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := stripHostname(tt.in); got != tt.want {
			t.Errorf("stripHostname(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseInputStrip(t *testing.T) {
	input := "foo.example.com,10.0.0.1\nbar,10.0.0.2\n"

	// stripAll=true reduces each validated hostname to its leftmost label.
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, true, "", nil)
	wantStripped := []Check{{"foo", "10.0.0.1", "iproute2", ""}, {"bar", "10.0.0.2", "iproute2", ""}}
	if failures != 0 {
		t.Fatalf("got %d failures, want 0", failures)
	}
	if len(checks) != len(wantStripped) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(wantStripped), checks)
	}
	for i, want := range wantStripped {
		if checks[i] != want {
			t.Errorf("strip=true check[%d] = %+v, want %+v", i, checks[i], want)
		}
	}

	// stripAll=false leaves the hostname untouched (existing behaviour).
	var alerter2 captureAlerter
	checks, _ = parseInput(strings.NewReader(input), &alerter2, false, "", nil)
	if checks[0].Hostname != "foo.example.com" {
		t.Errorf("stripAll=false altered hostname: got %q, want %q", checks[0].Hostname, "foo.example.com")
	}
}

func TestStripDomain(t *testing.T) {
	tests := []struct {
		host, domain, want string
	}{
		{"foo.example.com", "example.com", "foo"},           // leading dot added
		{"foo.example.com", ".example.com", "foo"},          // leading dot already present
		{"a.b.example.com", "example.com", "a.b"},           // only the suffix is removed
		{"foo.example.com", "other.com", "foo.example.com"}, // suffix absent: unchanged
		{"example.com", "example.com", "example.com"},       // no leading label: unchanged
		{"foo", "example.com", "foo"},                       // bare host: unchanged
	}
	for _, tt := range tests {
		if got := stripDomain(tt.host, tt.domain); got != tt.want {
			t.Errorf("stripDomain(%q, %q) = %q, want %q", tt.host, tt.domain, got, tt.want)
		}
	}
}

func TestParseInputStripDomain(t *testing.T) {
	input := "foo.example.com,10.0.0.1\nbar.other.com,10.0.0.2\nbaz,10.0.0.3\n"

	// domain suffix is stripped only where it matches; other hosts pass through.
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "example.com", nil)
	want := []Check{{"foo", "10.0.0.1", "iproute2", ""}, {"bar.other.com", "10.0.0.2", "iproute2", ""}, {"baz", "10.0.0.3", "iproute2", ""}}
	if failures != 0 {
		t.Fatalf("got %d failures, want 0", failures)
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(want), checks)
	}
	for i, w := range want {
		if checks[i] != w {
			t.Errorf("check[%d] = %+v, want %+v", i, checks[i], w)
		}
	}
}

func TestParseInputValidatesIP(t *testing.T) {
	input := strings.Join([]string{
		"host1,10.0.0.1",           // valid ipv4, canonical
		"host2,not-an-ip",          // invalid: not an address
		"host3,10.0.0.999",         // invalid: octet out of range
		"host4,10.0.0.1/24",        // invalid: CIDR, not a bare address
		"host5,FE80::1",            // valid ipv6, canonicalized to fe80::1
		"host6,fe80:0:0:0:0:0:0:1", // valid ipv6, canonicalized (compressed)
	}, "\n")

	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "", nil)

	want := []Check{
		{"host1", "10.0.0.1", "iproute2", ""},
		{"host5", "fe80::1", "iproute2", ""},
		{"host6", "fe80::1", "iproute2", ""},
	}
	if failures != 3 {
		t.Errorf("got %d failures, want 3", failures)
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(want), checks)
	}
	for i, w := range want {
		if checks[i] != w {
			t.Errorf("check[%d] = %+v, want %+v", i, checks[i], w)
		}
	}
	for _, a := range alerter.alerts {
		if a.reason != "invalid ip" {
			t.Errorf("unexpected alert reason %q, want %q", a.reason, "invalid ip")
		}
	}
}

func TestIPPresent(t *testing.T) {
	// Representative `ip address` output.
	out := `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0
    inet6 fe80::1/64 scope link`

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"present ipv4", "10.0.0.1", true},
		{"present ipv6", "fe80::1", true},
		{"broadcast address also matches", "10.0.0.255", true},
		{"absent", "192.168.1.1", false},
		{"substring trap not a false match", "10.0.0.10", false},
		{"prefix substring not a false match", "10.0.0", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipPresent(out, tt.ip); got != tt.want {
				t.Errorf("ipPresent(out, %q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestParseInputConfigTypes(t *testing.T) {
	input := "foo.example.com,10.0.0.1\nbar.example.com,10.0.0.2\n"
	config := map[string]HostConfig{
		"foo.example.com": {Type: "aws"}, // keyed by unstripped hostname
	}

	// The config lookup uses the hostname as read from stdin, even when
	// stripping rewrites what is stored on the Check.
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, true, "", config)
	want := []Check{{"foo", "10.0.0.1", "aws", ""}, {"bar", "10.0.0.2", "iproute2", ""}}
	if failures != 0 {
		t.Fatalf("got %d failures, want 0", failures)
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(want), checks)
	}
	for i, w := range want {
		if checks[i] != w {
			t.Errorf("check[%d] = %+v, want %+v", i, checks[i], w)
		}
	}

	// A nil config defaults every check to iproute2.
	var alerter2 captureAlerter
	checks, _ = parseInput(strings.NewReader(input), &alerter2, false, "", nil)
	for i, c := range checks {
		if c.Type != "iproute2" {
			t.Errorf("nil-config check[%d].Type = %q, want %q", i, c.Type, "iproute2")
		}
	}

	// An entry with an empty Type also defaults to iproute2.
	var alerter3 captureAlerter
	checks, _ = parseInput(strings.NewReader(input), &alerter3, false, "",
		map[string]HostConfig{"foo.example.com": {}})
	if checks[0].Type != "iproute2" {
		t.Errorf("empty-type check Type = %q, want %q", checks[0].Type, "iproute2")
	}
}

func TestValidHostname(t *testing.T) {
	valid := []string{"host", "host1", "sub.example.com", "my_host-1", "10.0.0.1"}
	invalid := []string{"", "-oProxyCommand", "-h", "host;rm", "a b", "host/../x", "café"}

	for _, h := range valid {
		if !validHostname.MatchString(h) {
			t.Errorf("validHostname rejected valid hostname %q", h)
		}
	}
	for _, h := range invalid {
		if validHostname.MatchString(h) {
			t.Errorf("validHostname accepted invalid hostname %q", h)
		}
	}
}

func TestSSHArgs(t *testing.T) {
	c := Check{Hostname: "web1", IP: "10.0.0.1", Type: "iproute2"}
	want := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", "web1", "ip address"}
	if got := sshArgs(c, 10); !slices.Equal(got, want) {
		t.Errorf("sshArgs(iproute2) = %q, want %q", got, want)
	}

	// aws type: same argv shape, remote command is the IMDS snippet.
	c.Type = "aws"
	got := sshArgs(c, 10)
	if len(got) != len(want) {
		t.Fatalf("sshArgs(aws) has %d args, want %d: %q", len(got), len(want), got)
	}
	remote := got[len(got)-1]
	if !strings.Contains(remote, "ip address") || !strings.Contains(remote, "169.254.169.254") {
		t.Errorf("aws remote command missing expected content: %q", remote)
	}

	// ifconfig type with a forced IP version injects curl's -4/-6 flag.
	for _, v := range []string{"4", "6"} {
		c = Check{Hostname: "web1", IP: "10.0.0.1", Type: "ifconfig", IPVersion: v}
		remote = sshArgs(c, 10)[len(sshArgs(c, 10))-1]
		if !strings.Contains(remote, "curl -sf -"+v+" ") {
			t.Errorf("ifconfig ip_version %q remote command missing curl -%s flag: %q", v, v, remote)
		}
	}

	// ifconfig without a version leaves curl's default (no -4/-6).
	c = Check{Hostname: "web1", IP: "10.0.0.1", Type: "ifconfig"}
	remote = sshArgs(c, 10)[len(sshArgs(c, 10))-1]
	if strings.Contains(remote, "curl -sf -4") || strings.Contains(remote, "curl -sf -6") {
		t.Errorf("ifconfig without ip_version should not force a family: %q", remote)
	}

	// Unknown or empty type falls back to the default command, so a
	// zero-value Check still runs a sane check.
	c.Type = ""
	got = sshArgs(c, 10)
	if got[len(got)-1] != "ip address" {
		t.Errorf("empty type remote command = %q, want %q", got[len(got)-1], "ip address")
	}
}

func TestRetryable(t *testing.T) {
	soft := []string{
		"ssh timed out after 10s",
		"ssh failed: kex_exchange_identification: Connection closed by remote host",
		"ssh failed: kex_exchange_identification: read: Connection reset by peer",
		"ssh failed: Connection closed by 10.0.0.1 port 22", // case-insensitive match on "connection closed by"
		"ssh failed: connect to host web1 port 22: Connection timed out",
	}
	hard := []string{
		"ssh failed: Permission denied (publickey).",
		"ssh failed: Host key verification failed.",
		"ssh failed: ssh: Could not resolve hostname web1: Name or service not known",
		"ssh failed: connect to host web1 port 22: No route to host",
		"ssh failed: connect to host web1 port 22: Connection refused",
		"ip 10.0.0.1 not found in `ip address` output",
	}
	for _, s := range soft {
		if !retryable(fmt.Errorf("%s", s)) {
			t.Errorf("retryable(%q) = false, want true (soft)", s)
		}
	}
	for _, h := range hard {
		if retryable(fmt.Errorf("%s", h)) {
			t.Errorf("retryable(%q) = true, want false (hard)", h)
		}
	}
	if retryable(nil) {
		t.Error("retryable(nil) = true, want false")
	}
}

// fakeChecker returns scripted errors per hostname: the i-th call for a host
// returns scripts[host][i] (nil once the script is exhausted => success). Safe
// for concurrent use by runPass workers.
type fakeChecker struct {
	mu      sync.Mutex
	scripts map[string][]error
	calls   map[string]int
}

func newFakeChecker(scripts map[string][]error) *fakeChecker {
	return &fakeChecker{scripts: scripts, calls: map[string]int{}}
}

func (f *fakeChecker) check(_ context.Context, _ time.Duration, c Check) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls[c.Hostname]
	f.calls[c.Hostname]++
	s := f.scripts[c.Hostname]
	if i < len(s) {
		return s[i]
	}
	return nil
}

func softErr() error { return fmt.Errorf("ssh timed out after 10s") }
func hardErr() error { return fmt.Errorf("ssh failed: Permission denied (publickey).") }

// testCLI returns a CLI with sleeping disabled so retry tests run instantly.
func testCLI(retries int) CLI {
	return CLI{Concurrency: 4, Timeout: time.Second, Retries: retries, RetryDelay: 0}
}

func TestRunPass(t *testing.T) {
	checks := []Check{
		{Hostname: "ok"},
		{Hostname: "soft"},
		{Hostname: "hard"},
	}
	fc := newFakeChecker(map[string][]error{
		"soft": {softErr()},
		"hard": {hardErr()},
	})
	var alerter captureAlerter
	var failures atomic.Int64
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	soft := runPass(context.Background(), testCLI(2), checks, fc.check, &alerter, log, &failures)

	if len(soft) != 1 || soft[0].c.Hostname != "soft" {
		t.Fatalf("soft = %+v, want one entry for host \"soft\"", soft)
	}
	if got := failures.Load(); got != 1 {
		t.Errorf("failures = %d, want 1 (hard only)", got)
	}
	if len(alerter.alerts) != 1 || alerter.alerts[0].reason != "check failed" {
		t.Errorf("alerts = %+v, want one \"check failed\"", alerter.alerts)
	}
}

func TestRetryLoop(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name       string
		retries    int
		script     []error // for the single host "h"
		wantCalls  int
		wantAlerts int
		wantReason string // reason of the (single) alert, if wantAlerts == 1
		wantExit   int
	}{
		{"soft twice then recovers", 2, []error{softErr(), softErr()}, 3, 0, "", 0},
		{"hard never retried", 2, []error{hardErr()}, 1, 1, "check failed", 1},
		{"soft never recovers", 2, []error{softErr(), softErr(), softErr()}, 3, 1, "check failed (after retries)", 1},
		{"retries zero", 0, []error{softErr()}, 1, 1, "check failed (after retries)", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := newFakeChecker(map[string][]error{"h": tt.script})
			var alerter captureAlerter
			exit := runChecks(context.Background(), testCLI(tt.retries),
				[]Check{{Hostname: "h"}}, 0, &alerter, log, fc.check)

			if fc.calls["h"] != tt.wantCalls {
				t.Errorf("calls = %d, want %d", fc.calls["h"], tt.wantCalls)
			}
			if len(alerter.alerts) != tt.wantAlerts {
				t.Fatalf("alerts = %d, want %d: %+v", len(alerter.alerts), tt.wantAlerts, alerter.alerts)
			}
			if tt.wantAlerts == 1 && alerter.alerts[0].reason != tt.wantReason {
				t.Errorf("alert reason = %q, want %q", alerter.alerts[0].reason, tt.wantReason)
			}
			if exit != tt.wantExit {
				t.Errorf("exit = %d, want %d", exit, tt.wantExit)
			}
		})
	}
}
