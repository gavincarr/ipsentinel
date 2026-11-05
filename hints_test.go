package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// msgHandler records log messages (at any level) in order, so tests can
// assert the exact text without slog's quoting.
type msgHandler struct {
	mu   *sync.Mutex
	msgs *[]string
}

func newMsgLogger() (*slog.Logger, func() []string) {
	h := msgHandler{mu: &sync.Mutex{}, msgs: new([]string)}
	return slog.New(h), func() []string { return *h.msgs }
}

func (h msgHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h msgHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	*h.msgs = append(*h.msgs, r.Level.String()+" "+r.Message)
	return nil
}
func (h msgHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h msgHandler) WithGroup(string) slog.Handler      { return h }

func TestUnknownHostKey(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"batchmode ask", errors.New("ssh failed: Host key verification failed."), true},
		{"strict yes", errors.New("ssh failed: No ED25519 host key is known for [192.0.2.1]:2222 and you have requested strict checking.\nHost key verification failed."), true},
		{"lower case", errors.New("ssh failed: host key verification failed."), true},
		{"changed key", errors.New("ssh failed: @@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n@@@@@@@@\nHost key verification failed."), false},
		{"revoked key", errors.New("ssh failed: @@@@@@@@\n@       WARNING: REVOKED HOST KEY DETECTED!               @\n@@@@@@@@\nHost key verification failed."), false},
		{"dns spoofing", errors.New("ssh failed: @@@\nWARNING: POSSIBLE DNS SPOOFING DETECTED!\nHost key verification failed."), false},
		{"other error", errors.New("ssh failed: Permission denied (publickey)."), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unknownHostKey(tt.err); got != tt.want {
				t.Errorf("unknownHostKey = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"ipsentinel.yml": "ipsentinel.yml", "/etc/a b.yml": "'/etc/a b.yml'",
		"it's": `'it'\''s'`, "": "''", "a=b@c+d:e/f-g_h": "a=b@c+d:e/f-g_h",
		"a;b": "'a;b'", "$x": "'$x'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKnownHostsCommand(t *testing.T) {
	tests := []struct {
		name string
		cli  CLI
		want string
	}{
		{"bare", CLI{ConnectDefault: "ip"}, "ipsentinel known-hosts"},
		{"config and strip", CLI{Config: "c.yml", ConnectDefault: "ip", Check: CheckCmd{Strip: "example.com"}},
			"ipsentinel known-hosts -c c.yml -s example.com"},
		{"strip all", CLI{ConnectDefault: "ip", Check: CheckCmd{StripAll: true}}, "ipsentinel known-hosts -S"},
		{"ssh_config default", CLI{Config: "c.yml", ConnectDefault: "ssh_config", Check: CheckCmd{Strip: "x.org"}},
			"ipsentinel known-hosts -c c.yml --connect-default=ssh_config -s x.org"},
		{"quoted path", CLI{Config: "/my dir/c.yml", ConnectDefault: "ip"}, "ipsentinel known-hosts -c '/my dir/c.yml'"},
		{"check-only flags ignored", CLI{ConnectDefault: "ip", Check: CheckCmd{Identity: "/k", Retries: 5}}, "ipsentinel known-hosts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := knownHostsCommand(tt.cli); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// hintHosts builds unknown-key checks and an env: fix hosts are fixable, noKey
// have no known key, other are already recorded (diagnosed "other"). file
// names the known_hosts file for host i.
func hintHosts(t *testing.T, fix, noKey, other int, file func(i int, shared string) string) ([]Check, knownHostsEnv, string) {
	t.Helper()
	needKeygen(t)
	var kh strings.Builder
	var checks []Check
	idx := map[string]int{}
	add := func(prefix string, n int, content func(h, ip string) string) {
		for i := 0; i < n; i++ {
			h, ip := fmt.Sprintf("%s%d", prefix, i), fmt.Sprintf("192.0.2.%d", len(checks)+1)
			idx[h] = len(checks)
			kh.WriteString(content(h, ip))
			checks = append(checks, Check{Hostname: h, IP: ip, Connect: connectIP})
		}
	}
	add("fix", fix, func(h, _ string) string { return h + " " + keyA + "\n" })
	add("nokey", noKey, func(string, string) string { return "" })
	add("other", other, func(h, ip string) string { return h + " " + keyA + "\n" + ip + " " + keyA + "\n" })
	shared := writeKnownHosts(t, kh.String())
	env := realKnownHostsEnv()
	env.salt = testSalt
	env.sshConfig = func(ctx context.Context, hostname, ip string) (string, error) {
		return fakeSSH{files: []string{file(idx[hostname], shared)}}.config(ctx, hostname, ip)
	}
	return checks, env, shared
}

func sameFile(_ int, shared string) string { return shared }

func TestLogHostKeyHints(t *testing.T) {
	const line1 = "WARN %d of %d connect: ip hosts failed: host key not recorded under the ip yet"
	const line4 = "WARN to check by hostname instead, pass --connect-default=ssh_config"
	cli := CLI{Config: "ipsentinel.yml", ConnectDefault: "ip", Check: CheckCmd{Strip: "example.com"}}
	tests := []struct {
		name              string
		fix, noKey, other int
		total             int
		cli               CLI
		file              func(int, string) string
		want              func(shared string) []string
	}{
		{name: "none", total: 5, cli: cli, file: sameFile,
			want: func(string) []string { return nil }},
		{name: "one fixable", fix: 1, total: 10, cli: cli, file: sameFile,
			want: func(s string) []string {
				return []string{fmt.Sprintf(line1, 1, 10),
					"WARN 1 can be fixed with: ipsentinel known-hosts -c ipsentinel.yml -s example.com >> " + s}
			}},
		{name: "mixed fixable and no key", fix: 2, noKey: 1, total: 20, cli: cli, file: sameFile,
			want: func(s string) []string {
				return []string{fmt.Sprintf(line1, 3, 20),
					"WARN 2 can be fixed with: ipsentinel known-hosts -c ipsentinel.yml -s example.com >> " + s,
					`WARN 1 have no known key at all; add them by hand, see README "connect: ip"`}
			}},
		{name: "only no key", noKey: 2, total: 2, cli: cli, file: sameFile,
			want: func(string) []string {
				return []string{fmt.Sprintf(line1, 2, 2),
					`WARN 2 have no known key at all; add them by hand, see README "connect: ip"`}
			}},
		{name: "other only gets no own line", other: 1, total: 1, cli: cli, file: sameFile,
			want: func(string) []string { return []string{fmt.Sprintf(line1, 1, 1)} }},
		{name: "N=2 of 2: no line 4", fix: 2, total: 2, cli: CLI{ConnectDefault: "ip"}, file: sameFile,
			want: func(s string) []string {
				return []string{fmt.Sprintf(line1, 2, 2), "WARN 2 can be fixed with: ipsentinel known-hosts >> " + s}
			}},
		{name: "N=3 of 6: line 4", fix: 3, total: 6, cli: CLI{ConnectDefault: "ip"}, file: sameFile,
			want: func(s string) []string {
				return []string{fmt.Sprintf(line1, 3, 6), "WARN 3 can be fixed with: ipsentinel known-hosts >> " + s, line4}
			}},
		{name: "N=3 of 7: no line 4", fix: 3, total: 7, cli: CLI{ConnectDefault: "ip"}, file: sameFile,
			want: func(s string) []string {
				return []string{fmt.Sprintf(line1, 3, 7), "WARN 3 can be fixed with: ipsentinel known-hosts >> " + s}
			}},
		{name: "differing files", fix: 2, total: 2, cli: CLI{ConnectDefault: "ip"},
			file: func(i int, shared string) string {
				if i == 0 {
					return shared
				}
				return writeKnownHosts(t, "fix1 "+keyA+"\n")
			},
			want: func(string) []string {
				return []string{fmt.Sprintf(line1, 2, 2),
					"WARN 2 can be fixed with: ipsentinel known-hosts and append its output to your known_hosts"}
			}},
		{name: "ssh_config default echoed", fix: 1, total: 1, cli: CLI{ConnectDefault: "ssh_config", Check: CheckCmd{StripAll: true}}, file: sameFile,
			want: func(s string) []string {
				return []string{fmt.Sprintf(line1, 1, 1),
					"WARN 1 can be fixed with: ipsentinel known-hosts --connect-default=ssh_config -S >> " + s}
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checks, env, shared := hintHosts(t, tt.fix, tt.noKey, tt.other, tt.file)
			log, got := newMsgLogger()
			logHostKeyHints(context.Background(), tt.cli, checks, tt.total, log, env)
			if want := tt.want(shared); !reflect.DeepEqual(got(), want) {
				t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got(), "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

func TestLogHostKeyHintsQuotesConfigAndFile(t *testing.T) {
	checks, env, _ := hintHosts(t, 1, 0, 0, func(_ int, _ string) string {
		return writeKnownHosts(t, "fix0 "+keyA+"\n")
	})
	// The temp path has no spaces, so only the config path needs quoting.
	log, got := newMsgLogger()
	logHostKeyHints(context.Background(), CLI{Config: "/my dir/c.yml", ConnectDefault: "ip"}, checks, 1, log, env)
	if len(got()) != 2 || !strings.Contains(got()[1], "known-hosts -c '/my dir/c.yml' >> ") {
		t.Errorf("got %v", got())
	}
}

// TestRunWithHints checks the whole check path: unknown host keys are
// alerted with their own reason, changed keys and ssh_config hosts keep
// "check failed", and the hint comes after the failures summary.
func TestRunWithHints(t *testing.T) {
	checks, env, _ := hintHosts(t, 1, 0, 0, sameFile)
	unknownErr := errors.New("ssh failed: Host key verification failed.")
	changedErr := errors.New("ssh failed: @@@\nWARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.")
	checks = append(checks,
		Check{Hostname: "changed", IP: "192.0.2.50", Connect: connectIP},
		Check{Hostname: "viaconfig", IP: "192.0.2.51", Connect: connectSSHConfig},
		Check{Hostname: "fine", IP: "192.0.2.52", Connect: connectIP})
	errs := map[string]error{"fix0": unknownErr, "changed": changedErr, "viaconfig": unknownErr}
	checkFn := func(_ context.Context, _ time.Duration, c Check) error { return errs[c.Hostname] }

	var alerter captureAlerter
	log, got := newMsgLogger()
	code := runWith(CLI{ConnectDefault: "ip", Check: testCheckCmd(2)}, checks, 0, &alerter, log, checkFn, env)
	if code != 1 {
		t.Errorf("code = %d, want 1", code)
	}
	reasons := map[string]string{}
	for _, a := range alerter.alerts {
		reasons[a.check.Hostname] = a.reason
	}
	want := map[string]string{"fix0": "host key not recorded for ip", "changed": "check failed", "viaconfig": "check failed"}
	if !reflect.DeepEqual(reasons, want) {
		t.Errorf("reasons = %v, want %v", reasons, want)
	}
	msgs := got()
	if len(msgs) < 3 || msgs[len(msgs)-2] != "WARN 1 of 3 connect: ip hosts failed: host key not recorded under the ip yet" ||
		!strings.HasPrefix(msgs[len(msgs)-1], "WARN 1 can be fixed with: ipsentinel known-hosts") ||
		msgs[len(msgs)-3] != "WARN finished with failures" {
		t.Errorf("msgs = %q", msgs)
	}
}
