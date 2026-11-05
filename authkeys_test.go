package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

// testPubkey is a real ed25519 public key line (generated for these tests
// only); testPubkeyNoComment is the same key without its comment.
const (
	testPubkeyNoComment = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM32UXayEbaPubIOyeSsq1G5p2uks4EOgKLfnJaAco3l"
	testPubkey          = testPubkeyNoComment + " ipsentinel@mon"
)

func TestForcedCommand(t *testing.T) {
	tests := []struct {
		name string
		c    Check
		want string
	}{
		{"iproute2", Check{Type: "iproute2"}, "ip address"},
		{"connect", Check{Type: "connect"}, "ip address"},
		{"empty type defaults", Check{}, "ip address"},
		{"ifconfig", Check{Type: "ifconfig"},
			"ip address; curl -sf -m 2 https://ifconfig.me || true; echo"},
		{"ifconfig ip_version 4", Check{Type: "ifconfig", IPVersion: "4"},
			"ip address; curl -sf -4 -m 2 https://ifconfig.me || true; echo"},
		{"ifconfig ip_version 6", Check{Type: "ifconfig", IPVersion: "6"},
			"ip address; curl -sf -6 -m 2 https://ifconfig.me || true; echo"},
		{"aws", Check{Type: "aws"},
			`ip address; ` +
				`TOKEN=$(curl -sf -m 2 -X PUT -H \"X-aws-ec2-metadata-token-ttl-seconds: 60\" http://169.254.169.254/latest/api/token 2>/dev/null) || true; ` +
				`curl -sf -m 2 ${TOKEN:+-H \"X-aws-ec2-metadata-token: $TOKEN\"} http://169.254.169.254/latest/meta-data/public-ipv4 || true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := forcedCommand(tt.c)
			if err != nil {
				t.Fatalf("forcedCommand: %v", err)
			}
			if got != tt.want {
				t.Errorf("forcedCommand(%+v)\n got %q\nwant %q", tt.c, got, tt.want)
			}
		})
	}
}

// TestForcedCommandAWSQuoting pins the aws command's escaping: every double
// quote escaped for sshd, and the shell expansions left for the remote shell.
func TestForcedCommandAWSQuoting(t *testing.T) {
	got, err := forcedCommand(Check{Type: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(awsCommand, `"`); n == 0 || strings.Count(got, `\"`) != n {
		t.Errorf("want all %d double quotes escaped, got %q", n, got)
	}
	if strings.Contains(strings.ReplaceAll(got, `\"`, ""), `"`) {
		t.Errorf("unescaped double quote in %q", got)
	}
	for _, needle := range []string{"$(curl ", "${TOKEN:+-H ", "$TOKEN"} {
		if !strings.Contains(got, needle) {
			t.Errorf("forced aws command missing %q: %q", needle, got)
		}
	}
}

// TestForcedCommandShippedCommandsQuotable guards the invariant forcedCommand
// relies on: no shipped command flattens to something with a backslash
// (which it refuses) or a newline (which would break the authorized_keys
// line).
func TestForcedCommandShippedCommandsQuotable(t *testing.T) {
	checks := []Check{
		{Type: "iproute2"},
		{Type: "connect"},
		{Type: "aws"},
		{Type: "ifconfig"},
		{Type: "ifconfig", IPVersion: "4"},
		{Type: "ifconfig", IPVersion: "6"},
	}
	for _, c := range checks {
		flat := strings.Join(strings.Split(remoteCommand(c), "\n"), "; ")
		if strings.ContainsAny(flat, "\\\n\r") {
			t.Errorf("%s: flattened command contains a backslash or newline: %q", describeType(c), flat)
		}
		if _, err := forcedCommand(c); err != nil {
			t.Errorf("%s: forcedCommand: %v", describeType(c), err)
		}
	}
}

func TestForcedCommandRejectsBackslash(t *testing.T) {
	saved := checkCommands["iproute2"]
	t.Cleanup(func() { checkCommands["iproute2"] = saved })
	checkCommands["iproute2"] = `printf 'a\n'`

	if got, err := forcedCommand(Check{Type: "iproute2"}); err == nil {
		t.Errorf("forcedCommand with backslash = %q, want error", got)
	}
}

func TestAuthorizedKeysLine(t *testing.T) {
	tests := []struct {
		name   string
		forced string
		from   []string
		want   string
	}{
		{"no from", "ip address", nil,
			`restrict,command="ip address" ` + testPubkey},
		{"one from", "ip address", []string{"192.0.2.10"},
			`from="192.0.2.10",restrict,command="ip address" ` + testPubkey},
		{"several from", `echo \"x\"`, []string{"192.0.2.0/24", "!192.0.2.1", "*.example.com"},
			`from="192.0.2.0/24,!192.0.2.1,*.example.com",restrict,command="echo \"x\"" ` + testPubkey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authorizedKeysLine(tt.forced, tt.from, testPubkey); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestParseFrom(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{"single", "192.0.2.10", []string{"192.0.2.10"}, false},
		{"list trimmed", " 192.0.2.10, 2001:db8::/32 ,!10.0.0.1,*.example.com",
			[]string{"192.0.2.10", "2001:db8::/32", "!10.0.0.1", "*.example.com"}, false},
		{"empty item", "192.0.2.10,,10.0.0.1", nil, true},
		{"trailing comma", "192.0.2.10,", nil, true},
		{"blank item", "192.0.2.10, ", nil, true},
		{"double quote", `192.0.2.10",command="sh`, nil, true},
		{"inner space", "192.0.2.10,10.0.0.1 10.0.0.2", nil, true},
		{"inner tab", "10.0.0.1\t10.0.0.2", nil, true},
		{"backslash", `10.0.0.\1`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFrom(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseFrom(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFrom(%q): %v", tt.in, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("parseFrom(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParsePubkey(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		errWant string // substring; "" means success
	}{
		{"ed25519 with comment", testPubkey + "\n", testPubkey, ""},
		{"ed25519 no comment", testPubkeyNoComment, testPubkeyNoComment, ""},
		{"surrounding whitespace", "\n  " + testPubkey + "  \n\n", testPubkey, ""},
		{"multi-word comment kept", testPubkey + " on host", testPubkey + " on host", ""},
		{"sk type", "sk-ssh-ed25519@openssh.com AAAA x", "sk-ssh-ed25519@openssh.com AAAA x", ""},
		{"ecdsa type", "ecdsa-sha2-nistp256 AAAA", "ecdsa-sha2-nistp256 AAAA", ""},
		{"empty", "", "", "empty"},
		{"whitespace only", " \n\t\n", "", "empty"},
		{"private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n", "", "private key"},
		{"multi-line", testPubkey + "\n" + testPubkey + "\n", "", "exactly one line"},
		{"type only", "ssh-ed25519", "", "at least"},
		{"bad type", "foo-ed25519 AAAA", "", "unrecognised key type"},
		{"authorized_keys options", `restrict ` + testPubkey, "", "unrecognised key type"},
		{"bad base64", "ssh-ed25519 not*base64!", "", "base64"},
		{"truncated base64", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM3", "", "base64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePubkey(tt.in)
			if tt.errWant != "" {
				if err == nil {
					t.Fatalf("parsePubkey = %q, want error containing %q", got, tt.errWant)
				}
				if !strings.Contains(err.Error(), tt.errWant) {
					t.Errorf("error %q does not contain %q", err, tt.errWant)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePubkey: %v", err)
			}
			if got != tt.want {
				t.Errorf("parsePubkey = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadPubkey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(path, []byte(testPubkey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadPubkey(path)
	if err != nil || got != testPubkey {
		t.Errorf("loadPubkey = %q, %v; want %q, nil", got, err, testPubkey)
	}
	if _, err := loadPubkey(filepath.Join(t.TempDir(), "missing.pub")); err == nil {
		t.Error("loadPubkey(missing) = nil error, want error")
	}
}

// akLog returns a logger writing to buf at the default (Warn) level, so
// tests see exactly what a user without -v would.
func akLog(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func TestResolveHost(t *testing.T) {
	config := map[string]HostConfig{
		"app":                {Type: "aws"},
		"app.example.com":    {Type: "iproute2"},
		"web1.example.com":   {Type: "aws"},
		"facts.example.com":  {Type: "ifconfig", IPVersion: "4"},
		"db.example.com":     {Type: "aws"},
		"db.example.net":     {Type: "aws"},
		"mx.example.com":     {Type: "aws"},
		"mx.example.net":     {Type: "iproute2"},
		"ifc.example.com":    {Type: "ifconfig"},
		"ifc.example.net":    {Type: "ifconfig", IPVersion: "6"},
		"dflt.example.com":   {},
		"dflt.example.net":   {Type: "iproute2"}, // same as the default
		"gitlab.example.com": {Type: "connect"},
		"git.example.com":    {Type: "connect"},
		"git.example.net":    {Type: "iproute2"}, // same command as connect
		"gw.example.com":     {Type: "connect"},
		"gw.example.net":     {Type: "aws"},
	}
	tests := []struct {
		host    string
		want    Check
		errWant []string // substrings; nil means success
	}{
		{"web1.example.com", Check{Hostname: "web1.example.com", Type: "aws"}, nil},
		{"app", Check{Hostname: "app", Type: "aws"}, nil}, // exact match beats prefix
		{"web1", Check{Hostname: "web1", Type: "aws"}, nil},
		{"web1.example", Check{Hostname: "web1.example", Type: "aws"}, nil},
		{"facts", Check{Hostname: "facts", Type: "ifconfig", IPVersion: "4"}, nil},
		{"web", Check{Hostname: "web", Type: "iproute2"}, nil}, // prefix must end on a label
		{"nothere", Check{Hostname: "nothere", Type: "iproute2"}, nil},
		{"db", Check{Hostname: "db", Type: "aws"}, nil},
		{"dflt", Check{Hostname: "dflt", Type: "iproute2"}, nil},
		{"gitlab", Check{Hostname: "gitlab", Type: "connect"}, nil},
		{"gitlab.example.com", Check{Hostname: "gitlab.example.com", Type: "connect"}, nil},
		{"git", Check{Hostname: "git", Type: "connect"}, nil}, // connect and iproute2 share a command
		{"gw", Check{}, []string{"gw.example.com (connect)", "gw.example.net (aws)"}},
		{"mx", Check{}, []string{"mx.example.com (aws)", "mx.example.net (iproute2)"}},
		{"ifc", Check{}, []string{"ifc.example.com (ifconfig)", "ifc.example.net (ifconfig (ip_version 6))"}},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got, err := resolveHost(tt.host, config)
			if tt.errWant != nil {
				if err == nil {
					t.Fatalf("resolveHost(%q) = %+v, want error", tt.host, got)
				}
				for _, s := range tt.errWant {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q missing %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveHost(%q): %v", tt.host, err)
			}
			if got != tt.want {
				t.Errorf("resolveHost(%q) = %+v, want %+v", tt.host, got, tt.want)
			}
		})
	}
}

func TestRunAuthorizedKeysHosts(t *testing.T) {
	const ifconfig4 = "ip address; curl -sf -4 -m 2 https://ifconfig.me || true; echo"
	aws, err := forcedCommand(Check{Type: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	line := func(forced string) string {
		return `from="192.0.2.10",restrict,command="` + forced + `" ` + testPubkey
	}
	config := map[string]HostConfig{
		"web1.example.com":   {Type: "aws"},
		"facts.example.com":  {Type: "ifconfig", IPVersion: "4"},
		"db.example.com":     {Type: "aws"},
		"db.example.net":     {Type: "aws"},
		"mx.example.com":     {Type: "aws"},
		"mx.example.net":     {Type: "iproute2"},
		"gitlab.example.com": {Type: "connect"},
	}

	tests := []struct {
		name       string
		hosts      []string
		wantStdout string
		wantStderr []string // substrings expected on stderr
		wantExit   int
	}{
		{
			name:  "exact, prefix, absent; labels as given; dedupe in first-seen order",
			hosts: []string{"web1.example.com", "facts", "other", "facts", "facts.example.com", "web1.example.com"},
			wantStdout: "web1.example.com   " + line(aws) + "\n" +
				"facts              " + line(ifconfig4) + "\n" +
				"other              " + line("ip address") + "\n" +
				"facts.example.com  " + line(ifconfig4) + "\n",
			wantExit: 0,
		},
		{
			name:       "connect host gets the ip address forced command",
			hosts:      []string{"gitlab", "web1"},
			wantStdout: "gitlab  " + line("ip address") + "\n" + "web1    " + line(aws) + "\n",
			wantExit:   0,
		},
		{
			name:       "ambiguous with one check type is fine",
			hosts:      []string{"db"},
			wantStdout: "db  " + line(aws) + "\n",
			wantExit:   0,
		},
		{
			name:       "ambiguous with different types is skipped",
			hosts:      []string{"mx", "other"},
			wantStdout: "other  " + line("ip address") + "\n",
			wantStderr: []string{"level=ERROR", "host=mx", "mx.example.com (aws)", "mx.example.net (iproute2)", "skipped=1"},
			wantExit:   1,
		},
		{
			name:       "invalid hostname is skipped",
			hosts:      []string{"-oProxyCommand=evil", "other"},
			wantStdout: "other  " + line("ip address") + "\n",
			wantStderr: []string{"level=ERROR", "invalid hostname", `host="-oProxyCommand=evil"`, "skipped=1"},
			wantExit:   1,
		},
		{
			name:       "all skipped",
			hosts:      []string{"bad host"},
			wantStdout: "",
			wantStderr: []string{"invalid hostname"},
			wantExit:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exit := runAuthorizedKeys(tt.hosts, config, akLog(&stderr), &stdout,
				testPubkey, []string{"192.0.2.10"})

			if exit != tt.wantExit {
				t.Errorf("exit = %d, want %d", exit, tt.wantExit)
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout:\n got %q\nwant %q", stdout.String(), tt.wantStdout)
			}
			for _, s := range tt.wantStderr {
				if !strings.Contains(stderr.String(), s) {
					t.Errorf("stderr missing %q:\n%s", s, stderr.String())
				}
			}
			if tt.wantExit == 0 && stderr.Len() > 0 {
				t.Errorf("unexpected stderr on success:\n%s", stderr.String())
			}
			// Logs must never leak onto the data channel.
			if strings.Contains(stdout.String(), "level=") {
				t.Errorf("log output on stdout: %q", stdout.String())
			}
		})
	}
}

func TestRunAuthorizedKeysVariants(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// Config must be ignored in variant mode.
	config := map[string]HostConfig{"iproute2": {Type: "aws"}}
	exit := runAuthorizedKeys(nil, config, akLog(&stderr), &stdout, testPubkey, []string{"192.0.2.10"})
	if exit != 0 {
		t.Errorf("exit = %d, want 0; stderr:\n%s", exit, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("unexpected stderr:\n%s", stderr.String())
	}

	wantLabels := []string{"iproute2", "connect", "aws", "ifconfig", "ifconfig-v4", "ifconfig-v6"}
	wantChecks := []Check{
		{Type: "iproute2"}, {Type: "connect"}, {Type: "aws"}, {Type: "ifconfig"},
		{Type: "ifconfig", IPVersion: "4"}, {Type: "ifconfig", IPVersion: "6"},
	}
	rows := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(rows) != len(wantLabels) {
		t.Fatalf("got %d rows, want %d:\n%s", len(rows), len(wantLabels), stdout.String())
	}
	for i, row := range rows {
		label, rest, _ := strings.Cut(row, " ")
		if label != wantLabels[i] {
			t.Errorf("row %d label = %q, want %q", i, label, wantLabels[i])
		}
		forced, err := forcedCommand(wantChecks[i])
		if err != nil {
			t.Fatal(err)
		}
		if want := authorizedKeysLine(forced, []string{"192.0.2.10"}, testPubkey); strings.TrimLeft(rest, " ") != want {
			t.Errorf("row %d line:\n got %q\nwant %q", i, strings.TrimLeft(rest, " "), want)
		}
	}
}

// TestCheckVariantsCoverCheckCommands guards against a new check type being
// silently left out of variant mode, and against two variants sharing a
// label. Forced commands may repeat: connect deliberately shares iproute2's.
func TestCheckVariantsCoverCheckCommands(t *testing.T) {
	vs := checkVariants()
	labels := make(map[string]bool)
	for _, v := range vs {
		labels[v.label] = true
		if _, err := forcedCommand(v.check); err != nil {
			t.Fatalf("%s: %v", v.label, err)
		}
	}
	for typ := range checkCommands {
		if !labels[typ] {
			t.Errorf("check type %q missing from checkVariants", typ)
		}
	}
	for _, v := range ipVersions {
		if !labels["ifconfig-v"+v] {
			t.Errorf("ifconfig-v%s missing from checkVariants", v)
		}
	}
	if len(vs) != len(labels) {
		t.Errorf("duplicate variant labels: %+v", vs)
	}
}

// TestWriteTableReadParseable pins the table format and the property the
// deploy recipe relies on: `while read -r host line` (default IFS) gives the
// label in host and the byte-identical authorized_keys line in line. In Go
// terms: the first whitespace-delimited field is the label, and the rest
// with leading spaces trimmed is exactly the line.
func TestWriteTableReadParseable(t *testing.T) {
	rows := []akRow{
		{"a", `restrict,command="ip address" ` + testPubkey},
		{"web1.example.com", `from="192.0.2.10",restrict,command="echo \"x  y\"" ` + testPubkey},
		{"facts", `restrict,command="ip address" ssh-ed25519 AAAA comment  with   spaces`},
	}
	var buf bytes.Buffer
	if err := writeTable(&buf, rows); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\t") {
		t.Errorf("table contains a tab:\n%s", out)
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(rows), out)
	}
	col := len("web1.example.com") + 2
	for i, l := range lines {
		r := rows[i]
		if l != strings.TrimRight(l, " \t") {
			t.Errorf("line %d has trailing whitespace: %q", i, l)
		}
		if got := strings.Index(l, r.line); got != col {
			t.Errorf("line %d: authorized_keys line starts at column %d, want %d: %q", i, got, col, l)
		}
		label := strings.Fields(l)[0]
		rest := strings.TrimLeft(strings.TrimPrefix(l, label), " ")
		if label != r.label || rest != r.line {
			t.Errorf("line %d parses as (%q, %q), want (%q, %q)", i, label, rest, r.label, r.line)
		}
	}
	if got, want := lines[0], "a"+strings.Repeat(" ", col-1)+rows[0].line; got != want {
		t.Errorf("line 0:\n got %q\nwant %q", got, want)
	}
}

func TestRunAuthorizedKeysFromWarning(t *testing.T) {
	for _, tt := range []struct {
		name string
		from []string
		warn bool
	}{
		{"absent", nil, true},
		{"given", []string{"192.0.2.10"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, hosts := range [][]string{nil, {"web1"}} {
				var stdout, stderr bytes.Buffer
				exit := runAuthorizedKeys(hosts, nil, akLog(&stderr), &stdout, testPubkey, tt.from)
				if exit != 0 {
					t.Errorf("hosts %q: exit = %d, want 0", hosts, exit)
				}
				gotWarn := strings.Contains(stderr.String(), "level=WARN") &&
					strings.Contains(stderr.String(), "no --from given")
				if gotWarn != tt.warn {
					t.Errorf("hosts %q: --from warning = %v, want %v; stderr:\n%s", hosts, gotWarn, tt.warn, stderr.String())
				}
				if !tt.warn && stderr.Len() > 0 {
					t.Errorf("hosts %q: unexpected stderr:\n%s", hosts, stderr.String())
				}
				if stdout.Len() == 0 || strings.Contains(stdout.String(), "--from") || strings.Contains(stdout.String(), "level=") {
					t.Errorf("hosts %q: stdout should hold only the table: %q", hosts, stdout.String())
				}
				if hasFrom := strings.Contains(stdout.String(), `from="`); hasFrom == tt.warn {
					t.Errorf("hosts %q: from= in output = %v, want %v", hosts, hasFrom, !tt.warn)
				}
			}
		})
	}
}

// TestCLIGrammar runs real argv through kong, catching tag mistakes (wrong
// or derived names, bad defaults, mis-scoped flags) that in-process tests
// calling run* skip. It checks both the parsed struct and the selected
// command, which is what main dispatches on.
func TestCLIGrammar(t *testing.T) {
	const (
		checkCmd   = "check"
		akCmd      = "authorized-keys <pubkey>"
		akHostsCmd = "authorized-keys <pubkey> <host>"
	)
	defaults := CLI{Check: CheckCmd{Concurrency: 8, Timeout: 10 * time.Second, Retries: 2, RetryDelay: 5 * time.Second}}
	with := func(f func(*CLI)) CLI {
		c := defaults
		f(&c)
		return c
	}
	tests := []struct {
		name    string
		args    []string
		want    CLI
		wantCmd string
	}{
		{"bare runs check with defaults", nil, defaults, checkCmd},
		{"production form without command", []string{"-i", "k", "-c", "cfg", "-s", "example.com"},
			with(func(c *CLI) { c.Check.Identity = "k"; c.Config = "cfg"; c.Check.Strip = "example.com" }), checkCmd},
		{"production form with -t and -r", []string{"-i", "k", "-c", "cfg", "-s", "example.com", "-t", "2s", "-r", "0"},
			with(func(c *CLI) {
				c.Check.Identity = "k"
				c.Config = "cfg"
				c.Check.Strip = "example.com"
				c.Check.Timeout = 2 * time.Second
				c.Check.Retries = 0
			}), checkCmd},
		{"explicit check", []string{"check", "-i", "k", "-C", "4"},
			with(func(c *CLI) { c.Check.Identity = "k"; c.Check.Concurrency = 4 }), checkCmd},
		{"explicit check strip-all", []string{"check", "-S"},
			with(func(c *CLI) { c.Check.StripAll = true }), checkCmd},
		{"explicit check strip long form", []string{"check", "--strip=example.com"},
			with(func(c *CLI) { c.Check.Strip = "example.com" }), checkCmd},
		{"check flags long form", []string{"--identity=id", "--concurrency=3", "--timeout=2s", "--retries=0", "--retry-delay=1s"},
			with(func(c *CLI) {
				c.Check = CheckCmd{Identity: "id", Concurrency: 3, Timeout: 2 * time.Second, Retries: 0, RetryDelay: time.Second}
			}), checkCmd},
		{"repeated -v", []string{"-v", "-v", "-c", "cfg"},
			with(func(c *CLI) { c.Verbose = 2; c.Config = "cfg" }), checkCmd},
		{"clustered -vv", []string{"-vv"},
			with(func(c *CLI) { c.Verbose = 2 }), checkCmd},
		{"existing flags unaffected", []string{"-i", "id", "-S", "-vv", "--retry-delay=1s"},
			with(func(c *CLI) {
				c.Check.Identity = "id"
				c.Check.StripAll = true
				c.Verbose = 2
				c.Check.RetryDelay = time.Second
			}), checkCmd},
		{"authorized-keys without hosts", []string{"authorized-keys", "k.pub"},
			with(func(c *CLI) { c.AuthorizedKeys.Pubkey = "k.pub" }), akCmd},
		{"authorized-keys with from and hosts",
			[]string{"authorized-keys", "--from", "192.0.2.1", "k.pub", "facts", "web1.example.com"},
			with(func(c *CLI) {
				c.AuthorizedKeys = AuthorizedKeysCmd{Pubkey: "k.pub", Hosts: []string{"facts", "web1.example.com"}, From: "192.0.2.1"}
			}), akHostsCmd},
		{"root flag before authorized-keys", []string{"-c", "cfg", "authorized-keys", "k.pub", "h"},
			with(func(c *CLI) {
				c.Config = "cfg"
				c.AuthorizedKeys = AuthorizedKeysCmd{Pubkey: "k.pub", Hosts: []string{"h"}}
			}), akHostsCmd},
		{"root flags after authorized-keys", []string{"authorized-keys", "-c", "cfg", "-v", "k.pub", "h"},
			with(func(c *CLI) {
				c.Config = "cfg"
				c.Verbose = 1
				c.AuthorizedKeys = AuthorizedKeysCmd{Pubkey: "k.pub", Hosts: []string{"h"}}
			}), akHostsCmd},
		{"authorized-keys from equals", []string{"authorized-keys", "--from=192.0.2.10,!10.0.0.1", "/root/.ssh/id_ipsentinel.pub"},
			with(func(c *CLI) {
				c.AuthorizedKeys = AuthorizedKeysCmd{Pubkey: "/root/.ssh/id_ipsentinel.pub", From: "192.0.2.10,!10.0.0.1"}
			}), akCmd},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli CLI
			parser, err := kong.New(&cli)
			if err != nil {
				t.Fatalf("kong.New: %v", err)
			}
			kctx, err := parser.Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse(%q): %v", tt.args, err)
			}
			if !reflect.DeepEqual(cli, tt.want) {
				t.Errorf("Parse(%q)\n got %+v\nwant %+v", tt.args, cli, tt.want)
			}
			if got := kctx.Command(); got != tt.wantCmd {
				t.Errorf("Parse(%q) command = %q, want %q", tt.args, got, tt.wantCmd)
			}
			// main dispatches on the selected command's name.
			if got, want, _ := strings.Cut(tt.wantCmd, " "); kctx.Selected() == nil || kctx.Selected().Name != got {
				t.Errorf("Parse(%q) selected = %v, want %q (%s)", tt.args, kctx.Selected(), got, want)
			}
		})
	}
}

// TestCLIGrammarErrors pins argv kong must reject: check-only flags
// (including -s/-S) are scoped away from authorized-keys, PUBKEY is
// required, and --from is only valid under authorized-keys.
func TestCLIGrammarErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"identity under authorized-keys", []string{"authorized-keys", "-i", "k", "k.pub"}},
		{"strip under authorized-keys", []string{"authorized-keys", "-s", "x", "k.pub"}},
		{"strip-all under authorized-keys", []string{"authorized-keys", "-S", "k.pub"}},
		{"strip before authorized-keys", []string{"-s", "x", "authorized-keys", "k.pub"}},
		{"strip-all before authorized-keys", []string{"-S", "authorized-keys", "k.pub"}},
		{"identity before authorized-keys", []string{"-i", "k", "authorized-keys", "k.pub", "h"}},
		{"authorized-keys missing pubkey", []string{"authorized-keys"}},
		{"from without authorized-keys", []string{"--from", "192.0.2.1"}},
		{"from under check", []string{"check", "--from", "192.0.2.1"}},
		{"strip xor strip-all", []string{"-s", "example.com", "-S"}},
		{"check strip xor strip-all", []string{"check", "-s", "example.com", "-S"}},
		{"old authorized-keys flag", []string{"--authorized-keys=k.pub"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli CLI
			parser, err := kong.New(&cli)
			if err != nil {
				t.Fatalf("kong.New: %v", err)
			}
			if _, err := parser.Parse(tt.args); err == nil {
				t.Errorf("Parse(%q) succeeded, want error; got %+v", tt.args, cli)
			}
		})
	}
}
