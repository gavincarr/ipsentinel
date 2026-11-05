package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
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

func TestRunAuthorizedKeys(t *testing.T) {
	const ifconfig4 = "ip address; curl -sf -4 -m 2 https://ifconfig.me || true; echo"
	line := func(forced string) string {
		return `from="192.0.2.10",restrict,command="` + forced + `" ` + testPubkey
	}
	config := map[string]HostConfig{
		"web2.example.com": {Type: "ifconfig", IPVersion: "4"},
		"db.example.com":   {Type: "aws"},
		"db.example.net":   {Type: "iproute2"}, // strips to the same target as db.example.com
	}

	tests := []struct {
		name       string
		strip      string
		stripAll   bool
		input      string
		wantStdout string
		wantStderr []string // substrings expected on stderr
		notStderr  []string // substrings that must not be on stderr
		wantExit   int
	}{
		{
			name:  "dedupe A and AAAA, first-seen order",
			strip: "example.com",
			input: "web1.example.com,192.0.2.1\n" +
				"web2.example.com,192.0.2.2\n" +
				"web1.example.com,2001:db8::1\n" + // AAAA for web1: deduped
				"web2.example.com,2001:db8::2\n",
			wantStdout: "web1\t" + line("ip address") + "\n" +
				"web2\t" + line(ifconfig4) + "\n",
			notStderr: []string{"ERROR", "WARN"},
			wantExit:  0,
		},
		{
			name:     "conflicting types for one target",
			stripAll: true,
			input: "web1.example.com,192.0.2.1\n" +
				"db.example.com,192.0.2.3\n" +
				"db.example.net,192.0.2.4\n" +
				"db.example.com,2001:db8::3\n",
			wantStdout: "web1\t" + line("ip address") + "\n",
			wantStderr: []string{"conflicting check types", "target=db", "type=aws", "other_type=iproute2", "omitted=1"},
			wantExit:   1,
		},
		{
			name:       "parse failure still emits valid targets, exits 1",
			input:      "web1,192.0.2.1\nbadline\n",
			wantStdout: "web1\t" + line("ip address") + "\n",
			wantStderr: []string{"malformed input line", "parse_failures=1"},
			wantExit:   1,
		},
		{
			name:       "empty input",
			input:      "",
			wantStdout: "",
			notStderr:  []string{"ERROR", "WARN"},
			wantExit:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			log := slog.New(slog.NewTextHandler(&stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
			cli := CLI{Strip: tt.strip, StripAll: tt.stripAll}

			exit := runAuthorizedKeys(cli, config, log, strings.NewReader(tt.input), &stdout,
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
			for _, s := range tt.notStderr {
				if strings.Contains(stderr.String(), s) {
					t.Errorf("stderr unexpectedly contains %q:\n%s", s, stderr.String())
				}
			}
			// Logs must never leak onto the data channel.
			if strings.Contains(stdout.String(), "level=") {
				t.Errorf("log output on stdout: %q", stdout.String())
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
		checkCmd = "check"
		akCmd    = "authorized-keys <pubkey>"
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
			with(func(c *CLI) { c.Check.Identity = "k"; c.Config = "cfg"; c.Strip = "example.com" }), checkCmd},
		{"explicit check", []string{"check", "-i", "k", "-C", "4"},
			with(func(c *CLI) { c.Check.Identity = "k"; c.Check.Concurrency = 4 }), checkCmd},
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
				c.StripAll = true
				c.Verbose = 2
				c.Check.RetryDelay = time.Second
			}), checkCmd},
		{"authorized-keys with from and root flags after command",
			[]string{"authorized-keys", "--from", "192.0.2.1,10.0.0.0/8", "-c", "cfg", "-s", "example.com", "k.pub"},
			with(func(c *CLI) {
				c.Config = "cfg"
				c.Strip = "example.com"
				c.AuthorizedKeys = AuthorizedKeysCmd{Pubkey: "k.pub", From: "192.0.2.1,10.0.0.0/8"}
			}), akCmd},
		{"root flag before authorized-keys", []string{"-c", "cfg", "authorized-keys", "k.pub"},
			with(func(c *CLI) { c.Config = "cfg"; c.AuthorizedKeys.Pubkey = "k.pub" }), akCmd},
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
			if cli != tt.want {
				t.Errorf("Parse(%q)\n got %+v\nwant %+v", tt.args, cli, tt.want)
			}
			if got := kctx.Command(); got != tt.wantCmd {
				t.Errorf("Parse(%q) command = %q, want %q", tt.args, got, tt.wantCmd)
			}
		})
	}
}

// TestCLIGrammarErrors pins argv kong must reject: check-only flags are
// scoped away from authorized-keys, PUBKEY is required, and --from is only
// valid under authorized-keys.
func TestCLIGrammarErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"check flag under authorized-keys", []string{"authorized-keys", "-i", "k", "k.pub"}},
		{"authorized-keys missing pubkey", []string{"authorized-keys"}},
		{"from without authorized-keys", []string{"--from", "192.0.2.1"}},
		{"from under check", []string{"check", "--from", "192.0.2.1"}},
		{"strip xor strip-all", []string{"-s", "example.com", "-S"}},
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
