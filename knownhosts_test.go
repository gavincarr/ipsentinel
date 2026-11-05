package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Fixed public keys (type and base64 only), generated once with ssh-keygen.
const (
	keyA   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKnp0aeQ8jjSXMEYtrE7Hxvvl66zqTCN372lSImJ1SAv"
	keyB   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgPMhfCe6kt8+n7Js6nEXI9rbMaRDvAoyBF6t5ySM1X"
	keyRSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCzKKIKctOd+QT2jdahFMBclo4NW6sdesJZCpAs+VOnJcTR7qVvf4ZMWqmAJZ29ih6DZa8pVhx4/OX3AUaK7tsjhkoQ+CmhkAkhw+lJpT+LnWs8LOIBCa0QLYdJwMuCKCDFXnoAPJL6stwFNr9Xc77VlmB78MwyMgHEE/isb2bL3w=="
)

func TestParseSSHConfig(t *testing.T) {
	out := "hostname somealias\nport 22\nhashknownhosts yes\n" +
		"globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2\n" +
		"userknownhostsfile /home/gavin/.ssh/known_hosts /home/gavin/.ssh/known_hosts2\n" +
		"identityfile ~/.ssh/a\nidentityfile ~/.ssh/b\n\n"
	got := parseSSHConfig(out)
	want := map[string]string{
		"hostname":             "somealias",
		"port":                 "22",
		"hashknownhosts":       "yes",
		"globalknownhostsfile": "/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2",
		"userknownhostsfile":   "/home/gavin/.ssh/known_hosts /home/gavin/.ssh/known_hosts2",
		"identityfile":         "~/.ssh/a",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSSHConfig = %v, want %v", got, want)
	}
	if _, ok := got["hostkeyalias"]; ok {
		t.Error("absent hostkeyalias should be absent from the map")
	}
}

func TestParseKeygenFind(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []hostKey
	}{
		{"empty", "", nil},
		{"plain", "# Host [web1]:2222 found: line 1 \n[web1]:2222 " + keyA + "\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyA)[1]}}},
		{"hashed", "# Host web1 found: line 3 \n|1|c2FsdA==|aGFzaA== " + keyB + "\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyB)[1]}}},
		{"revoked and cert-authority skipped",
			"# Host h found: line 1\n@revoked h " + keyA + "\n# Host h found: line 2\n@cert-authority h " + keyB + "\n",
			nil},
		{"trailing comment ignored", "h " + keyA + " root@box\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyA)[1]}}},
		{"blank lines and dupes", "\nh " + keyA + "\n\nh " + keyA + " again\nh " + keyRSA + "\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyA)[1]}, {"ssh-rsa", strings.Fields(keyRSA)[1]}}},
		{"short line skipped", "h ssh-ed25519\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseKeygenFind(tt.out); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseKeygenFind = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKnownHostsName(t *testing.T) {
	tests := []struct{ host, port, want string }{
		{"192.0.2.1", "22", "192.0.2.1"},
		{"192.0.2.1", "2222", "[192.0.2.1]:2222"},
		{"2001:db8::1", "22", "2001:db8::1"},
		{"2001:db8::1", "2222", "[2001:db8::1]:2222"},
		{"web1", "2222", "[web1]:2222"},
	}
	for _, tt := range tests {
		if got := knownHostsName(tt.host, tt.port); got != tt.want {
			t.Errorf("knownHostsName(%q, %q) = %q, want %q", tt.host, tt.port, got, tt.want)
		}
	}
}

// TestHashKnownHostsName pins the hashed form against a line produced by
// `ssh-keygen -H`.
func TestHashKnownHostsName(t *testing.T) {
	salt, err := base64.StdEncoding.DecodeString("uF0fbbkt4hMtByt2CtWcDVjP1OM=")
	if err != nil {
		t.Fatal(err)
	}
	const want = "|1|uF0fbbkt4hMtByt2CtWcDVjP1OM=|RIULQ3InVILmUm+hH+P62bLOgF4="
	if got := hashKnownHostsName("[web1]:2222", salt); got != want {
		t.Errorf("hashKnownHostsName = %q, want %q", got, want)
	}
}

// fakeSSH is a fake `ssh -G` environment: the same settings for every host,
// with the host-side hostname equal to the input hostname.
type fakeSSH struct {
	hostPort string // port in host-side config; "" means 22
	ipPort   string // port in ip-side config; "" means 22
	hash     bool
	alias    string
	files    []string // user known_hosts files; the global list is empty
	err      error
}

func (f fakeSSH) config(_ context.Context, hostname, ip string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	port := func(p string) string {
		if p == "" {
			return "22"
		}
		return p
	}
	if ip == "" {
		return "hostname " + hostname + "\nport " + port(f.hostPort) + "\n", nil
	}
	hash := "no"
	if f.hash {
		hash = "yes"
	}
	out := "hostname " + ip + "\nport " + port(f.ipPort) + "\nhashknownhosts " + hash + "\n" +
		"userknownhostsfile " + strings.Join(f.files, " ") + "\nglobalknownhostsfile /nonexistent/ssh_known_hosts\n"
	if f.alias != "" {
		out += "hostkeyalias " + f.alias + "\n"
	}
	return out, nil
}

// testSalt is a fixed salt source.
func testSalt() ([]byte, error) { return []byte("01234567890123456789"), nil }

func needKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not on PATH")
	}
}

// writeKnownHosts writes content to a known_hosts file in a temp dir.
func writeKnownHosts(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// hashedLine returns a known_hosts line for name in hashed form.
func hashedLine(name, key string) string {
	return hashKnownHostsName(name, []byte("abcdefghijklmnopqrst")) + " " + key + "\n"
}

func TestRunKnownHosts(t *testing.T) {
	needKeygen(t)
	const in1 = "web1,192.0.2.1\n"
	tests := []struct {
		name       string
		input      string
		known      string // known_hosts file content; "" means a missing file
		ssh        fakeSSH
		config     Config
		wantOut    string
		wantCode   int
		wantLog    []string
		wantNotLog []string
	}{
		{name: "happy path port 22", input: in1,
			known:   "web1 " + keyA + "\n",
			wantOut: "192.0.2.1 " + keyA + "\n"},
		{name: "happy path non-22", input: in1,
			known:   "[web1]:2222 " + keyA + "\n",
			ssh:     fakeSSH{hostPort: "2222", ipPort: "2222"},
			wantOut: "[192.0.2.1]:2222 " + keyA + "\n"},
		{name: "ipv6 ip", input: "web1,2001:db8::1\n",
			known:   "web1 " + keyA + "\n",
			wantOut: "2001:db8::1 " + keyA + "\n"},
		{name: "hashed host entry", input: in1,
			known:   hashedLine("web1", keyA),
			wantOut: "192.0.2.1 " + keyA + "\n"},
		{name: "already recorded", input: in1,
			known:      "web1 " + keyA + "\n192.0.2.1 " + keyA + "\n",
			wantNotLog: []string{"level=ERROR", "level=WARN"},
			wantLog:    []string{"already recorded"}},
		{name: "already recorded hashed", input: in1,
			known: "web1 " + keyA + "\n" + hashedLine("192.0.2.1", keyA)},
		{name: "partial: only missing key printed", input: in1,
			known:   "web1 " + keyA + "\nweb1 " + keyRSA + "\n192.0.2.1 " + keyA + "\n",
			wantOut: "192.0.2.1 " + keyRSA + "\n"},
		{name: "ip has a foreign key", input: in1,
			known:    "web1 " + keyA + "\n192.0.2.1 " + keyB + "\n",
			wantCode: 1,
			wantLog:  []string{"ip already has a different host key; not adding", "name=192.0.2.1", "level=WARN"}},
		{name: "ip has foreign key as well as a good one", input: in1,
			known:    "web1 " + keyA + "\n192.0.2.1 " + keyA + "\n192.0.2.1 " + keyB + "\n",
			wantCode: 1,
			wantLog:  []string{"ip already has a different host key"}},
		{name: "host unknown", input: in1,
			known:    "other " + keyA + "\n",
			wantCode: 1,
			wantLog:  []string{"no known host key for host; add it by hand, see README", "hostname=web1", "ip=192.0.2.1", "name=web1"}},
		{name: "missing known_hosts file tolerated", input: in1,
			known:    "",
			wantCode: 1,
			wantLog:  []string{"no known host key for host"}},
		{name: "revoked host key not copied", input: in1,
			known:    "@revoked web1 " + keyA + "\n",
			wantCode: 1,
			wantLog:  []string{"no known host key for host"}},
		{name: "hostkeyalias set is skipped", input: in1,
			known:      "web1 " + keyA + "\n",
			ssh:        fakeSSH{alias: "shared"},
			wantLog:    []string{"hostkeyalias set"},
			wantNotLog: []string{"level=ERROR", "level=WARN"}},
		{name: "ssh_config host skipped", input: in1,
			known:   "web1 " + keyA + "\n",
			config:  Config{Hosts: map[string]HostConfig{"web1": {Connect: connectSSHConfig}}, ConnectDefault: connectIP},
			wantLog: []string{"not connect: ip"}},
		{name: "duplicate input line printed once", input: in1 + in1,
			known:   "web1 " + keyA + "\n",
			wantOut: "192.0.2.1 " + keyA + "\n"},
		{name: "second host claiming same ip with another key", input: in1 + "web2,192.0.2.1\n",
			known:    "web1 " + keyA + "\nweb2 " + keyB + "\n",
			wantOut:  "192.0.2.1 " + keyA + "\n",
			wantCode: 1,
			wantLog:  []string{"ip already has a different host key", "hostname=web2"}},
		{name: "ssh -G failure", input: in1,
			known:    "web1 " + keyA + "\n",
			ssh:      fakeSSH{err: errors.New("ssh exited 255: bad config")},
			wantCode: 1,
			wantLog:  []string{"ssh -G failed", "bad config"}},
		{name: "malformed input is a problem", input: "garbage\n" + in1,
			known:    "web1 " + keyA + "\n",
			wantOut:  "192.0.2.1 " + keyA + "\n",
			wantCode: 1,
			wantLog:  []string{"malformed input line"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "known_hosts")
			if tt.known != "" {
				if err := os.WriteFile(file, []byte(tt.known), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			f := tt.ssh
			f.files = []string{file}
			cfg := tt.config
			if cfg.ConnectDefault == "" {
				cfg.ConnectDefault = connectIP
			}
			var stdout, logbuf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&logbuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			env := realKnownHostsEnv()
			env.sshConfig, env.salt = f.config, testSalt

			code := runKnownHosts(strings.NewReader(tt.input), false, "", cfg, log, &stdout, env)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nlog:\n%s", code, tt.wantCode, logbuf.String())
			}
			if stdout.String() != tt.wantOut {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantOut)
			}
			for _, s := range tt.wantLog {
				if !strings.Contains(logbuf.String(), s) {
					t.Errorf("log missing %q:\n%s", s, logbuf.String())
				}
			}
			for _, s := range tt.wantNotLog {
				if strings.Contains(logbuf.String(), s) {
					t.Errorf("log unexpectedly contains %q:\n%s", s, logbuf.String())
				}
			}
		})
	}
}

// TestRunKnownHostsHashedRoundTrip checks that with HashKnownHosts yes the
// printed line is hashed, never leaks the ip or hostname, and is found by
// the real `ssh-keygen -F <ipname>` once appended to a known_hosts file.
func TestRunKnownHostsHashedRoundTrip(t *testing.T) {
	needKeygen(t)
	for _, port := range []string{"22", "2222"} {
		t.Run("port "+port, func(t *testing.T) {
			hostName := knownHostsName("web1", port)
			ipName := knownHostsName("192.0.2.1", port)
			src := writeKnownHosts(t, hostName+" "+keyA+"\n")
			f := fakeSSH{hostPort: port, ipPort: port, hash: true, files: []string{src}}
			env := realKnownHostsEnv()
			env.sshConfig, env.salt = f.config, testSalt

			var stdout, logbuf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&logbuf, nil))
			code := runKnownHosts(strings.NewReader("web1,192.0.2.1\n"), false, "", Config{ConnectDefault: connectIP}, log, &stdout, env)
			if code != 0 {
				t.Fatalf("exit code = %d\nlog:\n%s", code, logbuf.String())
			}
			line := stdout.String()
			if !strings.HasPrefix(line, "|1|") || strings.Contains(line, "192.0.2.1") || strings.Contains(line, "web1") {
				t.Fatalf("stdout = %q, want a hashed line without plain names", line)
			}

			dst := writeKnownHosts(t, line)
			out, err := exec.Command("ssh-keygen", "-F", ipName, "-f", dst).CombinedOutput()
			if err != nil || !strings.Contains(string(out), keyA) {
				t.Errorf("ssh-keygen -F %s = %q, %v; want the key", ipName, out, err)
			}
		})
	}
}
