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
		rev  []hostKey
	}{
		{"empty", "", nil, nil},
		{"plain", "# Host [web1]:2222 found: line 1 \n[web1]:2222 " + keyA + "\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyA)[1]}}, nil},
		{"hashed", "# Host web1 found: line 3 \n|1|c2FsdA==|aGFzaA== " + keyB + "\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyB)[1]}}, nil},
		{"revoked returned separately, cert-authority skipped",
			"# Host h found: line 1\n@revoked h " + keyA + "\n# Host h found: line 2\n@cert-authority h " + keyB + "\n",
			nil, []hostKey{{"ssh-ed25519", strings.Fields(keyA)[1]}}},
		{"trailing comment ignored", "h " + keyA + " root@box\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyA)[1]}}, nil},
		{"blank lines and dupes", "\nh " + keyA + "\n\nh " + keyA + " again\nh " + keyRSA + "\n",
			[]hostKey{{"ssh-ed25519", strings.Fields(keyA)[1]}, {"ssh-rsa", strings.Fields(keyRSA)[1]}}, nil},
		{"short line skipped", "h ssh-ed25519\n", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, rev := parseKeygenFind(tt.out)
			if !reflect.DeepEqual(got, tt.want) || !reflect.DeepEqual(rev, tt.rev) {
				t.Errorf("parseKeygenFind = %v, %v; want %v, %v", got, rev, tt.want, tt.rev)
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
	alias    string   // HostKeyAlias in the ip-side config
	hostAl   string   // HostKeyAlias in the host-side config
	files    []string // user known_hosts files; the global list is empty
	hostFile []string // host-side user files; nil means the same as files
	none     bool     // user and global lists are both the literal "none"
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
	user, global := strings.Join(f.files, " "), "/nonexistent/ssh_known_hosts"
	if f.none {
		user, global = "none", "none"
	}
	if ip == "" {
		hu := user
		if f.hostFile != nil {
			hu = strings.Join(f.hostFile, " ")
		}
		out := "hostname " + hostname + "\nport " + port(f.hostPort) + "\n" +
			"userknownhostsfile " + hu + "\nglobalknownhostsfile " + global + "\n"
		if f.hostAl != "" {
			out += "hostkeyalias " + f.hostAl + "\n"
		}
		return out, nil
	}
	hash := "no"
	if f.hash {
		hash = "yes"
	}
	out := "hostname " + ip + "\nport " + port(f.ipPort) + "\nhashknownhosts " + hash + "\n" +
		"userknownhostsfile " + user + "\nglobalknownhostsfile " + global + "\n"
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
		{name: "key revoked for host is not copied", input: in1,
			known:    "web1 " + keyA + "\n@revoked web1 " + keyA + "\n",
			wantCode: 1,
			wantLog:  []string{"host key revoked for host; not adding", "hostname=web1", "ip=192.0.2.1", "name=web1"}},
		{name: "only the unrevoked key is copied", input: in1,
			known:   "web1 " + keyA + "\nweb1 " + keyB + "\n@revoked web1 " + keyA + "\n",
			wantOut: "192.0.2.1 " + keyB + "\n"},
		{name: "key revoked under the ip name is not printed", input: in1,
			known:   "web1 " + keyA + "\nweb1 " + keyB + "\n@revoked 192.0.2.1 " + keyA + "\n",
			wantOut: "192.0.2.1 " + keyB + "\n"},
		{name: "all keys revoked under the ip name", input: in1,
			known:    "web1 " + keyA + "\n@revoked 192.0.2.1 " + keyA + "\n",
			wantCode: 1,
			wantLog:  []string{"host key revoked for host; not adding"}},
		{name: "host-side hostkeyalias is the lookup name", input: in1,
			known:   "shared " + keyA + "\n",
			ssh:     fakeSSH{hostAl: "shared", hostPort: "2222", ipPort: "2222"},
			wantOut: "[192.0.2.1]:2222 " + keyA + "\n"},
		{name: "no connect: ip hosts warns", input: in1,
			known:   "web1 " + keyA + "\n",
			config:  Config{ConnectDefault: connectSSHConfig},
			wantLog: []string{"level=WARN", "no connect: ip hosts in input; nothing to do (did you mean --connect-default ip?)"}},
		{name: "ssh -G failure on ip side", input: in1,
			known:    "web1 " + keyA + "\n",
			ssh:      fakeSSH{err: errors.New("boom")},
			wantCode: 1,
			wantLog:  []string{"ssh -G failed", "side=ip"}},
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

// TestFindKeysStatError checks that a known_hosts file that cannot be
// stat'ed for a reason other than not existing is an error, not skipped.
func TestFindKeysStatError(t *testing.T) {
	needKeygen(t)
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits")
	}
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(file, []byte("web1 "+keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	missing := filepath.Join(t.TempDir(), "absent")
	if keys, _, err := findKeys(context.Background(), realKnownHostsEnv(), "web1", []string{missing}); err != nil || keys != nil {
		t.Errorf("missing file: keys = %v, err = %v; want nil, nil", keys, err)
	}
	if _, _, err := findKeys(context.Background(), realKnownHostsEnv(), "web1", []string{file}); err == nil {
		t.Error("unreadable file: err = nil, want an error")
	}
}

// TestRunKnownHostsPerSideFiles checks the %h-style layout where the host
// and ip names expand to different user known_hosts files: the host name is
// looked up in the host side's file, the ip name in the ip side's, and a Warn
// says where the printed lines belong.
func TestRunKnownHostsPerSideFiles(t *testing.T) {
	needKeygen(t)
	hostFile := writeKnownHosts(t, "web1 "+keyA+"\n")
	ipFile := writeKnownHosts(t, "192.0.2.1 "+keyA+"\n"+"192.0.2.1 "+keyRSA+"\n")
	f := fakeSSH{files: []string{ipFile}, hostFile: []string{hostFile}}
	env := realKnownHostsEnv()
	env.sshConfig, env.salt = f.config, testSalt
	var stdout, logbuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logbuf, nil))
	code := runKnownHosts(strings.NewReader("web1,192.0.2.1\n"), false, "", Config{ConnectDefault: connectIP}, log, &stdout, env)
	// The ip file holds a key that is not the host's: only reachable if the
	// ip name was looked up in the ip side's file.
	if code != 1 || !strings.Contains(logbuf.String(), "ip already has a different host key") {
		t.Errorf("code = %d, want 1 with a foreign-key error\nlog:\n%s", code, logbuf.String())
	}
	if !strings.Contains(logbuf.String(), "level=WARN") || !strings.Contains(logbuf.String(), "file="+ipFile) {
		t.Errorf("log missing the user-files Warn naming %s:\n%s", ipFile, logbuf.String())
	}

	// Without the foreign key, the host key is found in the host side's file
	// only, and printed.
	ipFile2 := writeKnownHosts(t, "")
	f = fakeSSH{files: []string{ipFile2}, hostFile: []string{hostFile}}
	env.sshConfig = f.config
	stdout.Reset()
	logbuf.Reset()
	code = runKnownHosts(strings.NewReader("web1,192.0.2.1\n"), false, "", Config{ConnectDefault: connectIP}, log, &stdout, env)
	if code != 0 || stdout.String() != "192.0.2.1 "+keyA+"\n" {
		t.Errorf("code = %d, stdout = %q\nlog:\n%s", code, stdout.String(), logbuf.String())
	}
}

// TestRunKnownHostsNoneFiles checks that the literal "none" ssh -G prints
// for a disabled known_hosts list is dropped, not treated as a relative file
// called none (which is made to exist here, holding the host's key).
func TestRunKnownHostsNoneFiles(t *testing.T) {
	needKeygen(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "none"), []byte("web1 "+keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	f := fakeSSH{none: true}
	env := realKnownHostsEnv()
	env.sshConfig, env.salt = f.config, testSalt
	var stdout, logbuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logbuf, nil))
	code := runKnownHosts(strings.NewReader("web1,192.0.2.1\n"), false, "", Config{ConnectDefault: connectIP}, log, &stdout, env)
	if code != 1 || stdout.String() != "" || !strings.Contains(logbuf.String(), "no known host key for host") {
		t.Errorf("code = %d, stdout = %q\nlog:\n%s", code, stdout.String(), logbuf.String())
	}
}
