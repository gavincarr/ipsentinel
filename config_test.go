package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeConfig writes content to a temp config file and returns its path.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `# ipsentinel config
web1.example.com:
  check: aws
web2.example.com:
  check: iproute2
web3.example.com:
web4.example.com:
  check: ifconfig
web5.example.com: {}
gitlab.example.com:
  connect: ip
  check: none
fwd.example.com:
  connect: ip
`)
	config, err := loadConfig(path, connectSSHConfig)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	want := map[string]HostConfig{
		"web1.example.com":   {Check: "aws"},
		"web2.example.com":   {Check: "iproute2"},
		"web3.example.com":   {}, // null entry: defaults later
		"web4.example.com":   {Check: "ifconfig"},
		"web5.example.com":   {}, // empty mapping: defaults later
		"gitlab.example.com": {Connect: "ip", Check: "none"},
		"fwd.example.com":    {Connect: "ip"},
	}
	if len(config.Hosts) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(config.Hosts), len(want), config.Hosts)
	}
	for host, hc := range want {
		if config.Hosts[host] != hc {
			t.Errorf("config.Hosts[%q] = %+v, want %+v", host, config.Hosts[host], hc)
		}
	}
	if config.ConnectDefault != connectSSHConfig {
		t.Errorf("ConnectDefault = %q, want %q", config.ConnectDefault, connectSSHConfig)
	}
}

// TestConfigDefaults pins how a host's connect and check resolve: unset
// keys (and absent hosts) take ssh_config — or the --connect-default — and
// iproute2, and an explicit connect beats the default.
func TestConfigDefaults(t *testing.T) {
	tests := []struct {
		name           string
		connectDefault string
		hc             HostConfig
		wantConnect    string
		wantCheck      string
	}{
		{"empty entry", connectSSHConfig, HostConfig{}, "ssh_config", "iproute2"},
		{"empty default means ssh_config", "", HostConfig{}, "ssh_config", "iproute2"},
		{"entry without connect takes default ip", connectIP, HostConfig{Check: "aws"}, "ip", "aws"},
		{"absent host takes default ip", connectIP, HostConfig{}, "ip", "iproute2"},
		{"explicit ssh_config beats default ip", connectIP, HostConfig{Connect: "ssh_config"}, "ssh_config", "iproute2"},
		{"explicit ip beats default ssh_config", connectSSHConfig, HostConfig{Connect: "ip", Check: "none"}, "ip", "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := Config{ConnectDefault: tt.connectDefault}.check("h", tt.hc)
			want := Check{Hostname: "h", Connect: tt.wantConnect, CheckName: tt.wantCheck}
			if c != want {
				t.Errorf("check = %+v, want %+v", c, want)
			}
		})
	}
}

// TestLoadConfigConnectDefault pins that loadConfig carries the default
// through and validates against it: an entry with no connect takes it.
func TestLoadConfigConnectDefault(t *testing.T) {
	path := writeConfig(t, "a.example.com:\n  check: aws\nb.example.com:\n  connect: ssh_config\n")
	config, err := loadConfig(path, connectIP)
	if err != nil {
		t.Fatal(err)
	}
	if config.ConnectDefault != connectIP {
		t.Errorf("ConnectDefault = %q, want %q", config.ConnectDefault, connectIP)
	}
	for host, want := range map[string]string{"a.example.com": "ip", "b.example.com": "ssh_config", "absent": "ip"} {
		if got := config.check(host, config.Hosts[host]).Connect; got != want {
			t.Errorf("%s: connect = %q, want %q", host, got, want)
		}
	}
}

// TestLoadConfigCombos pins that every connect x check combination loads,
// except check: none without connect: ip.
func TestLoadConfigCombos(t *testing.T) {
	for _, connect := range append([]string{""}, connectModes...) {
		for _, check := range append([]string{""}, slices.Sorted(maps.Keys(checkCommands))...) {
			for _, def := range connectModes {
				content := "h.example.com:\n"
				if connect != "" {
					content += "  connect: " + connect + "\n"
				}
				if check != "" {
					content += "  check: " + check + "\n"
				}
				effective := connect
				if effective == "" {
					effective = def
				}
				_, err := loadConfig(writeConfig(t, content), def)
				wantErr := check == checkNone && effective != connectIP
				if (err != nil) != wantErr {
					t.Errorf("default %s, %q: err = %v, wantErr %v", def, content, err, wantErr)
				}
			}
		}
	}
}

func TestLoadConfigCheckNoneNeedsConnectIP(t *testing.T) {
	tests := []struct {
		name, content, connectDefault, wantDetail string
	}{
		{"explicit ssh_config", "h.example.com:\n  connect: ssh_config\n  check: none\n", connectSSHConfig,
			"connect: ssh_config"},
		{"explicit ssh_config beats default ip", "h.example.com:\n  connect: ssh_config\n  check: none\n", connectIP,
			"connect: ssh_config"},
		{"defaulted", "h.example.com:\n  check: none\n", connectSSHConfig,
			"connect unset, so --connect-default=ssh_config applies"},
		{"defaulted, empty default", "h.example.com:\n  check: none\n", "",
			"connect unset, so --connect-default=ssh_config applies"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.content)
			_, err := loadConfig(path, tt.connectDefault)
			want := path + ": host h.example.com: check: none requires connect: ip (" + tt.wantDetail +
				"; it would pass whenever ssh to the name works, without ever testing the IP)"
			if err == nil || err.Error() != want {
				t.Errorf("error\n got %v\nwant %s", err, want)
			}
		})
	}
	// With --connect-default=ip, the same defaulted entry is valid.
	if _, err := loadConfig(writeConfig(t, "h.example.com:\n  check: none\n"), connectIP); err != nil {
		t.Errorf("check: none with --connect-default=ip: %v", err)
	}
}

func TestLoadConfigEmptyFile(t *testing.T) {
	config, err := loadConfig(writeConfig(t, ""), connectIP)
	if err != nil {
		t.Fatalf("empty config file should not error: %v", err)
	}
	if len(config.Hosts) != 0 {
		t.Errorf("got %d entries, want 0", len(config.Hosts))
	}
	if config.ConnectDefault != connectIP {
		t.Errorf("ConnectDefault = %q, want %q", config.ConnectDefault, connectIP)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		errWant string // substring expected in the error
	}{
		{"malformed yaml", "web1: [unclosed\n", "parsing"},
		{"unknown check", "web1.example.com:\n  check: gcp\n",
			`host web1.example.com: unknown check "gcp" (known: aws, ifconfig, iproute2, none)`},
		{"unknown connect", "web1.example.com:\n  connect: dns\n",
			`host web1.example.com: unknown connect "dns" (known: ip, ssh_config)`},
		{"connect type name as check", "web1.example.com:\n  connect: ip\n  check: connect\n", `unknown check "connect"`},
		{"unknown key", "web1.example.com:\n  chekc: aws\n", "chekc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, tt.content), connectSSHConfig)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errWant) {
				t.Errorf("error %q does not contain %q", err, tt.errWant)
			}
		})
	}
}

// TestLoadConfigRejectsType pins that the retired type key fails with a
// migration hint tailored to its value — not yaml's generic unknown-field
// error — even alongside the new keys.
func TestLoadConfigRejectsType(t *testing.T) {
	const generic = "replace type with check (and connect)"
	tests := []struct{ value, hint string }{
		{"iproute2", "use check: iproute2"},
		{"aws", "use check: aws"},
		{"ifconfig", "use check: ifconfig"},
		{`"ifconfig"`, "use check: ifconfig"},
		{"connect", "use connect: ip and check: none"},
		{"gcp", generic},
		{"none", generic},
		{"null", generic},
		{"", generic},
		{`""`, generic},
		{"[aws]", generic},
	}
	for _, tt := range tests {
		for _, extra := range []string{"", "  check: aws\n", "  connect: ip\n  check: none\n"} {
			content := "web1.example.com:\n" + extra + "  type: " + tt.value + "\n"
			path := writeConfig(t, content)
			_, err := loadConfig(path, connectSSHConfig)
			want := path + ": host web1.example.com: type is no longer supported: " + tt.hint
			if err == nil || err.Error() != want {
				t.Errorf("loadConfig(%q) error\n got %v\nwant %s", content, err, want)
			}
		}
	}
}

// TestLoadConfigRejectsIPVersion pins that the retired ip_version key fails
// with an actionable message — not yaml's generic unknown-field error —
// whatever its value and whatever the host's check.
func TestLoadConfigRejectsIPVersion(t *testing.T) {
	const wantMsg = "host web1.example.com: ip_version is no longer supported: " +
		"ifconfig checks now query both IPv4 and IPv6; remove it"
	values := []string{`"4"`, `"6"`, "4", `"5"`, `""`, "", "null", "[4, 6]"}
	settings := []string{"", "  check: ifconfig\n", "  check: iproute2\n", "  check: aws\n", "  connect: ip\n  check: none\n"}
	for _, set := range settings {
		for _, v := range values {
			content := "web1.example.com:\n" + set + "  ip_version: " + v + "\n"
			path := writeConfig(t, content)
			_, err := loadConfig(path, connectSSHConfig)
			if err == nil {
				t.Errorf("loadConfig(%q) = nil error, want ip_version rejection", content)
				continue
			}
			if want := path + ": " + wantMsg; err.Error() != want {
				t.Errorf("loadConfig(%q) error\n got %q\nwant %q", content, err, want)
			}
		}
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := loadConfig(filepath.Join(t.TempDir(), "nonexistent.yml"), connectSSHConfig); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestCheckCommands(t *testing.T) {
	if cmd := checkCommands["iproute2"]; cmd != "ip address" {
		t.Errorf(`checkCommands["iproute2"] = %q, want "ip address"`, cmd)
	}
	aws := checkCommands["aws"]
	for _, needle := range []string{"ip address", "169.254.169.254", "public-ipv4", "X-aws-ec2-metadata-token"} {
		if !strings.Contains(aws, needle) {
			t.Errorf(`checkCommands["aws"] missing %q`, needle)
		}
	}
	// ifconfig asks ifconfig.me over both families, each curl followed by
	// an echo for the newline its response body lacks.
	wantIfconfig := []string{
		"ip address",
		"curl -sf -4 -m 2 https://ifconfig.me || true",
		"echo",
		"curl -sf -6 -m 2 https://ifconfig.me || true",
		"echo",
	}
	if got := strings.Split(checkCommands["ifconfig"], "\n"); !slices.Equal(got, wantIfconfig) {
		t.Errorf(`checkCommands["ifconfig"] lines = %q, want %q`, got, wantIfconfig)
	}
	// none runs `true`: its output is never read, and it's the least
	// capability the key can be forced to.
	if cmd := checkCommands[checkNone]; cmd != "true" {
		t.Errorf(`checkCommands["none"] = %q, want "true"`, cmd)
	}
	if _, ok := checkCommands[defaultCheck]; !ok {
		t.Errorf("defaultCheck %q is not a checkCommands key", defaultCheck)
	}
	if !slices.Contains(connectModes, defaultConnect) {
		t.Errorf("defaultConnect %q is not in connectModes", defaultConnect)
	}
	if !slices.IsSorted(connectModes) {
		t.Errorf("connectModes %q is not sorted", connectModes)
	}
}
