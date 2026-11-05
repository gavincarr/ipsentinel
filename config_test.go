package main

import (
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
  type: aws
web2.example.com:
  type: iproute2
web3.example.com:
web4.example.com:
  type: ifconfig
gitlab.example.com:
  type: connect
`)
	config, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	want := map[string]HostConfig{
		"web1.example.com":   {Type: "aws"},
		"web2.example.com":   {Type: "iproute2"},
		"web3.example.com":   {}, // null entry: empty type, defaults later
		"web4.example.com":   {Type: "ifconfig"},
		"gitlab.example.com": {Type: "connect"},
	}
	if len(config) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(config), len(want), config)
	}
	for host, hc := range want {
		if config[host] != hc {
			t.Errorf("config[%q] = %+v, want %+v", host, config[host], hc)
		}
	}
}

func TestLoadConfigEmptyFile(t *testing.T) {
	config, err := loadConfig(writeConfig(t, ""))
	if err != nil {
		t.Fatalf("empty config file should not error: %v", err)
	}
	if len(config) != 0 {
		t.Errorf("got %d entries, want 0", len(config))
	}
}

func TestLoadConfigErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		errWant string // substring expected in the error
	}{
		{"malformed yaml", "web1: [unclosed\n", "parsing"},
		{"unknown type", "web1.example.com:\n  type: gcp\n", `unknown type "gcp"`},
		{"unknown key", "web1.example.com:\n  tyep: aws\n", "tyep"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadConfig(writeConfig(t, tt.content))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.errWant) {
				t.Errorf("error %q does not contain %q", err, tt.errWant)
			}
		})
	}
}

// TestLoadConfigRejectsIPVersion pins that the retired ip_version key fails
// with an actionable message — not yaml's generic unknown-field error —
// whatever its value and whatever the host's type.
func TestLoadConfigRejectsIPVersion(t *testing.T) {
	const wantMsg = "host web1.example.com: ip_version is no longer supported: " +
		"ifconfig checks now query both IPv4 and IPv6; remove it"
	values := []string{`"4"`, `"6"`, "4", `"5"`, `""`, "", "null", "[4, 6]"}
	types := []string{"", "  type: ifconfig\n", "  type: iproute2\n", "  type: aws\n", "  type: connect\n"}
	for _, typ := range types {
		for _, v := range values {
			content := "web1.example.com:\n" + typ + "  ip_version: " + v + "\n"
			path := writeConfig(t, content)
			_, err := loadConfig(path)
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
	if _, err := loadConfig(filepath.Join(t.TempDir(), "nonexistent.yml")); err == nil {
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
	// connect deliberately shares iproute2's command, so its forced command
	// in authorized_keys is identical too.
	if cmd := checkCommands["connect"]; cmd != "ip address" {
		t.Errorf(`checkCommands["connect"] = %q, want "ip address"`, cmd)
	}
	if _, ok := checkCommands[defaultCheckType]; !ok {
		t.Errorf("defaultCheckType %q is not a checkCommands key", defaultCheckType)
	}
}
