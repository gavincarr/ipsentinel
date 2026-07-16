package main

import (
	"os"
	"path/filepath"
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
`)
	config, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	want := map[string]HostConfig{
		"web1.example.com": {Type: "aws"},
		"web2.example.com": {Type: "iproute2"},
		"web3.example.com": {}, // null entry: empty type, defaults later
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
	if _, ok := checkCommands[defaultCheckType]; !ok {
		t.Errorf("defaultCheckType %q is not a checkCommands key", defaultCheckType)
	}
}
