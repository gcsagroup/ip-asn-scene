package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPathFromArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "single dash value", args: []string{"-addr", ":18080", "-config", "config.yaml"}, want: "config.yaml"},
		{name: "double dash value", args: []string{"--config", "/etc/ipasn/config.yaml"}, want: "/etc/ipasn/config.yaml"},
		{name: "single dash equals", args: []string{"-config=/etc/ipasn/config.yaml"}, want: "/etc/ipasn/config.yaml"},
		{name: "double dash equals", args: []string{"--config=/etc/ipasn/config.yaml"}, want: "/etc/ipasn/config.yaml"},
		{name: "missing", args: []string{"-addr", ":18080"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := configPathFromArgs(tt.args); got != tt.want {
				t.Fatalf("configPathFromArgs() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewServiceConfigUsesAbsoluteConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("addr: ':18080'\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := newServiceConfig("ipasn-test", "IP ASN Test", "test service", path, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Arguments) != 3 {
		t.Fatalf("unexpected service arguments: %#v", cfg.Arguments)
	}
	if cfg.Arguments[0] != "-config" {
		t.Fatalf("missing config argument: %#v", cfg.Arguments)
	}
	if !filepath.IsAbs(cfg.Arguments[1]) {
		t.Fatalf("config path is not absolute: %#v", cfg.Arguments)
	}
	if cfg.Arguments[2] != "-update-on-start" {
		t.Fatalf("missing update-on-start argument: %#v", cfg.Arguments)
	}
}

func TestResolveServiceConfigPathRequiresReadableFile(t *testing.T) {
	if _, err := resolveServiceConfigPath(filepath.Join(t.TempDir(), "missing.yaml"), true); err == nil {
		t.Fatal("expected missing config file error")
	}
}
