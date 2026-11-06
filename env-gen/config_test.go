package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "config")
	t.Setenv("ENV_GEN_CONFIG", p)
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	c.Set("vault.server", "https://v.example.com")
	c.Set("defaults.length", "40")
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	c2, err := LoadConfig()
	if err != nil || c2.Get("vault.server", "") != "https://v.example.com" || c2.Get("defaults.length", "") != "40" {
		t.Fatalf("%v %v", err, c2.vals)
	}
	if c2.Get("vault.bw", "bw") != "bw" {
		t.Error("default not applied")
	}
}
