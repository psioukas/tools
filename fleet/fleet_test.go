package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocSetKeepsStructure(t *testing.T) {
	d := parseDoc([]byte("# top\nexport A=1 # note\n\nB=\"x y\"\n"))
	d.set("A", "2")
	d.set("B", "plain")
	d.set("C", "needs space")
	d.del("B")
	want := "# top\nexport A=2 # note\n\nC=\"needs space\"\n"
	if string(d.bytes()) != want {
		t.Fatalf("got %q want %q", d.bytes(), want)
	}
	if v := parseDoc([]byte(`K='a b'` + "\n" + `L="q\"z"` + "\n")).values(); v["K"] != "a b" || v["L"] != `q"z` {
		t.Fatalf("values %v", v)
	}
}

func TestCompare(t *testing.T) {
	d := compare(map[string]string{"A": "1", "B": "2", "C": "3"}, map[string]string{"A": "1", "B": "x", "Z": "9"})
	if strings.Join(d.missing, ",") != "C" || strings.Join(d.changed, ",") != "B" || strings.Join(d.extra, ",") != "Z" {
		t.Fatalf("%+v", d)
	}
	if !d.drifted() || d.empty() {
		t.Fatal("expected drift")
	}
	if compare(map[string]string{"A": "1"}, map[string]string{"A": "1", "X": "y"}).empty() == false {
		t.Fatal("extra keys alone must not count as needing a push")
	}
}

func stubEnv(items map[string]map[string]string) *env {
	v := newVault()
	for k, m := range items {
		v.cache[k] = m
	}
	return &env{ctx: context.Background(), vault: v}
}

func TestDesired(t *testing.T) {
	e := stubEnv(map[string]map[string]string{
		"shop":      {"A": "1", "SECRET": "s", "LOCAL_ONLY": "x", "ENVV": "dev"},
		"shop-prod": {"A": "p", "ENVV": "prod"},
	})
	a := &App{VaultItem: "shop", Exclude: []string{"LOCAL_ONLY"}}
	got, err := e.desired(a, &Target{Overrides: map[string]string{"ENVV": "override", "EXTRA": "e"}})
	if err != nil {
		t.Fatal(err)
	}
	if got["A"] != "1" || got["SECRET"] != "s" || got["ENVV"] != "override" || got["EXTRA"] != "e" || got["LOCAL_ONLY"] != "" {
		t.Fatalf("%v", got)
	}
	got, _ = e.desired(a, &Target{VaultItem: "shop-prod", Include: []string{"A"}})
	if len(got) != 1 || got["A"] != "p" {
		t.Fatalf("item override + include: %v", got)
	}
	got, _ = e.desired(a, &Target{Exclude: []string{"SECRET"}})
	if _, ok := got["SECRET"]; ok {
		t.Fatal("target exclude ignored")
	}
	if _, err := e.desired(a, &Target{VaultItem: "missing"}); err == nil {
		t.Fatal("missing item should error")
	}
}

func TestConfigValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "apps.yaml")
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	if _, err := loadConfig(write(sampleConfig)); err != nil {
		t.Fatalf("sample config invalid: %v", err)
	}
	bad := map[string]string{
		"unknown field": "apps:\n a:\n  targets:\n   t: {driver: file, file: x, nope: 1}\n",
		"no file":       "apps:\n a:\n  targets:\n   t: {driver: file}\n",
		"ssh no host":   "apps:\n a:\n  targets:\n   t: {driver: ssh, file: x}\n",
		"file w/ host":  "apps:\n a:\n  targets:\n   t: {driver: file, file: x, host: h}\n",
		"bad driver":    "apps:\n a:\n  targets:\n   t: {driver: ftp, file: x}\n",
		"docker bare":   "apps:\n a:\n  targets:\n   t: {driver: docker, file: x}\n",
		"service/dir":   "apps:\n a:\n  targets:\n   t: {driver: docker, file: x, service: s}\n",
		"bad override":  "apps:\n a:\n  targets:\n   t: {driver: file, file: x, overrides: {'bad key': 1}}\n",
		"no targets":    "apps:\n a: {}\n",
	}
	for name, y := range bad {
		if _, err := loadConfig(write(y)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLocalStoreWriteBackupMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	st := localStore{}
	ctx := context.Background()
	if _, ok, err := st.read(ctx, p); ok || err != nil {
		t.Fatalf("missing file: %v %v", ok, err)
	}
	if err := st.write(ctx, p, []byte("A=1\n")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode %v", fi.Mode())
	}
	os.Chmod(p, 0o640)
	if err := st.write(ctx, p, []byte("A=2\n")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Fatalf("existing mode not kept: %v", fi.Mode())
	}
	if b, _ := os.ReadFile(p + ".bak"); string(b) != "A=1\n" {
		t.Fatalf("bak: %q", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("leftover temp files: %v", ents)
	}
}

// fake ssh: skips ssh options and the host, then runs the remote command locally.
const fakeSSH = `#!/usr/bin/env bash
while [[ "$1" == -* ]]; do case "$1" in -o|-p|-i) shift 2;; *) shift;; esac; done
shift # host
exec bash -c "$1"
`

func TestSSHStore(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "ssh")
	os.WriteFile(bin, []byte(fakeSSH), 0o755)
	t.Setenv("FLEET_SSH", bin)
	t.Setenv("HOME", dir)
	st := newSSHStore("user@host", "", 0)
	ctx := context.Background()
	for _, p := range []string{"~/app dir/it's.env", filepath.Join(dir, "plain.env")} {
		os.MkdirAll(filepath.Join(dir, "app dir"), 0o755)
		if _, ok, err := st.read(ctx, p); ok || err != nil {
			t.Fatalf("%s missing: %v %v", p, ok, err)
		}
		if err := st.write(ctx, p, []byte("K=v\n")); err != nil {
			t.Fatalf("%s write: %v", p, err)
		}
		if err := st.write(ctx, p, []byte("K=w\n")); err != nil {
			t.Fatal(err)
		}
		b, ok, err := st.read(ctx, p)
		if err != nil || !ok || string(b) != "K=w\n" {
			t.Fatalf("%s read back: %q %v %v", p, b, ok, err)
		}
		real := expandHome(p)
		if bak, _ := os.ReadFile(real + ".bak"); string(bak) != "K=v\n" {
			t.Fatalf("%s bak: %q", p, bak)
		}
	}
	out, err := st.shell(ctx, "echo hi; exit 0")
	if err != nil || strings.TrimSpace(string(out)) != "hi" {
		t.Fatalf("shell: %q %v", out, err)
	}
	if _, err := st.shell(ctx, "echo nope >&2; exit 7"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("shell error: %v", err)
	}
}

func TestDockerReloadDefaults(t *testing.T) {
	d, _ := newDockerDriver(&Target{Driver: "docker", File: "/x/.env", ComposeDir: "/srv/a b", Service: "web", Context: "ctx"})
	if got := d.(*dockerDriver).reload; got != "docker --context 'ctx' compose --project-directory '/srv/a b' up -d --force-recreate 'web'" {
		t.Fatalf("compose reload: %s", got)
	}
	d, _ = newDockerDriver(&Target{Driver: "docker", File: "/x/.env", Container: "c", Host: "h"})
	if got := d.(*dockerDriver).reload; got != "docker restart 'c'" {
		t.Fatalf("restart reload: %s", got)
	}
}

func TestShQuote(t *testing.T) {
	if shQuote("a'b") != `'a'\''b'` || remotePath("~/x y") != `"$HOME"/'x y'` || remotePath("~") != `"$HOME"` {
		t.Fatal("quoting")
	}
}
