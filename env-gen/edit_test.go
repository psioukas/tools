package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestEnvDocEdit(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("# top\nexport A=1\n\nB=\"x y\"\nC=3\n"), 0o600)
	d, err := loadDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	d.set("A", "2")
	d.set("D", "\"n w\"")
	d.del("C")
	d.rename("B", "BB")
	want := "# top\nexport A=2\n\nBB=\"x y\"\nD=\"n w\"\n"
	if d.String() != want {
		t.Fatalf("got %q want %q", d.String(), want)
	}
	if v, ok := d.get("BB"); !ok || v != "x y" {
		t.Fatalf("get: %q %v", v, ok)
	}
}

func TestRecentCache(t *testing.T) {
	t.Setenv("ENV_GEN_CACHE", filepath.Join(t.TempDir(), "c", "recent.json"))
	recordItem("a", "F1")
	recordItem("b")
	recordItem("a", "F2", "F1")
	got := loadRecent()
	if len(got) != 2 || got[0].Name != "a" || len(got[0].Fields) != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestSessionCache(t *testing.T) {
	t.Setenv("ENV_GEN_SESSION", filepath.Join(t.TempDir(), "c", "session"))
	if loadSession() != "" {
		t.Fatal("expected empty")
	}
	saveSession("abc==")
	if loadSession() != "abc==" {
		t.Fatal("not cached")
	}
	st, _ := os.Stat(sessionPath())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	os.Chmod(sessionPath(), 0o644)
	if loadSession() != "" {
		t.Fatal("must ignore world-readable cache")
	}
	os.Chmod(sessionPath(), 0o600)
	clearSession()
	if loadSession() != "" {
		t.Fatal("not cleared")
	}
	cfg.Set("session.ttl", "1ns")
	defer cfg.Unset("session.ttl")
	saveSession("x")
	if loadSession() != "" {
		t.Fatal("expired session returned")
	}
}

func TestSetKeepsInlineComment(t *testing.T) {
	d := &envDoc{lines: []string{`A=1 # first`, `B="x # y" # second`, `C='q'`, `export D=4`}}
	d.set("A", "2")
	d.set("B", `"new val"`)
	d.set("C", "3")
	d.set("D", "5")
	want := []string{`A=2 # first`, `B="new val" # second`, `C=3`, `export D=5`}
	for i, w := range want {
		if d.lines[i] != w {
			t.Errorf("line %d: got %q want %q", i, d.lines[i], w)
		}
	}
}

func TestVarLabel(t *testing.T) {
	orig := map[string]string{"PORT": "3000", "DB_PASSWORD": "s3cret", "OLD": "x"}
	cases := []struct {
		k, v   string
		reveal bool
		want   string
	}{
		{"PORT", "3000", false, `PORT="3000"`},
		{"PORT", "4000", false, `PORT="4000"   (modified)`},
		{"DB_PASSWORD", "s3cret", false, `DB_PASSWORD="••••••••"`},
		{"DB_PASSWORD", "s3cret", true, `DB_PASSWORD="s3cret"`},
		{"NEW_ONE", "a b", false, `NEW_ONE="a b"   (new)`},
		{"EMPTY", "", false, `EMPTY=""   (new)`},
	}
	for _, c := range cases {
		if got := varLabel(c.k, c.v, c.reveal, orig); got != c.want {
			t.Errorf("got %s want %s", got, c.want)
		}
	}
}

func TestEnvCandidates(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{".env.production", ".env", "app.env", ".env.bak", "notes.txt", ".env.example"} {
		os.WriteFile(filepath.Join(dir, n), []byte("A=1\n"), 0o600)
	}
	os.Mkdir(filepath.Join(dir, ".env.d"), 0o755)
	wd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(wd)
	got := envCandidates()
	want := []string{".env", ".env.example", ".env.production", "app.env"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
