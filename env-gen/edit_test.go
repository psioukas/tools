package main

import (
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
