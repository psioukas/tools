package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseEnv(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(p, []byte("# c\nexport A=\"x y\\n#z\"\nB=1 # note\nC='a$b'\n\nD=\n"), 0o600)
	got, err := parseEnv(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []kv{{"A", "x y\n#z"}, {"B", "1"}, {"C", "a$b"}, {"D", ""}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %v != %v", i, got[i], want[i])
		}
	}
}
