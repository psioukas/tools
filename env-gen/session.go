package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/x/term"
)

// The unlock session (BW_SESSION) can be cached in a 0600 file with an expiry, so
// you don't have to unlock in every shell. It is a bearer key for your vault while it
// lives: keep the TTL short, run `env-gen lock` when done, or disable it with
// `env-gen config set session.cache off`.
//
//	$XDG_CACHE_HOME/env-gen/session (default ~/.cache/env-gen/session), override ENV_GEN_SESSION
type sessFile struct {
	Session string    `json:"session"`
	Expires time.Time `json:"expires"`
}

func sessionPath() string {
	if p := os.Getenv("ENV_GEN_SESSION"); p != "" {
		return p
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "env-gen", "session")
}

func sessionTTL() time.Duration {
	d, err := time.ParseDuration(cfg.Get("session.ttl", "1h"))
	if err != nil || d < 0 {
		return time.Hour
	}
	return d
}

func sessionCacheEnabled() bool {
	return cfg.Get("session.cache", "on") != "off" && sessionTTL() > 0 && sessionPath() != ""
}

// loadSession returns a still-valid cached session, or "".
func loadSession() string {
	if !sessionCacheEnabled() {
		return ""
	}
	p := sessionPath()
	st, err := os.Stat(p)
	if err != nil {
		return ""
	}
	if st.Mode().Perm()&0o077 != 0 { // readable by others: don't trust, don't use
		fmt.Fprintf(os.Stderr, "warning: ignoring %s (permissions %v; expected 0600)\n", p, st.Mode().Perm())
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var f sessFile
	if json.Unmarshal(b, &f) != nil || f.Session == "" || time.Now().After(f.Expires) {
		_ = os.Remove(p)
		return ""
	}
	return f.Session
}

func sessionExpiry() (time.Time, bool) {
	b, err := os.ReadFile(sessionPath())
	if err != nil {
		return time.Time{}, false
	}
	var f sessFile
	if json.Unmarshal(b, &f) != nil || f.Session == "" || time.Now().After(f.Expires) {
		return time.Time{}, false
	}
	return f.Expires, true
}

func saveSession(s string) {
	if !sessionCacheEnabled() || s == "" {
		return
	}
	p := sessionPath()
	if os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	b, _ := json.Marshal(sessFile{Session: s, Expires: time.Now().Add(sessionTTL())})
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, p)
	}
}

func clearSession() {
	if p := sessionPath(); p != "" {
		_ = os.Remove(p)
	}
}

func isTerminal(f *os.File) bool { return term.IsTerminal(f.Fd()) } // /dev/null is not a terminal

// unlockInteractive asks for the master password (hidden), unlocks with bw and caches the session.
func unlockInteractive(bw *Bw) (string, error) {
	var pw string
	if err := newForm(huh.NewGroup(huh.NewInput().Title("Master password").
		EchoMode(huh.EchoModePassword).Value(&pw))).Run(); err != nil {
		return "", err
	}
	s, err := bw.Unlock(pw)
	if err != nil {
		return "", err
	}
	saveSession(s)
	return s, nil
}

func runUnlock() int {
	bw := NewBw()
	s, err := unlockInteractive(bw)
	if err != nil {
		say("unlock failed: %v", err)
		return 1
	}
	if sessionCacheEnabled() {
		say("unlocked; session cached for %s (`env-gen lock` to clear it)", sessionTTL())
	} else {
		say("unlocked; session caching is off, so use:  eval \"$(env-gen unlock)\"")
	}
	fmt.Printf("export BW_SESSION='%s'\n", s)
	return 0
}

func runLock() int {
	clearSession()
	bw := NewBw()
	bw.Session = ""
	_, _ = bw.run("", "lock")
	say("locked; cached session removed. (An exported BW_SESSION in your shell stays set but is no longer valid.)")
	return 0
}
