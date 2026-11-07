package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ---- TOTP (RFC 6238, SHA-1, 6 digits, 30s) -------------------------------------------------

func totpAt(secret []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000)
}

// verifyTOTP accepts the previous, current and next 30s step, once per step (replay-safe).
func verifyTOTP(secret []byte, code string, now time.Time, last *int64) bool {
	step := now.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		c := step + d
		if c <= *last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, c)), []byte(code)) == 1 {
			*last = c
			return true
		}
	}
	return false
}

// ---- 2FA secret storage ------------------------------------------------------------------------

type uiFile struct {
	TOTPSecret string `json:"totp_secret"`
}

func uiSecretPath() string {
	if cfg.Path != "" {
		return filepath.Join(filepath.Dir(cfg.Path), "ui.json")
	}
	return ""
}

func loadTOTPSecret() ([]byte, error) {
	p := uiSecretPath()
	if p == "" {
		return nil, fmt.Errorf("cannot locate config dir")
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("2FA is not set up: run  env-gen ui init")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by others (mode %v); chmod 600 it", p, st.Mode().Perm())
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var f uiFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(f.TOTPSecret)
}

func runUIInit(force bool) int {
	p := uiSecretPath()
	if p == "" {
		fmt.Fprintln(os.Stderr, "cannot locate config dir (set ENV_GEN_CONFIG)")
		return 1
	}
	if _, err := os.Stat(p); err == nil && !force {
		fmt.Fprintf(os.Stderr, "%s already exists (use -force to replace the 2FA secret)\n", p)
		return 1
	}
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	b, _ := json.Marshal(uiFile{TOTPSecret: enc})
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "2FA secret saved to %s (0600).\nAdd it to your authenticator app (Google Authenticator, Aegis, 2FAS, ...):\n\n", p)
	fmt.Printf("  key:  %s\n  uri:  otpauth://totp/env-gen:vault?secret=%s&issuer=env-gen&algorithm=SHA1&digits=6&period=30\n\n", enc, enc)
	fmt.Fprintln(os.Stderr, "Log in to the web UI with your Vaultwarden master password plus the 6-digit code.")
	return 0
}

// ---- login rate limiting ---------------------------------------------------------------------

type failRec struct {
	n     int
	until time.Time
}

type limiter struct {
	mu     sync.Mutex
	perIP  map[string]*failRec
	global failRec
}

func newLimiter() *limiter { return &limiter{perIP: map[string]*failRec{}} }

func lockFor(n, threshold int) time.Duration {
	if n < threshold {
		return 0
	}
	d := 10 * time.Minute
	for i := threshold; i < n && d < 24*time.Hour; i++ {
		d *= 2
	}
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}
	return d
}

// allow reports whether a login attempt may proceed, or how long to wait.
func (l *limiter) allow(ip string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.global.until.After(now) {
		return false, l.global.until.Sub(now)
	}
	if r := l.perIP[ip]; r != nil && r.until.After(now) {
		return false, r.until.Sub(now)
	}
	return true, 0
}

func (l *limiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.perIP[ip]
	if r == nil {
		r = &failRec{}
		l.perIP[ip] = r
	}
	r.n++
	if d := lockFor(r.n, 5); d > 0 {
		r.until = now.Add(d)
	}
	l.global.n++
	if d := lockFor(l.global.n, 20); d > 0 {
		l.global.until = now.Add(d)
	}
}

func (l *limiter) ok(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.perIP, ip)
	l.global = failRec{}
}
