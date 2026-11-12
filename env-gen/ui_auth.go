package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/charmbracelet/huh"
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

// checkTOTP finds the 30s step a code belongs to (previous, current or next) without
// using it up: a typo in the other credential must not burn a valid code.
func checkTOTP(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	step := now.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		c := step + d
		if c <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, c)), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// commitTOTP marks a step as used (call under the server lock, after the whole login
// succeeded). It fails if the step was used meanwhile, which stops replays and races.
func commitTOTP(last *int64, counter int64) bool {
	if counter <= *last {
		return false
	}
	*last = counter
	return true
}

// verifyTOTP checks and consumes in one go.
func verifyTOTP(secret []byte, code string, now time.Time, last *int64) bool {
	c, ok := checkTOTP(secret, code, now, *last)
	return ok && commitTOTP(last, c)
}

// ---- credential storage ------------------------------------------------------------------------

// ui.json (0600) holds the web UI's second factors. Editor login uses TOTPSecret.
// Admin elevation (keys, push, pull, storing in the vault) needs its own passphrase
// and its own authenticator entry, so editor credentials alone can never elevate.
type uiFile struct {
	TOTPSecret      string `json:"totp_secret"`
	AdminSalt       string `json:"admin_salt,omitempty"`
	AdminHash       string `json:"admin_hash,omitempty"`
	AdminIter       int    `json:"admin_iter,omitempty"`
	AdminTOTPSecret string `json:"admin_totp_secret,omitempty"`
}

type uiCreds struct {
	totp                []byte
	adminSalt, adminKey []byte
	adminIter           int
	adminTOTP           []byte
}

func (c *uiCreds) adminEnabled() bool {
	return len(c.adminKey) > 0 && len(c.adminTOTP) > 0
}

const adminIterations = 600000

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func uiSecretPath() string {
	if cfg.Path != "" {
		return filepath.Join(filepath.Dir(cfg.Path), "ui.json")
	}
	return ""
}

func readUIFile() (*uiFile, error) {
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
	return &f, nil
}

func writeUIFile(f *uiFile) error {
	p := uiSecretPath()
	if p == "" {
		return fmt.Errorf("cannot locate config dir (set ENV_GEN_CONFIG)")
	}
	b, _ := json.Marshal(f)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func loadUICreds() (*uiCreds, error) {
	f, err := readUIFile()
	if err != nil {
		return nil, err
	}
	c := &uiCreds{}
	if c.totp, err = b32.DecodeString(f.TOTPSecret); err != nil || len(c.totp) == 0 {
		return nil, fmt.Errorf("ui.json: bad totp_secret")
	}
	if f.AdminHash != "" {
		salt, e1 := hex.DecodeString(f.AdminSalt)
		key, e2 := hex.DecodeString(f.AdminHash)
		adm, e3 := b32.DecodeString(f.AdminTOTPSecret)
		if e1 != nil || e2 != nil || e3 != nil || f.AdminIter < 1 {
			return nil, fmt.Errorf("ui.json: admin credentials are corrupt; re-run  env-gen ui admin-init -force")
		}
		c.adminSalt, c.adminKey, c.adminIter, c.adminTOTP = salt, key, f.AdminIter, adm
	}
	return c, nil
}

func hashPassphrase(pass string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pass, salt, iter, 32)
}

func (c *uiCreds) checkPassphrase(pass string) bool {
	k, err := hashPassphrase(pass, c.adminSalt, c.adminIter)
	return err == nil && subtle.ConstantTimeCompare(k, c.adminKey) == 1
}

func newSecret() ([]byte, string) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	return secret, b32.EncodeToString(secret)
}

func runUIInit(force bool) int {
	p := uiSecretPath()
	if p == "" {
		fmt.Fprintln(os.Stderr, "cannot locate config dir (set ENV_GEN_CONFIG)")
		return 1
	}
	f := &uiFile{}
	if old, err := readUIFile(); err == nil {
		if !force {
			fmt.Fprintf(os.Stderr, "%s already exists (use -force to replace the editor 2FA secret; admin credentials are kept)\n", p)
			return 1
		}
		f = old
	}
	_, enc := newSecret()
	f.TOTPSecret = enc
	if err := writeUIFile(f); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "Editor 2FA secret saved to %s (0600).\nAdd it to your authenticator app (Google Authenticator, Aegis, 2FAS, ...):\n\n", p)
	fmt.Printf("  key:  %s\n  uri:  otpauth://totp/env-gen:editor?secret=%s&issuer=env-gen&algorithm=SHA1&digits=6&period=30\n\n", enc, enc)
	fmt.Fprintln(os.Stderr, "Log in to the web UI with your Vaultwarden master password plus the 6-digit code.\nFor keys, push, pull and storing in the vault, also run:  env-gen ui admin-init")
	return 0
}

// setAdminCreds stores a new admin passphrase and admin TOTP secret; returns the TOTP key.
func setAdminCreds(pass string, iter int) (string, error) {
	f, err := readUIFile()
	if err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := hashPassphrase(pass, salt, iter)
	if err != nil {
		return "", err
	}
	_, enc := newSecret()
	f.AdminSalt, f.AdminHash, f.AdminIter, f.AdminTOTPSecret = hex.EncodeToString(salt), hex.EncodeToString(key), iter, enc
	return enc, writeUIFile(f)
}

func runUIAdminInit(force bool) int {
	f, err := readUIFile()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if f.AdminHash != "" && !force {
		fmt.Fprintln(os.Stderr, "admin credentials already exist (use -force to replace them)")
		return 1
	}
	var p1, p2 string
	if err := newForm(huh.NewGroup(
		huh.NewInput().Title("New admin passphrase (min 12 characters)").EchoMode(huh.EchoModePassword).Value(&p1).
			Validate(func(s string) error {
				if len(s) < 12 {
					return fmt.Errorf("at least 12 characters")
				}
				return nil
			}),
		huh.NewInput().Title("Repeat it").EchoMode(huh.EchoModePassword).Value(&p2),
	)).Run(); err != nil {
		return abort(err)
	}
	if p1 != p2 {
		fmt.Fprintln(os.Stderr, "passphrases do not match")
		return 1
	}
	enc, err := setAdminCreds(p1, adminIterations)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "Admin credentials saved. Add this SEPARATE entry to your authenticator app:")
	fmt.Printf("  key:  %s\n  uri:  otpauth://totp/env-gen:admin?secret=%s&issuer=env-gen&algorithm=SHA1&digits=6&period=30\n\n", enc, enc)
	fmt.Fprintln(os.Stderr, "Use the admin passphrase + admin code in the UI's \"Admin sign-in\". Elevation lasts 5 minutes.")
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
