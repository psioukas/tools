package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed webui/*
var webFS embed.FS

type uiSession struct {
	id, csrf, bwSession string
	created, last       time.Time
	adminUntil          time.Time // zero unless elevated with admin credentials
}

type uiServer struct {
	root       string // absolute, symlink-resolved
	hosts      map[string]bool
	trustProxy bool
	insecure   bool // plain-http dev mode, loopback only
	idle       time.Duration
	maxAge     time.Duration
	creds      *uiCreds
	adminTTL   time.Duration
	bin        string

	mu            sync.Mutex
	sess          *uiSession
	lastTOTP      int64
	lastAdminTOTP int64
	lim           *limiter
	adminLim      *limiter
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func runUI(args []string) int {
	if len(args) > 0 && args[0] == "admin-init" {
		f := flag.NewFlagSet("ui admin-init", flag.ExitOnError)
		force := f.Bool("force", false, "replace existing admin credentials")
		f.Parse(args[1:])
		return runUIAdminInit(*force)
	}
	if len(args) > 0 && args[0] == "init" {
		f := flag.NewFlagSet("ui init", flag.ExitOnError)
		force := f.Bool("force", false, "replace an existing 2FA secret")
		f.Parse(args[1:])
		return runUIInit(*force)
	}
	f := flag.NewFlagSet("ui", flag.ExitOnError)
	listen := f.String("listen", "127.0.0.1:8765", "address to listen on (put your HTTPS reverse proxy in front)")
	root := f.String("root", ".", "directory the UI may read and write .env files in")
	hosts := f.String("host", "", "public host name(s) the UI is served under, comma separated (required unless -insecure-http)")
	trust := f.Bool("trust-proxy", false, "trust X-Forwarded-Proto/-For from the reverse proxy (required unless -insecure-http)")
	insecure := f.Bool("insecure-http", false, "development only: allow plain http on a loopback address")
	idle := f.Duration("idle", 15*time.Minute, "log out after this much inactivity")
	adminTTL := f.Duration("admin-ttl", 5*time.Minute, "how long an admin sign-in lasts")
	f.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: env-gen ui init | ui admin-init | env-gen ui -root DIR -host vault.example.com -trust-proxy [-listen 127.0.0.1:8765]")
		f.PrintDefaults()
	}
	f.Parse(args)

	s := &uiServer{idle: *idle, maxAge: 8 * time.Hour, trustProxy: *trust, insecure: *insecure,
		hosts: map[string]bool{}, lim: newLimiter(), adminLim: newLimiter(), adminTTL: *adminTTL, bin: bwBin()}
	abs, err := filepath.Abs(*root)
	if err == nil {
		abs, err = filepath.EvalSymlinks(abs)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: bad -root:", err)
		return 1
	}
	s.root = abs
	for _, h := range strings.Split(*hosts, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			s.hosts[h] = true
		}
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: bad -listen:", err)
		return 1
	}
	loopback := host == "localhost" || net.ParseIP(host).IsLoopback()
	if !*insecure {
		if !*trust || len(s.hosts) == 0 {
			fmt.Fprintln(os.Stderr, "error: public mode needs -trust-proxy and -host (the UI refuses to serve anything but https via your proxy).\nFor local development use -insecure-http on a loopback address.")
			return 2
		}
		if !loopback {
			fmt.Fprintln(os.Stderr, "error: with a reverse proxy the UI should listen on a loopback address (127.0.0.1), not "+host)
			return 2
		}
	} else if !loopback {
		fmt.Fprintln(os.Stderr, "error: -insecure-http is only allowed on a loopback address")
		return 2
	}
	if s.creds, err = loadUICreds(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if s.creds.adminEnabled() {
		fmt.Fprintln(os.Stderr, "admin features enabled (keys, push, pull, storing in the vault need admin sign-in)")
	} else {
		fmt.Fprintln(os.Stderr, "admin features DISABLED: run  env-gen ui admin-init  to enable keys, push, pull and vault storing")
	}
	if _, err := exec.LookPath(s.bin); err != nil {
		fmt.Fprintf(os.Stderr, "error: bw (%q) not found in PATH\n", s.bin)
		return 1
	}

	srv := &http.Server{Addr: *listen, Handler: s.handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		sc, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = srv.Shutdown(sc)
	}()
	fmt.Fprintf(os.Stderr, "env-gen web UI on %s, files under %s\n", *listen, s.root)
	if *insecure {
		fmt.Fprintf(os.Stderr, "DEV MODE (plain http): open http://%s/\n", *listen)
	} else {
		fmt.Fprintf(os.Stderr, "serving https hosts: %s (via your reverse proxy). Ctrl+C to stop.\n", *hosts)
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// ---- HTTP plumbing ---------------------------------------------------------------------------

func (s *uiServer) handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "webui")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("POST /api/login", s.wrap(false, s.login))
	mux.HandleFunc("POST /api/logout", s.wrap(true, s.logout))
	mux.HandleFunc("GET /api/status", s.wrap(false, s.status))
	mux.HandleFunc("GET /api/projects", s.wrap(true, s.projects))
	mux.HandleFunc("GET /api/file", s.wrap(true, s.getFile))
	mux.HandleFunc("GET /api/value", s.wrap(true, s.getValue))
	mux.HandleFunc("POST /api/save", s.wrap(true, s.save))
	mux.HandleFunc("GET /api/vault/search", s.wrap(true, s.vaultSearch))
	mux.HandleFunc("GET /api/vault/fields", s.wrap(true, s.vaultFields))
	mux.HandleFunc("GET /api/vault/recent", s.wrap(true, s.vaultRecent))
	mux.HandleFunc("POST /api/admin/elevate", s.wrap(true, s.elevate))
	mux.HandleFunc("POST /api/admin/drop", s.wrap(true, s.dropAdmin))
	mux.HandleFunc("GET /api/admin/keys", s.wrap(true, s.admin("keys.list", s.adminKeysList)))
	mux.HandleFunc("GET /api/admin/key", s.wrap(true, s.admin("keys.reveal", s.adminKeyReveal)))
	mux.HandleFunc("POST /api/admin/keys/generate", s.wrap(true, s.admin("keys.generate", s.adminKeyGenerate)))
	mux.HandleFunc("POST /api/admin/keys/rename", s.wrap(true, s.admin("keys.rename", s.adminKeyRename)))
	mux.HandleFunc("POST /api/admin/keys/delete", s.wrap(true, s.admin("keys.delete", s.adminKeyDelete)))
	mux.HandleFunc("POST /api/admin/push", s.wrap(true, s.admin("push", s.adminPush)))
	mux.HandleFunc("POST /api/admin/pull", s.wrap(true, s.admin("pull", s.adminPull)))
	return s.guard(mux)
}

// guard applies the checks every request needs: security headers, allowed Host, https.
func (s *uiServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if !s.insecure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			if r.Header.Get("X-Forwarded-Proto") != "https" {
				http.Error(w, "https required", http.StatusForbidden)
				return
			}
		}
		if len(s.hosts) > 0 {
			host := strings.ToLower(r.Host)
			if hh, _, err := net.SplitHostPort(host); err == nil {
				host = hh
			}
			if !s.hosts[host] {
				http.Error(w, "unknown host", http.StatusMisdirectedRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *uiServer) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			parts := strings.Split(xf, ",")
			return strings.TrimSpace(parts[len(parts)-1]) // the entry our proxy appended
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

type apiFn func(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error)

func (s *uiServer) cookieName() string {
	if s.insecure {
		return "envgen"
	}
	return "__Host-envgen"
}

// current returns the live session for the request cookie, expiring idle ones.
func (s *uiServer) current(r *http.Request) *uiSession {
	c, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.sess.id)) != 1 {
		return nil
	}
	now := time.Now()
	if now.Sub(s.sess.last) > s.idle || now.Sub(s.sess.created) > s.maxAge {
		s.sess = nil
		return nil
	}
	s.sess.last = now
	cp := *s.sess
	return &cp
}

// wrap adds auth, CSRF protection and JSON handling. needAuth=false handlers see sess==nil when logged out.
func (s *uiServer) wrap(needAuth bool, fn apiFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.current(r)
		if needAuth && sess == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in"})
			return
		}
		if r.Method != http.MethodGet {
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "JSON required"})
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				if !sameOrigin(o, r.Host) {
					writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-origin request refused"})
					return
				}
			}
			if sess != nil && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.csrf)) != 1 {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "bad CSRF token"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		out, code, err := fn(w, r, sess)
		if err != nil {
			if code == 0 {
				code = http.StatusInternalServerError
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		if code == 0 {
			code = http.StatusOK
		}
		writeJSON(w, code, out)
	}
}

func sameOrigin(origin, host string) bool {
	i := strings.Index(origin, "://")
	return i >= 0 && strings.EqualFold(origin[i+3:], host)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ---- auth handlers ---------------------------------------------------------------------------

func (s *uiServer) status(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	if sess == nil {
		return map[string]any{"logged_in": false}, 0, nil
	}
	out := map[string]any{"logged_in": true, "csrf": sess.csrf, "unlocked": true,
		"server": cfg.Get("vault.server", ""), "email": cfg.Get("vault.email", ""),
		"root": filepath.Base(s.root), "admin_enabled": s.creds.adminEnabled(),
		"admin": sess.isAdmin(time.Now()), "admin_seconds": sess.adminSeconds(time.Now())}
	return out, 0, nil
}

func (s *uiServer) login(w http.ResponseWriter, r *http.Request, _ *uiSession) (any, int, error) {
	var req struct{ Password, Code string }
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	ip := s.clientIP(r)
	now := time.Now()
	if ok, wait := s.lim.allow(ip, now); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())))
		return nil, http.StatusTooManyRequests, fmt.Errorf("too many failed attempts; try again in %s", wait.Round(time.Second))
	}
	bad := func() (any, int, error) {
		s.lim.fail(ip, time.Now())
		time.Sleep(400 * time.Millisecond) // blunt timing / brute-force speed
		return nil, http.StatusUnauthorized, errors.New("invalid credentials")
	}
	s.mu.Lock()
	counter, okCode := checkTOTP(s.creds.totp, strings.TrimSpace(req.Code), now, s.lastTOTP)
	s.mu.Unlock()
	if !okCode || req.Password == "" {
		return bad()
	}
	b := s.newBw("")
	st, err := status(b)
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("vault CLI error: " + err.Error())
	}
	if st.Status == "unauthenticated" {
		return nil, http.StatusConflict, errors.New("the vault CLI is not logged in on the server; run `env-gen setup` there first")
	}
	bws, err := b.Unlock(req.Password)
	if err != nil {
		return bad()
	}
	s.mu.Lock()
	fresh := commitTOTP(&s.lastTOTP, counter)
	s.mu.Unlock()
	if !fresh { // the same code was used by a concurrent attempt
		return bad()
	}
	s.lim.ok(ip)
	sess := &uiSession{id: randHex(32), csrf: randHex(24), bwSession: bws, created: now, last: now}
	s.mu.Lock()
	s.sess = sess
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: sess.id, Path: "/", HttpOnly: true,
		Secure: !s.insecure, SameSite: http.SameSiteStrictMode, MaxAge: int(s.maxAge.Seconds())})
	return map[string]any{"logged_in": true, "csrf": sess.csrf}, 0, nil
}

func (s *uiServer) logout(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	s.mu.Lock()
	s.sess = nil
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: !s.insecure, SameSite: http.SameSiteStrictMode})
	return map[string]bool{"logged_in": false}, 0, nil
}

// newBw builds a vault client bound to a UI session. It deliberately ignores the
// on-disk session cache and BW_SESSION: only a UI login may open the vault here.
func (s *uiServer) newBw(session string) *Bw {
	return &Bw{Bin: s.bin, Session: session, cache: map[string]*bwItem{}}
}
