package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

func (u *uiSession) isAdmin(now time.Time) bool { return u != nil && now.Before(u.adminUntil) }

func (u *uiSession) adminSeconds(now time.Time) int {
	if !u.isAdmin(now) {
		return 0
	}
	return int(u.adminUntil.Sub(now).Seconds())
}

func (s *uiServer) audit(r *http.Request, action, detail string) {
	log.Printf("audit ip=%s action=%s %s", s.clientIP(r), action, detail)
}

// admin gates a handler behind an active admin elevation and audits the call.
func (s *uiServer) admin(action string, fn apiFn) apiFn {
	return func(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
		if !s.creds.adminEnabled() {
			return nil, http.StatusForbidden, errors.New("admin access is not configured on the server (run `fleet ui admin-init`)")
		}
		if !sess.isAdmin(time.Now()) {
			return nil, http.StatusForbidden, errors.New("admin credentials required: use Admin sign-in")
		}
		out, code, err := fn(w, r, sess)
		status := "ok"
		if err != nil {
			status = "failed"
		}
		s.audit(r, action, status)
		return out, code, err
	}
}

// elevate verifies the separate admin passphrase and admin authenticator code.
func (s *uiServer) elevate(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	if !s.creds.adminEnabled() {
		return nil, http.StatusForbidden, errors.New("admin access is not configured on the server (run `fleet ui admin-init`)")
	}
	var req struct{ Passphrase, Code string }
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	ip := s.clientIP(r)
	now := time.Now()
	if ok, wait := s.adminLim.allow(ip, now); !ok {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())))
		return nil, http.StatusTooManyRequests, fmt.Errorf("too many failed admin attempts; try again in %s", wait.Round(time.Second))
	}
	s.mu.Lock()
	counter, codeOK := checkTOTP(s.creds.adminTOTP, strings.TrimSpace(req.Code), now, s.lastAdminTOTP)
	s.mu.Unlock()
	passOK := s.creds.checkPassphrase(req.Passphrase) // always evaluated: no shortcut on a bad code
	if codeOK && passOK {
		s.mu.Lock()
		codeOK = commitTOTP(&s.lastAdminTOTP, counter) // use the code up only on full success
		s.mu.Unlock()
	}
	if !codeOK || !passOK {
		s.adminLim.fail(ip, time.Now())
		s.audit(r, "admin.elevate", "denied")
		time.Sleep(400 * time.Millisecond)
		return nil, http.StatusUnauthorized, errors.New("invalid admin credentials")
	}
	s.adminLim.ok(ip)
	until := now.Add(s.adminTTL)
	s.mu.Lock()
	if s.sess != nil && s.sess.id == sess.id {
		s.sess.adminUntil = until
	}
	s.mu.Unlock()
	s.audit(r, "admin.elevate", "granted")
	return map[string]any{"admin": true, "admin_seconds": int(s.adminTTL.Seconds())}, 0, nil
}

func (s *uiServer) dropAdmin(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	s.mu.Lock()
	if s.sess != nil && s.sess.id == sess.id {
		s.sess.adminUntil = time.Time{}
	}
	s.mu.Unlock()
	return map[string]any{"admin": false}, 0, nil
}
