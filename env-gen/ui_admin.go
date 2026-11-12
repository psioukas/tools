package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
			return nil, http.StatusForbidden, errors.New("admin access is not configured on the server (run `env-gen ui admin-init`)")
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
		return nil, http.StatusForbidden, errors.New("admin access is not configured on the server (run `env-gen ui admin-init`)")
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

// ---- vault key management ---------------------------------------------------------------------

func validItem(item string) error {
	if strings.TrimSpace(item) == "" || len(item) > 200 || strings.ContainsAny(item, "\x00\r\n") {
		return errors.New("a valid vault item name is required")
	}
	return nil
}

func notFoundOr(err error, msg string) (int, error) {
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound, errors.New("vault item not found")
	}
	return http.StatusBadGateway, errors.New(msg)
}

func (s *uiServer) adminKeysList(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	item := r.URL.Query().Get("item")
	if err := validItem(item); err != nil {
		return nil, http.StatusBadRequest, err
	}
	raw, err := s.newBw(sess.bwSession).rawItem(item)
	if err != nil {
		c, e := notFoundOr(err, "vault lookup failed")
		return nil, c, e
	}
	recordItem(item)
	type row struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		Length int    `json:"length"`
	}
	rows := []row{}
	for _, f := range rawFields(raw) {
		typ := "text"
		if t, _ := f["type"].(float64); t == 1 {
			typ = "hidden"
		}
		rows = append(rows, row{fmt.Sprint(f["name"]), typ, len(fmt.Sprint(f["value"]))})
	}
	return map[string]any{"item": item, "fields": rows}, 0, nil
}

func (s *uiServer) adminKeyReveal(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	item, key := r.URL.Query().Get("item"), r.URL.Query().Get("key")
	if err := validItem(item); err != nil || key == "" {
		return nil, http.StatusBadRequest, errors.New("item and key required")
	}
	v, err := s.newBw(sess.bwSession).Read(item, key)
	if err != nil {
		c, e := notFoundOr(err, "no such field")
		return nil, c, e
	}
	return map[string]string{"value": v}, 0, nil
}

func (s *uiServer) adminKeyGenerate(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct {
		Item, Field, Charset string
		Length               int
		Replace              bool
	}
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	if err := validItem(req.Item); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if !keyRe.MatchString(req.Field) {
		return nil, http.StatusBadRequest, errors.New("field must look like an env var name")
	}
	if req.Length < 5 || req.Length > 128 {
		return nil, http.StatusBadRequest, errors.New("length must be 5-128")
	}
	v, err := genSecret(req.Length, req.Charset)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := s.newBw(sess.bwSession).StoreFields(req.Item, []kv{{req.Field, v}}, req.Replace, false); err != nil {
		if strings.Contains(err.Error(), "already has fields") {
			return nil, http.StatusConflict, errors.New("that field already exists; tick Replace to rotate it")
		}
		return nil, http.StatusBadGateway, errors.New("vault update failed")
	}
	recordItem(req.Item, req.Field)
	s.audit(r, "keys.generate.detail", fmt.Sprintf("item=%q field=%q replace=%v", req.Item, req.Field, req.Replace))
	return map[string]any{"item": req.Item, "field": req.Field, "length": req.Length}, 0, nil
}

func (s *uiServer) adminKeyRename(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct{ Item, Old, New string }
	if err := decode(r, &req); err != nil || validItem(req.Item) != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	if !keyRe.MatchString(req.New) {
		return nil, http.StatusBadRequest, errors.New("new name must look like an env var name")
	}
	bw := s.newBw(sess.bwSession)
	raw, err := bw.rawItem(req.Item)
	if err != nil {
		c, e := notFoundOr(err, "vault lookup failed")
		return nil, c, e
	}
	fields := rawFields(raw)
	oi, ni := -1, -1
	for i, f := range fields {
		switch f["name"] {
		case req.Old:
			oi = i
		case req.New:
			ni = i
		}
	}
	if oi < 0 || ni >= 0 {
		return nil, http.StatusConflict, errors.New("the old field must exist and the new name must not")
	}
	fields[oi]["name"] = req.New
	setRawFields(raw, fields)
	if err := bw.saveRaw(raw); err != nil {
		return nil, http.StatusBadGateway, errors.New("vault update failed")
	}
	s.audit(r, "keys.rename.detail", fmt.Sprintf("item=%q %q->%q", req.Item, req.Old, req.New))
	return map[string]bool{"ok": true}, 0, nil
}

func (s *uiServer) adminKeyDelete(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct {
		Item string
		Keys []string
	}
	if err := decode(r, &req); err != nil || validItem(req.Item) != nil || len(req.Keys) == 0 {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	drop := map[string]bool{}
	for _, k := range req.Keys {
		drop[k] = true
	}
	bw := s.newBw(sess.bwSession)
	raw, err := bw.rawItem(req.Item)
	if err != nil {
		c, e := notFoundOr(err, "vault lookup failed")
		return nil, c, e
	}
	var keep []map[string]any
	found := 0
	for _, f := range rawFields(raw) {
		if drop[fmt.Sprint(f["name"])] {
			found++
			continue
		}
		keep = append(keep, f)
	}
	if found != len(drop) {
		return nil, http.StatusNotFound, errors.New("one or more fields do not exist")
	}
	setRawFields(raw, keep)
	if err := bw.saveRaw(raw); err != nil {
		return nil, http.StatusBadGateway, errors.New("vault update failed")
	}
	names := append([]string{}, req.Keys...)
	sort.Strings(names)
	s.audit(r, "keys.delete.detail", fmt.Sprintf("item=%q fields=%v", req.Item, names))
	return map[string]int{"deleted": found}, 0, nil
}

// ---- push / pull --------------------------------------------------------------------------------

func (s *uiServer) adminPush(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct {
		Path, Item string
		Force      bool
		Template   bool
	}
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	full, err := s.safePath(req.Path)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if req.Item == "" {
		req.Item = pathProject(full)
	}
	if err := validItem(req.Item); err != nil {
		return nil, http.StatusBadRequest, err
	}
	pairs, err := parseEnv(full)
	if err != nil {
		return nil, http.StatusBadRequest, errors.New("could not parse the file")
	}
	if len(pairs) == 0 {
		return nil, http.StatusBadRequest, errors.New("no variables found")
	}
	if err := s.newBw(sess.bwSession).StoreFields(req.Item, pairs, req.Force, false); err != nil {
		if strings.Contains(err.Error(), "already has fields") {
			return nil, http.StatusConflict, errors.New("the vault item already has some of these fields; tick Overwrite to replace them")
		}
		return nil, http.StatusBadGateway, errors.New("vault update failed")
	}
	recordItem(req.Item)
	out := map[string]any{"item": req.Item, "pushed": len(pairs)}
	if req.Template {
		var tpl strings.Builder
		for _, p := range pairs {
			fmt.Fprintf(&tpl, "%s={{vw:%s/%s}}\n", p.Key, req.Item, p.Key)
		}
		tplPath := full + ".template"
		if _, err := os.Stat(tplPath); err == nil && !req.Force {
			out["template"] = "skipped (exists)"
		} else if err := os.WriteFile(tplPath, []byte(tpl.String()), 0o600); err != nil {
			out["template"] = "failed"
		} else {
			out["template"] = s.rel(tplPath)
		}
	}
	s.audit(r, "push.detail", fmt.Sprintf("file=%q item=%q vars=%d", s.rel(full), req.Item, len(pairs)))
	return out, 0, nil
}

func pathProject(full string) string { return filepath.Base(filepath.Dir(full)) }

func (s *uiServer) adminPull(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct {
		Item, To string
		Force    bool
	}
	if err := decode(r, &req); err != nil || validItem(req.Item) != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	dst, err := s.safePath(req.To)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	if _, err := os.Stat(dst); err == nil && !req.Force {
		return nil, http.StatusConflict, errors.New("target file already exists; tick Overwrite")
	}
	fields, err := s.newBw(sess.bwSession).Fields(req.Item)
	if err != nil {
		c, e := notFoundOr(err, "vault lookup failed")
		return nil, c, e
	}
	var sb strings.Builder
	var skipped []string
	for _, f := range fields {
		if !keyRe.MatchString(f.Name) {
			skipped = append(skipped, f.Name)
			continue
		}
		sb.WriteString(f.Name + "=" + quoteIfNeeded(f.Value) + "\n")
	}
	if sb.Len() == 0 {
		return nil, http.StatusBadRequest, errors.New("the item has no usable custom fields")
	}
	if old, err := os.ReadFile(dst); err == nil {
		_ = os.WriteFile(dst+".bak", old, 0o600)
	}
	if err := os.WriteFile(dst, []byte(sb.String()), 0o600); err != nil {
		return nil, http.StatusInternalServerError, errors.New("could not write file")
	}
	recordItem(req.Item)
	s.audit(r, "pull.detail", fmt.Sprintf("item=%q file=%q", req.Item, s.rel(dst)))
	return map[string]any{"path": s.rel(dst), "written": len(fields) - len(skipped), "skipped": skipped}, 0, nil
}
