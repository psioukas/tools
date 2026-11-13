package main

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
)

// allowedItem limits the web UI to vault items that apps.yaml refers to, so it can never
// be used to browse or modify unrelated entries in the vault.
func allowedItem(cfg *Config, item string) bool {
	for _, a := range cfg.Apps {
		if a.VaultItem == item {
			return true
		}
		for _, t := range a.Targets {
			if t.VaultItem == item {
				return true
			}
		}
	}
	return false
}

func (s *uiServer) appTarget(cfg *Config, app, target string) (*App, *Target, error) {
	a, ok := cfg.Apps[app]
	if !ok {
		return nil, nil, errors.New("unknown app")
	}
	if target == "" {
		return a, nil, nil
	}
	t, ok := a.Targets[target]
	if !ok {
		return nil, nil, errors.New("unknown target")
	}
	return a, t, nil
}

func targetsOf(a *App) []*Target {
	var ts []*Target
	for _, n := range a.targetNames() {
		ts = append(ts, a.Targets[n])
	}
	return ts
}

// ---- read-only (editor login) --------------------------------------------------------------------

func (s *uiServer) apiApps(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	cfg, err := loadConfig(s.cfgPath)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	type tgt struct {
		Name      string   `json:"name"`
		Driver    string   `json:"driver"`
		Where     string   `json:"where"`
		Item      string   `json:"vault_item"`
		Overrides []string `json:"overrides"`
		CanReload bool     `json:"can_reload"`
	}
	type app struct {
		Name    string `json:"name"`
		Item    string `json:"vault_item"`
		Targets []tgt  `json:"targets"`
	}
	var apps []app
	for _, an := range cfg.appNames() {
		a := cfg.Apps[an]
		x := app{Name: an, Item: a.VaultItem}
		for _, t := range targetsOf(a) {
			where := ""
			if d, err := newDriver(t); err == nil {
				where = d.Describe()
			}
			ov := sortedKeys(t.Overrides)
			x.Targets = append(x.Targets, tgt{t.name, t.Driver, where, t.item(a), ov, t.Reload != "" || t.Service != "" || t.Container != ""})
		}
		apps = append(apps, x)
	}
	return map[string]any{"apps": apps}, 0, nil
}

func (s *uiServer) apiState(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	e, err := s.env(r.Context(), sess)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	a, _, err := s.appTarget(e.cfg, r.URL.Query().Get("app"), "")
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	return map[string]any{"app": r.URL.Query().Get("app"), "targets": e.status(a, targetsOf(a), s.jobs)}, 0, nil
}

func (s *uiServer) apiPullPlan(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct{ App, Target string }
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	e, err := s.env(r.Context(), sess)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	a, t, err := s.appTarget(e.cfg, req.App, req.Target)
	if err != nil || t == nil {
		return nil, http.StatusNotFound, errors.New("unknown app or target")
	}
	p, err := e.planPull(a, t)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	return map[string]any{"item": p.Item, "creating": p.Creating, "add": nz(p.Add), "update": nz(p.Upd)}, 0, nil
}

func (s *uiServer) apiVaultVars(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	e, err := s.env(r.Context(), sess)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	item := r.URL.Query().Get("item")
	if !allowedItem(e.cfg, item) {
		return nil, http.StatusNotFound, errors.New("unknown vault item")
	}
	vals, err := e.vault.get(item)
	if err == errItemMissing {
		return map[string]any{"item": item, "exists": false, "vars": []any{}}, 0, nil
	}
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("vault lookup failed")
	}
	type v struct {
		Name   string `json:"name"`
		Length int    `json:"length"`
	}
	out := []v{}
	for _, k := range sortedKeys(vals) {
		out = append(out, v{k, len(vals[k])})
	}
	return map[string]any{"item": item, "exists": true, "vars": out}, 0, nil
}

// ---- changes (admin) --------------------------------------------------------------------------------

func (s *uiServer) apiPush(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct {
		App     string
		Targets []string
		Prune   bool
		Reload  bool
	}
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	e, err := s.env(r.Context(), sess)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	a, _, err := s.appTarget(e.cfg, req.App, "")
	if err != nil {
		return nil, http.StatusNotFound, err
	}
	var ts []*Target
	for _, n := range req.Targets {
		t, ok := a.Targets[n]
		if !ok {
			return nil, http.StatusNotFound, fmt.Errorf("unknown target %q", n)
		}
		ts = append(ts, t)
	}
	if len(ts) == 0 {
		return nil, http.StatusBadRequest, errors.New("choose at least one target")
	}
	var todo []*state
	var errs []ApplyResult
	for _, in := range e.inspectAll(a, ts, s.jobs) {
		switch {
		case in.Err != nil:
			errs = append(errs, ApplyResult{App: in.T.app, Target: in.T.name, Err: in.Err.Error()})
		case in.St.d.empty() && !(req.Prune && len(in.St.d.extra) > 0):
			// nothing to do
		default:
			todo = append(todo, in.St)
		}
	}
	results := append(errs, e.apply(todo, req.Prune, req.Reload, s.jobs)...)
	for _, res := range results {
		s.audit(r, "push.detail", fmt.Sprintf("app=%q target=%q wrote=%v reload=%q failed=%v", res.App, res.Target, res.Wrote, res.Reload, res.Err != ""))
	}
	return map[string]any{"results": results, "unchanged": len(ts) - len(results)}, 0, nil
}

func (s *uiServer) apiPull(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct{ App, Target string }
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	e, err := s.env(r.Context(), sess)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	a, t, err := s.appTarget(e.cfg, req.App, req.Target)
	if err != nil || t == nil {
		return nil, http.StatusNotFound, errors.New("unknown app or target")
	}
	p, err := e.planPull(a, t)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	if err := e.applyPull(p); err != nil {
		return nil, http.StatusBadGateway, errors.New("storing in the vault failed")
	}
	s.audit(r, "pull.detail", fmt.Sprintf("app=%q target=%q item=%q stored=%d", req.App, req.Target, p.Item, len(p.Changes)))
	return map[string]any{"item": p.Item, "stored": len(p.Changes), "created": p.Creating}, 0, nil
}

func (s *uiServer) itemAndEnv(r *http.Request, sess *uiSession, item string) (*env, int, error) {
	e, err := s.env(r.Context(), sess)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !allowedItem(e.cfg, item) {
		return nil, http.StatusNotFound, errors.New("unknown vault item")
	}
	return e, 0, nil
}

func (s *uiServer) apiVaultValue(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	item, key := r.URL.Query().Get("item"), r.URL.Query().Get("key")
	e, code, err := s.itemAndEnv(r, sess, item)
	if err != nil {
		return nil, code, err
	}
	vals, err := e.vault.get(item)
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("vault lookup failed")
	}
	v, ok := vals[key]
	if !ok {
		return nil, http.StatusNotFound, errors.New("no such variable")
	}
	return map[string]string{"value": v}, 0, nil
}

func (s *uiServer) apiVaultSet(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct{ Item, Key, Value string }
	if err := decode(r, &req); err != nil || !keyRe.MatchString(req.Key) {
		return nil, http.StatusBadRequest, errors.New("bad request: the name must look like an env var name")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	e, code, err := s.itemAndEnv(r, sess, req.Item)
	if err != nil {
		return nil, code, err
	}
	if err := e.vault.set(req.Item, map[string]string{req.Key: req.Value}); err != nil {
		return nil, http.StatusBadGateway, errors.New("vault update failed")
	}
	s.audit(r, "vault.set.detail", fmt.Sprintf("item=%q key=%q", req.Item, req.Key))
	return map[string]bool{"ok": true}, 0, nil
}

func (s *uiServer) apiVaultDelete(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct {
		Item string
		Keys []string
	}
	if err := decode(r, &req); err != nil || len(req.Keys) == 0 {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	e, code, err := s.itemAndEnv(r, sess, req.Item)
	if err != nil {
		return nil, code, err
	}
	if err := e.vault.remove(req.Item, req.Keys); err != nil {
		return nil, http.StatusBadGateway, errors.New("vault update failed")
	}
	names := append([]string{}, req.Keys...)
	sort.Strings(names)
	s.audit(r, "vault.delete.detail", fmt.Sprintf("item=%q keys=%v", req.Item, names))
	return map[string]int{"deleted": len(req.Keys)}, 0, nil
}

func (s *uiServer) apiVaultRename(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req struct{ Item, Old, New string }
	if err := decode(r, &req); err != nil || !keyRe.MatchString(req.New) {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	e, code, err := s.itemAndEnv(r, sess, req.Item)
	if err != nil {
		return nil, code, err
	}
	vals, err := e.vault.get(req.Item)
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("vault lookup failed")
	}
	v, ok := vals[req.Old]
	if !ok {
		return nil, http.StatusNotFound, errors.New("no such variable")
	}
	if _, clash := vals[req.New]; clash {
		return nil, http.StatusConflict, errors.New("the new name already exists")
	}
	if err := e.vault.set(req.Item, map[string]string{req.New: v}); err != nil {
		return nil, http.StatusBadGateway, errors.New("vault update failed")
	}
	if err := e.vault.remove(req.Item, []string{req.Old}); err != nil {
		return nil, http.StatusBadGateway, errors.New("renamed copy stored but the old name could not be removed")
	}
	s.audit(r, "vault.rename.detail", fmt.Sprintf("item=%q %q->%q", req.Item, req.Old, req.New))
	return map[string]bool{"ok": true}, 0, nil
}
