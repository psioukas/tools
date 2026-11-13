package main

import (
	"fmt"
	"sync"
)

// defaultJobs is how many targets are processed at once.
const defaultJobs = 4

// parallel runs fn(0..n-1) with at most `jobs` at a time and waits for all of them.
func parallel(n, jobs int, fn func(i int)) {
	if jobs < 1 {
		jobs = 1
	}
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

// prefetch loads every distinct vault item the targets need, one at a time, before any
// target is contacted: an unlock prompt then appears once, and workers only hit the cache.
func (e *env) prefetch(a *App, ts []*Target) error {
	seen := map[string]bool{}
	for _, t := range ts {
		it := t.item(a)
		if seen[it] {
			continue
		}
		seen[it] = true
		if _, err := e.vault.get(it); err != nil && err != errItemMissing {
			return err
		}
	}
	return nil
}

// Inspected is the outcome of looking at one target.
type Inspected struct {
	T       *Target
	St      *state
	Err     error
	Runtime []string // variables whose live value in the running app differs (drivers that can tell)
}

// inspectAll looks at the targets concurrently and returns results in the input order.
func (e *env) inspectAll(a *App, ts []*Target, jobs int) []*Inspected {
	out := make([]*Inspected, len(ts))
	if err := e.prefetch(a, ts); err != nil {
		for i, t := range ts {
			out[i] = &Inspected{T: t, Err: err}
		}
		return out
	}
	parallel(len(ts), jobs, func(i int) {
		r := &Inspected{T: ts[i]}
		r.St, r.Err = e.inspect(a, ts[i])
		if r.Err == nil {
			if rc, ok := r.St.drv.(RuntimeChecker); ok {
				if names, err := rc.RuntimeDiffers(e.ctx, r.St.want); err == nil {
					r.Runtime = names
				}
			}
		}
		out[i] = r
	})
	return out
}

// TargetStatus is the names-only summary of a target (no values), used by the UI and JSON output.
type TargetStatus struct {
	App     string   `json:"app"`
	Target  string   `json:"target"`
	Driver  string   `json:"driver"`
	Where   string   `json:"where"`
	State   string   `json:"state"` // in_sync | drifted | missing | error
	Error   string   `json:"error,omitempty"`
	Missing []string `json:"missing"`
	Changed []string `json:"changed"`
	Extra   []string `json:"extra"`
	Stale   []string `json:"runtime_differs"`
	Item    string   `json:"vault_item"`
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (e *env) summarize(a *App, r *Inspected) TargetStatus {
	ts := TargetStatus{App: r.T.app, Target: r.T.name, Driver: r.T.Driver, Item: r.T.item(a),
		Missing: []string{}, Changed: []string{}, Extra: []string{}, Stale: []string{}}
	if r.Err != nil {
		ts.State, ts.Error = "error", r.Err.Error()
		if drv, err := newDriver(r.T); err == nil {
			ts.Where = drv.Describe()
		}
		return ts
	}
	ts.Where = r.St.drv.Describe()
	ts.Missing, ts.Changed, ts.Extra, ts.Stale = nz(r.St.d.missing), nz(r.St.d.changed), nz(r.St.d.extra), nz(r.Runtime)
	switch {
	case !r.St.exists:
		ts.State = "missing"
	case !r.St.d.empty():
		ts.State = "drifted"
	default:
		ts.State = "in_sync"
	}
	return ts
}

func (e *env) status(a *App, ts []*Target, jobs int) []TargetStatus {
	rs := e.inspectAll(a, ts, jobs)
	out := make([]TargetStatus, len(rs))
	for i, r := range rs {
		out[i] = e.summarize(a, r)
	}
	return out
}

// ---- apply ---------------------------------------------------------------------------------------

// ApplyResult is what happened to one target during a push.
type ApplyResult struct {
	App    string `json:"app"`
	Target string `json:"target"`
	Where  string `json:"where"`
	Wrote  bool   `json:"wrote"`
	Reload string `json:"reload"` // "" (not requested), "ok", "none" (no command), "skipped", "failed"
	Err    string `json:"error,omitempty"`
	Hint   bool   `json:"reload_hint"` // a reload command exists but reload was not requested
}

// apply writes the planned changes to the targets concurrently, then optionally reloads each.
func (e *env) apply(sts []*state, prune, reload bool, jobs int) []ApplyResult {
	out := make([]ApplyResult, len(sts))
	parallel(len(sts), jobs, func(i int) {
		st := sts[i]
		t := st.t
		r := ApplyResult{App: t.app, Target: t.name, Where: st.drv.Describe()}
		d := parseDoc(st.raw)
		for _, k := range append(append([]string{}, st.d.missing...), st.d.changed...) {
			d.set(k, st.want[k])
		}
		if prune {
			for _, k := range st.d.extra {
				d.del(k)
			}
		}
		if err := st.drv.Write(e.ctx, d.bytes()); err != nil {
			r.Err = "write failed: " + err.Error()
			out[i] = r
			return
		}
		r.Wrote = true
		if !reload {
			r.Reload = "skipped"
			r.Hint = t.Reload != "" || t.Service != "" || t.Container != ""
			out[i] = r
			return
		}
		switch err := st.drv.Reload(e.ctx); {
		case err == nil:
			r.Reload = "ok"
		case err == errNoReload:
			r.Reload = "none"
		default:
			r.Reload, r.Err = "failed", "reload failed: "+err.Error()
		}
		out[i] = r
	})
	return out
}

// ---- pull ------------------------------------------------------------------------------------------

type pullPlan struct {
	T        *Target
	Item     string
	Creating bool
	Add, Upd []string
	Changes  map[string]string
}

func (e *env) planPull(a *App, t *Target) (*pullPlan, error) {
	drv, err := newDriver(t)
	if err != nil {
		return nil, err
	}
	raw, exists, err := drv.Read(e.ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", drv.Describe(), err)
	}
	if !exists {
		return nil, fmt.Errorf("%s does not exist", drv.Describe())
	}
	skip := map[string]bool{}
	for _, k := range append(append([]string{}, a.Exclude...), t.Exclude...) {
		skip[k] = true
	}
	for k := range t.Overrides { // per-target values are not the shared truth
		skip[k] = true
	}
	only := map[string]bool{}
	for _, k := range t.Include {
		only[k] = true
	}
	incoming := map[string]string{}
	for k, v := range parseDoc(raw).values() {
		if !skip[k] && (len(only) == 0 || only[k]) {
			incoming[k] = v
		}
	}
	p := &pullPlan{T: t, Item: t.item(a), Changes: map[string]string{}}
	current, err := e.vault.get(p.Item)
	if err == errItemMissing {
		current, err, p.Creating = map[string]string{}, nil, true
	}
	if err != nil {
		return nil, err
	}
	for _, k := range sortedKeys(incoming) {
		cv, ok := current[k]
		switch {
		case !ok:
			p.Add = append(p.Add, k)
			p.Changes[k] = incoming[k]
		case cv != incoming[k]:
			p.Upd = append(p.Upd, k)
			p.Changes[k] = incoming[k]
		}
	}
	return p, nil
}

func (e *env) applyPull(p *pullPlan) error {
	if len(p.Changes) == 0 {
		return nil
	}
	return e.vault.set(p.Item, p.Changes)
}
