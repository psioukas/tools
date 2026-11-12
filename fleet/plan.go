package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

type env struct {
	ctx   context.Context
	cfg   *Config
	vault *vaultClient
}

// desired computes the variables a target should hold: the vault item's values,
// minus excluded keys, limited to `include` when set, with per-target overrides on top.
func (e *env) desired(a *App, t *Target) (map[string]string, error) {
	vals, err := e.vault.get(t.item(a))
	if err != nil {
		if err == errItemMissing {
			return nil, fmt.Errorf("vault item %q does not exist yet (create it with `fleet pull` or `fleet edit`)", t.item(a))
		}
		return nil, err
	}
	skip := map[string]bool{}
	for _, k := range a.Exclude {
		skip[k] = true
	}
	for _, k := range t.Exclude {
		skip[k] = true
	}
	only := map[string]bool{}
	for _, k := range t.Include {
		only[k] = true
	}
	out := map[string]string{}
	for k, v := range vals {
		if skip[k] || (len(only) > 0 && !only[k]) || !keyRe.MatchString(k) {
			continue
		}
		out[k] = v
	}
	for k, v := range t.Overrides {
		out[k] = v
	}
	return out, nil
}

type diff struct {
	missing, changed, extra []string // names only; values never leave this package unless asked
}

func (d diff) empty() bool { return len(d.missing)+len(d.changed) == 0 }

func (d diff) drifted() bool { return !d.empty() || len(d.extra) > 0 }

func compare(want, have map[string]string) diff {
	var d diff
	for _, k := range sortedKeys(want) {
		hv, ok := have[k]
		switch {
		case !ok:
			d.missing = append(d.missing, k)
		case hv != want[k]:
			d.changed = append(d.changed, k)
		}
	}
	for _, k := range sortedKeys(have) {
		if _, ok := want[k]; !ok {
			d.extra = append(d.extra, k)
		}
	}
	return d
}

func (d diff) summary() string {
	var p []string
	if n := len(d.changed); n > 0 {
		p = append(p, fmt.Sprintf("%d changed", n))
	}
	if n := len(d.missing); n > 0 {
		p = append(p, fmt.Sprintf("%d missing", n))
	}
	if n := len(d.extra); n > 0 {
		p = append(p, fmt.Sprintf("%d extra", n))
	}
	return strings.Join(p, ", ")
}

// state is a target's current content and how it compares with what it should hold.
type state struct {
	t      *Target
	drv    Driver
	raw    []byte
	exists bool
	have   map[string]string
	want   map[string]string
	d      diff
}

func (e *env) inspect(a *App, t *Target) (*state, error) {
	drv, err := newDriver(t)
	if err != nil {
		return nil, err
	}
	raw, exists, err := drv.Read(e.ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", drv.Describe(), err)
	}
	want, err := e.desired(a, t)
	if err != nil {
		return nil, err
	}
	have := parseDoc(raw).values()
	return &state{t: t, drv: drv, raw: raw, exists: exists, have: have, want: want, d: compare(want, have)}, nil
}

// pickTargets resolves "APP [TARGET]" arguments.
func (c *Config) pick(args []string) (string, *App, []*Target, error) {
	if len(args) < 1 {
		return "", nil, nil, fmt.Errorf("app name required (known: %s)", strings.Join(c.appNames(), ", "))
	}
	a, ok := c.Apps[args[0]]
	if !ok {
		return "", nil, nil, fmt.Errorf("unknown app %q (known: %s)", args[0], strings.Join(c.appNames(), ", "))
	}
	if len(args) >= 2 {
		t, ok := a.Targets[args[1]]
		if !ok {
			return "", nil, nil, fmt.Errorf("app %q has no target %q (known: %s)", args[0], args[1], strings.Join(a.targetNames(), ", "))
		}
		return args[0], a, []*Target{t}, nil
	}
	var ts []*Target
	for _, n := range a.targetNames() {
		ts = append(ts, a.Targets[n])
	}
	return args[0], a, ts, nil
}

// confirm asks a yes/no question on stdin; end of input counts as no.
func confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y")
}
