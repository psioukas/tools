package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
)

func setup(name string, args []string, extra func(*flag.FlagSet)) (*env, *flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfgPath := fs.String("f", "", "path to apps.yaml (default: ./apps.yaml, $FLEET_CONFIG, ~/.config/fleet/apps.yaml)")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	cfg, err := loadConfig(configPath(*cfgPath))
	if err != nil {
		return nil, nil, err
	}
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)
	return &env{ctx: ctx, cfg: cfg, vault: newVault()}, fs, nil
}

func fail(err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	return 1
}

// ---- apps ---------------------------------------------------------------------------------------

func cmdApps(args []string) int {
	e, _, err := setup("apps", args, nil)
	if err != nil {
		return fail(err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	for _, an := range e.cfg.appNames() {
		a := e.cfg.Apps[an]
		fmt.Fprintf(tw, "%s\t(vault item %q)\n", an, a.VaultItem)
		for _, tn := range a.targetNames() {
			t := a.Targets[tn]
			drv, err := newDriver(t)
			where := "?"
			if err == nil {
				where = drv.Describe()
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t(item %q)\n", tn, t.Driver, where, t.item(a))
		}
	}
	tw.Flush()
	return 0
}

// ---- status ---------------------------------------------------------------------------------------

func cmdStatus(args []string) int {
	var check *bool
	e, fs, err := setup("status", args, func(fs *flag.FlagSet) {
		check = fs.Bool("check", false, "exit 1 if anything is drifted or unreachable (for CI/cron)")
	})
	if err != nil {
		return fail(err)
	}
	apps := e.cfg.appNames()
	if fs.NArg() > 0 {
		apps = fs.Args()
	}
	bad := false
	for _, an := range apps {
		a, ok := e.cfg.Apps[an]
		if !ok {
			return fail(fmt.Errorf("unknown app %q", an))
		}
		fmt.Println(an)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, tn := range a.targetNames() {
			t := a.Targets[tn]
			st, err := e.inspect(a, t)
			if err != nil {
				fmt.Fprintf(tw, "  %s\t%s\t✗ %v\n", tn, t.Driver, err)
				bad = true
				continue
			}
			line := "✓ in sync"
			switch {
			case !st.exists:
				line = fmt.Sprintf("~ file missing (%d to create)", len(st.want))
				bad = true
			case st.d.drifted():
				mark := "~"
				if st.d.empty() {
					mark = "·" // only extra keys on the target: informational
				} else {
					bad = true
				}
				line = fmt.Sprintf("%s drifted: %s", mark, st.d.summary())
			}
			if rc, ok := st.drv.(RuntimeChecker); ok {
				if names, err := rc.RuntimeDiffers(e.ctx, st.want); err == nil && len(names) > 0 {
					line += fmt.Sprintf("; running container differs on %d (restart/recreate needed)", len(names))
					bad = true
				}
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", tn, t.Driver, st.drv.Describe(), line)
		}
		tw.Flush()
	}
	if *check && bad {
		return 1
	}
	return 0
}

// ---- diff -----------------------------------------------------------------------------------------

func cmdDiff(args []string) int {
	var values *bool
	e, fs, err := setup("diff", args, func(fs *flag.FlagSet) {
		values = fs.Bool("values", false, "also show the values (secrets!)")
	})
	if err != nil {
		return fail(err)
	}
	_, a, targets, err := e.cfg.pick(fs.Args())
	if err != nil {
		return fail(err)
	}
	for _, t := range targets {
		fmt.Printf("%s/%s\n", t.app, t.name)
		st, err := e.inspect(a, t)
		if err != nil {
			fmt.Printf("  ✗ %v\n", err)
			continue
		}
		printDiff(st, *values, true)
	}
	return 0
}

func printDiff(st *state, values, showExtra bool) {
	show := func(sign, k string, old, nw string) {
		if values {
			fmt.Printf("  %s %s  %q -> %q\n", sign, k, old, nw)
		} else {
			fmt.Printf("  %s %s\n", sign, k)
		}
	}
	for _, k := range st.d.missing {
		show("+", k, "", st.want[k])
	}
	for _, k := range st.d.changed {
		show("~", k, st.have[k], st.want[k])
	}
	if showExtra {
		for _, k := range st.d.extra {
			show("-", k, st.have[k], "")
		}
	}
	if !st.d.drifted() {
		fmt.Println("  in sync")
	} else if len(st.d.extra) > 0 && showExtra {
		fmt.Println("  (- = only on the target; kept unless you push with -prune)")
	}
}

// ---- push -----------------------------------------------------------------------------------------

func cmdPush(args []string) int {
	var yes, dry, prune, reload *bool
	e, fs, err := setup("push", args, func(fs *flag.FlagSet) {
		yes = fs.Bool("y", false, "don't ask for confirmation")
		dry = fs.Bool("dry-run", false, "show the plan and change nothing")
		prune = fs.Bool("prune", false, "also remove variables that are only on the target")
		reload = fs.Bool("reload", false, "run each target's reload command after a change")
	})
	if err != nil {
		return fail(err)
	}
	_, a, targets, err := e.cfg.pick(fs.Args())
	if err != nil {
		return fail(err)
	}
	return e.push(a, targets, *yes, *dry, *prune, *reload)
}

func (e *env) push(a *App, targets []*Target, yes, dry, prune, reload bool) int {
	var todo []*state
	rc := 0
	for _, t := range targets {
		fmt.Printf("%s/%s\n", t.app, t.name)
		st, err := e.inspect(a, t)
		if err != nil {
			fmt.Printf("  ✗ %v\n", err)
			rc = 1
			continue
		}
		printDiff(st, false, prune)
		if st.d.empty() && !(prune && len(st.d.extra) > 0) {
			continue
		}
		todo = append(todo, st)
	}
	if len(todo) == 0 {
		fmt.Println("nothing to push")
		return rc
	}
	if dry {
		fmt.Printf("dry run: %d target(s) would change\n", len(todo))
		return rc
	}
	if !yes && !confirm(fmt.Sprintf("Apply to %d target(s)?", len(todo))) {
		fmt.Fprintln(os.Stderr, "cancelled")
		return 1
	}
	for _, st := range todo {
		t := st.t
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
			fmt.Fprintf(os.Stderr, "%s/%s: write failed: %v\n", t.app, t.name, err)
			rc = 1
			continue
		}
		fmt.Printf("%s/%s: wrote %s (previous kept as .bak)\n", t.app, t.name, st.drv.Describe())
		switch err := func() error {
			if !reload {
				return errSkipped
			}
			return st.drv.Reload(e.ctx)
		}(); {
		case err == nil:
			fmt.Printf("%s/%s: reloaded\n", t.app, t.name)
		case err == errSkipped:
			if t.Reload != "" || t.Service != "" || t.Container != "" {
				fmt.Printf("%s/%s: not reloaded (use -reload to run the reload command)\n", t.app, t.name)
			}
		case err == errNoReload:
			fmt.Printf("%s/%s: no reload command configured\n", t.app, t.name)
		default:
			fmt.Fprintf(os.Stderr, "%s/%s: reload failed: %v\n", t.app, t.name, err)
			rc = 1
		}
	}
	return rc
}

var errSkipped = fmt.Errorf("skipped")

// ---- pull -----------------------------------------------------------------------------------------

func cmdPull(args []string) int {
	var yes, dry *bool
	e, fs, err := setup("pull", args, func(fs *flag.FlagSet) {
		yes = fs.Bool("y", false, "don't ask for confirmation")
		dry = fs.Bool("dry-run", false, "show the plan and change nothing")
	})
	if err != nil {
		return fail(err)
	}
	if fs.NArg() != 2 {
		return fail(fmt.Errorf("usage: fleet pull APP TARGET"))
	}
	_, a, targets, err := e.cfg.pick(fs.Args())
	if err != nil {
		return fail(err)
	}
	t := targets[0]
	drv, err := newDriver(t)
	if err != nil {
		return fail(err)
	}
	raw, exists, err := drv.Read(e.ctx)
	if err != nil {
		return fail(fmt.Errorf("cannot read %s: %w", drv.Describe(), err))
	}
	if !exists {
		return fail(fmt.Errorf("%s does not exist", drv.Describe()))
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
	item := t.item(a)
	current, err := e.vault.get(item)
	if err == errItemMissing {
		current, err = map[string]string{}, nil
		fmt.Printf("vault item %q will be created\n", item)
	}
	if err != nil {
		return fail(err)
	}
	var add, upd []string
	changes := map[string]string{}
	for _, k := range sortedKeys(incoming) {
		cv, ok := current[k]
		switch {
		case !ok:
			add = append(add, k)
			changes[k] = incoming[k]
		case cv != incoming[k]:
			upd = append(upd, k)
			changes[k] = incoming[k]
		}
	}
	fmt.Printf("%s/%s -> vault item %q\n", t.app, t.name, item)
	for _, k := range add {
		fmt.Printf("  + %s\n", k)
	}
	for _, k := range upd {
		fmt.Printf("  ~ %s\n", k)
	}
	if len(changes) == 0 {
		fmt.Println("  vault already matches")
		return 0
	}
	if *dry {
		return 0
	}
	if !*yes && !confirm(fmt.Sprintf("Store %d variable(s) in the vault?", len(changes))) {
		fmt.Fprintln(os.Stderr, "cancelled")
		return 1
	}
	if err := e.vault.set(item, changes); err != nil {
		return fail(err)
	}
	fmt.Printf("stored %d variable(s) in %q\n", len(changes), item)
	return 0
}

// ---- edit -----------------------------------------------------------------------------------------

func cmdEdit(args []string) int {
	var pushAfter *bool
	e, fs, err := setup("edit", args, func(fs *flag.FlagSet) {
		pushAfter = fs.Bool("push", false, "push to the app's targets afterwards without asking")
	})
	if err != nil {
		return fail(err)
	}
	_, a, targets, err := e.cfg.pick(fs.Args())
	if err != nil {
		return fail(err)
	}
	item := targets[0].item(a)
	if fs.NArg() < 2 { // whole app: edit the app-level item
		item = a.VaultItem
	}
	return e.editItem(a, targets, item, *pushAfter)
}

func (e *env) editItem(a *App, targets []*Target, item string, pushAfter bool) int {
	vals, err := e.vault.get(item)
	if err == errItemMissing {
		vals, err = map[string]string{}, nil
		fmt.Fprintf(os.Stderr, "vault item %q does not exist yet; it will be created if you save variables\n", item)
	}
	if err != nil {
		return fail(err)
	}
	dir, err := os.MkdirTemp("", "fleet-edit-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)
	path := dir + "/.env"
	var d doc
	for _, k := range sortedKeys(vals) {
		d.set(k, vals[k])
	}
	if err := os.WriteFile(path, d.bytes(), 0o600); err != nil {
		return fail(err)
	}
	bin := os.Getenv("FLEET_ENVGEN")
	if bin == "" {
		bin = "env-gen"
	}
	fmt.Fprintf(os.Stderr, "editing vault item %q (changes are stored in the vault when you save)\n", item)
	cmd := execCommand(bin, "edit", "-no-backup", path)
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "editor closed without saving; the vault is unchanged")
		return 1
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fail(err)
	}
	after := parseDoc(b).values()
	var changes = map[string]string{}
	var removed []string
	for _, k := range sortedKeys(after) {
		if ov, ok := vals[k]; !ok || ov != after[k] {
			changes[k] = after[k]
		}
	}
	for _, k := range sortedKeys(vals) {
		if _, ok := after[k]; !ok {
			removed = append(removed, k)
		}
	}
	if len(changes)+len(removed) == 0 {
		fmt.Println("no changes")
		return 0
	}
	if len(changes) > 0 {
		if err := e.vault.set(item, changes); err != nil {
			return fail(err)
		}
	}
	if len(removed) > 0 {
		if err := e.vault.remove(item, removed); err != nil {
			return fail(err)
		}
	}
	fmt.Printf("vault item %q updated: %d added/changed, %d removed\n", item, len(changes), len(removed))
	if !pushAfter && !confirm("Push to "+strings.Join(targetNames(targets), ", ")+" now?") {
		fmt.Println("not pushed; run `fleet push` when ready")
		return 0
	}
	return e.push(a, targets, true, false, false, false)
}

func targetNames(ts []*Target) []string {
	var n []string
	for _, t := range ts {
		n = append(n, t.name)
	}
	return n
}
