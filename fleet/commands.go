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
	var jobs *int
	e, fs, err := setup("status", args, func(fs *flag.FlagSet) {
		check = fs.Bool("check", false, "exit 1 if anything is drifted or unreachable (for CI/cron)")
		jobs = fs.Int("j", defaultJobs, "targets to look at in parallel")
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
		var ts []*Target
		for _, tn := range a.targetNames() {
			ts = append(ts, a.Targets[tn])
		}
		fmt.Println(an)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, s := range e.status(a, ts, *jobs) {
			var line string
			switch s.State {
			case "error":
				line = "\u2717 " + s.Error
				bad = true
			case "missing":
				line = fmt.Sprintf("~ file missing (%d to create)", len(s.Missing)+len(s.Changed))
				bad = true
			case "drifted":
				line = "~ drifted: " + summaryOf(s)
				bad = true
			default:
				line = "\u2713 in sync"
				if len(s.Extra) > 0 {
					line = fmt.Sprintf("\u00b7 in sync (%d extra on the target)", len(s.Extra))
				}
			}
			if len(s.Stale) > 0 {
				line += fmt.Sprintf("; running app differs on %d (restart/recreate needed)", len(s.Stale))
				bad = true
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", s.Target, s.Driver, s.Where, line)
		}
		tw.Flush()
	}
	if *check && bad {
		return 1
	}
	return 0
}

func summaryOf(s TargetStatus) string {
	return diff{missing: s.Missing, changed: s.Changed, extra: s.Extra}.summary()
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
	var jobs *int
	e, fs, err := setup("push", args, func(fs *flag.FlagSet) {
		yes = fs.Bool("y", false, "don't ask for confirmation")
		dry = fs.Bool("dry-run", false, "show the plan and change nothing")
		prune = fs.Bool("prune", false, "also remove variables that are only on the target")
		reload = fs.Bool("reload", false, "run each target's reload command after a change")
		jobs = fs.Int("j", defaultJobs, "targets to process in parallel")
	})
	if err != nil {
		return fail(err)
	}
	_, a, targets, err := e.cfg.pick(fs.Args())
	if err != nil {
		return fail(err)
	}
	return e.push(a, targets, *yes, *dry, *prune, *reload, *jobs)
}

func (e *env) push(a *App, targets []*Target, yes, dry, prune, reload bool, jobs int) int {
	var todo []*state
	rc := 0
	for _, r := range e.inspectAll(a, targets, jobs) {
		fmt.Printf("%s/%s\n", r.T.app, r.T.name)
		if r.Err != nil {
			fmt.Printf("  \u2717 %v\n", r.Err)
			rc = 1
			continue
		}
		printDiff(r.St, false, prune)
		if r.St.d.empty() && !(prune && len(r.St.d.extra) > 0) {
			continue
		}
		todo = append(todo, r.St)
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
	for _, r := range e.apply(todo, prune, reload, jobs) {
		id := r.App + "/" + r.Target
		if r.Wrote {
			fmt.Printf("%s: wrote %s (previous kept as .bak)\n", id, r.Where)
		}
		switch r.Reload {
		case "ok":
			fmt.Printf("%s: reloaded\n", id)
		case "none":
			fmt.Printf("%s: no reload command configured\n", id)
		case "skipped":
			if r.Hint {
				fmt.Printf("%s: not reloaded (use -reload to run the reload command)\n", id)
			}
		}
		if r.Err != "" {
			fmt.Fprintf(os.Stderr, "%s: %s\n", id, r.Err)
			rc = 1
		}
	}
	return rc
}

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
	p, err := e.planPull(a, targets[0])
	if err != nil {
		return fail(err)
	}
	if p.Creating {
		fmt.Printf("vault item %q will be created\n", p.Item)
	}
	fmt.Printf("%s/%s -> vault item %q\n", p.T.app, p.T.name, p.Item)
	for _, k := range p.Add {
		fmt.Printf("  + %s\n", k)
	}
	for _, k := range p.Upd {
		fmt.Printf("  ~ %s\n", k)
	}
	if len(p.Changes) == 0 {
		fmt.Println("  vault already matches")
		return 0
	}
	if *dry {
		return 0
	}
	if !*yes && !confirm(fmt.Sprintf("Store %d variable(s) in the vault?", len(p.Changes))) {
		fmt.Fprintln(os.Stderr, "cancelled")
		return 1
	}
	if err := e.applyPull(p); err != nil {
		return fail(err)
	}
	fmt.Printf("stored %d variable(s) in %q\n", len(p.Changes), p.Item)
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
	return e.push(a, targets, true, false, false, false, defaultJobs)
}

func targetNames(ts []*Target) []string {
	var n []string
	for _, t := range ts {
		n = append(n, t.name)
	}
	return n
}
