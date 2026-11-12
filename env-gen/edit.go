package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

// envDoc is a .env file held as raw lines, so comments, blank lines, order and
// `export` prefixes survive edits.
type envDoc struct{ lines []string }

func loadDoc(path string) (*envDoc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return &envDoc{}, nil
	}
	return &envDoc{lines: strings.Split(s, "\n")}, nil
}

// entry parses a raw line into key, raw value and prefix ("export " or "").
func entry(line string) (key, raw, prefix string, ok bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return
	}
	if strings.HasPrefix(t, "export ") {
		prefix, t = "export ", strings.TrimSpace(strings.TrimPrefix(t, "export "))
	}
	k, v, found := strings.Cut(t, "=")
	k = strings.TrimSpace(k)
	if !found || !keyRe.MatchString(k) {
		return "", "", "", false
	}
	return k, strings.TrimSpace(v), prefix, true
}

func (d *envDoc) find(key string) int {
	idx := -1
	for i, l := range d.lines {
		if k, _, _, ok := entry(l); ok && k == key {
			idx = i
		}
	}
	return idx
}

func (d *envDoc) get(key string) (string, bool) {
	if i := d.find(key); i >= 0 {
		_, raw, _, _ := entry(d.lines[i])
		return parseValue(raw), true
	}
	return "", false
}

// set stores an already-quoted value, replacing the line or appending a new one.
func (d *envDoc) set(key, quoted string) {
	if i := d.find(key); i >= 0 {
		_, raw, prefix, _ := entry(d.lines[i])
		d.lines[i] = prefix + key + "=" + quoted + trailingComment(raw)
		return
	}
	d.lines = append(d.lines, key+"="+quoted)
}

// trailingComment returns the " # ..." tail of a raw value, so edits keep inline comments.
func trailingComment(raw string) string {
	rest := raw
	if raw != "" && (raw[0] == '"' || raw[0] == '\'') {
		q, i := raw[0], 1
		for i < len(raw) {
			if raw[i] == '\\' && q == '"' {
				i += 2
				continue
			}
			if raw[i] == q {
				break
			}
			i++
		}
		if i >= len(raw) {
			return ""
		}
		rest = raw[i+1:]
	}
	if j := strings.Index(rest, " #"); j >= 0 {
		return rest[j:]
	}
	return ""
}

func (d *envDoc) del(key string) {
	var out []string
	for _, l := range d.lines {
		if k, _, _, ok := entry(l); ok && k == key {
			continue
		}
		out = append(out, l)
	}
	d.lines = out
}

func (d *envDoc) rename(old, nw string) {
	if i := d.find(old); i >= 0 {
		_, raw, prefix, _ := entry(d.lines[i])
		d.lines[i] = prefix + nw + "=" + raw
	}
}

func (d *envDoc) keys() []string {
	var ks []string
	seen := map[string]bool{}
	for _, l := range d.lines {
		if k, _, _, ok := entry(l); ok && !seen[k] {
			seen[k] = true
			ks = append(ks, k)
		}
	}
	return ks
}

func (d *envDoc) String() string { return strings.Join(d.lines, "\n") + "\n" }

func (d *envDoc) values() map[string]string {
	m := map[string]string{}
	for _, k := range d.keys() {
		m[k], _ = d.get(k)
	}
	return m
}

// resolve turns "value or placeholder" into a final, quoted dotenv value.
func resolve(res Resolver, key, value string) (string, error) {
	out, err := renderLines([]string{key + "=" + value}, res)
	if err != nil {
		return "", err
	}
	_, v, _ := strings.Cut(strings.TrimSuffix(out, "\n"), "=")
	return v, nil
}

func display(key, val string) string {
	if secretKeyRe.MatchString(key) && val != "" {
		return "••••••••"
	}
	if len(val) > 40 {
		return val[:37] + "..."
	}
	return val
}

// runEdit edits an existing env file in place. With -set/-unset it runs without
// prompts; otherwise it opens a menu. Comments and ordering are preserved, the
// previous file is kept as FILE.bak, and every variable can be backed up to the vault.
func runEdit(res *cliResolver, file string, sets, unsets []string, backup string, dry bool) int {
	if file == "" {
		if len(sets)+len(unsets) > 0 {
			file = ".env"
		} else {
			f, code := pickEnvFile()
			if code != 0 {
				return code
			}
			file = f
		}
	}
	doc, err := loadDoc(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v (use `env-gen new` to create one)\n", err)
		return 1
	}
	orig := doc.values()
	project := projectName()

	if len(sets)+len(unsets) > 0 {
		for _, s := range sets {
			k, v, ok := strings.Cut(s, "=")
			k = strings.TrimSpace(k)
			if !ok || !keyRe.MatchString(k) {
				fmt.Fprintf(os.Stderr, "error: bad -set %q (want KEY=VALUE)\n", s)
				return 2
			}
			q, err := resolve(res, k, v)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
			doc.set(k, q)
		}
		for _, k := range unsets {
			doc.del(k)
		}
	} else if code := editMenu(res, doc, project, orig, file); code != 0 {
		return code
	}

	final := doc.values()
	var summary []string
	for _, k := range doc.keys() {
		if v, had := orig[k]; !had {
			summary = append(summary, "  + "+k)
		} else if v != final[k] {
			summary = append(summary, "  ~ "+k)
		}
	}
	for k := range orig {
		if _, still := final[k]; !still {
			summary = append(summary, "  - "+k)
		}
	}
	if len(summary) == 0 {
		fmt.Fprintln(os.Stderr, "no changes")
		return 0
	}
	fmt.Fprintf(os.Stderr, "\nChanges to %s:\n%s\n", file, strings.Join(summary, "\n"))

	if len(sets)+len(unsets) == 0 { // interactive: confirm + vault backup choice
		ok := false
		fields := []huh.Field{}
		if !offline && !noBackup {
			if backup == "" {
				backup = project
			}
			fields = append(fields, huh.NewInput().Title("Back up ALL variables to this vault item").Description("leave empty to skip").Value(&backup))
		}
		fields = append(fields, huh.NewConfirm().Title("Save changes?").Affirmative("Save").Negative("Discard").Value(&ok))
		if err := newForm(huh.NewGroup(fields...)).Run(); err != nil {
			return abort(err)
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "discarded")
			return 1
		}
	}
	if backup != "" && !offline {
		if err := backupContent(res.bw, strings.TrimSpace(backup), doc.String(), dry); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	if dry {
		fmt.Printf("# --- %s ---\n%s", file, doc.String())
		return 0
	}
	if old, err := os.ReadFile(file); err == nil {
		_ = os.WriteFile(file+".bak", old, 0o600)
	}
	if err := os.WriteFile(file, []byte(doc.String()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "saved %s (previous version: %s.bak)\n", file, file)
	return 0
}

// envCandidates lists .env-style files in the current directory, ".env" first.
func envCandidates() []string {
	ents, err := os.ReadDir(".")
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range ents {
		if !d.IsDir() && isEnvName(d.Name()) {
			out = append(out, d.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i] == ".env") != (out[j] == ".env") {
			return out[i] == ".env"
		}
		return out[i] < out[j]
	})
	return out
}

// pickEnvFile asks which env file in the current directory to edit.
func pickEnvFile() (string, int) {
	files := envCandidates()
	switch len(files) {
	case 0:
		fmt.Fprintln(os.Stderr, "no .env files in this directory (use `env-gen new` to create one, or pass a path)")
		return "", 1
	case 1:
		fmt.Fprintf(os.Stderr, "editing %s\n", files[0])
		return files[0], 0
	}
	opts := make([]huh.Option[string], len(files))
	for i, f := range files {
		n := "?"
		if ps, err := parseEnv(f); err == nil {
			n = fmt.Sprint(len(ps))
		}
		opts[i] = huh.NewOption(fmt.Sprintf("%-28s %s variables", f, n), f)
	}
	choice := files[0]
	if err := newForm(huh.NewGroup(huh.NewSelect[string]().Title("Which file do you want to edit?").
		Options(opts...).Height(minInt(len(opts)+2, 14)).Value(&choice))).Run(); err != nil {
		return "", abort(err)
	}
	return choice, 0
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// varLabel renders one variable as KEY="value". Secret-looking values are masked
// until "Show secret values" is switched on.
func varLabel(key, val string, reveal bool, orig map[string]string) string {
	shown := val
	if secretKeyRe.MatchString(key) && val != "" && !reveal {
		shown = "••••••••"
	}
	if r := []rune(shown); len(r) > 60 {
		shown = string(r[:57]) + "..."
	}
	label := key + "=" + strconv.Quote(shown)
	if ov, had := orig[key]; !had {
		label += "   (new)"
	} else if ov != val {
		label += "   (modified)"
	}
	return label
}

func nextChoice(keys []string, deleted string) string {
	for i, k := range keys {
		if k == deleted {
			if i+1 < len(keys) {
				return "k:" + keys[i+1]
			}
			if i > 0 {
				return "k:" + keys[i-1]
			}
		}
	}
	return "save"
}

func editMenu(res *cliResolver, doc *envDoc, project string, orig map[string]string, file string) int {
	reveal := false
	choice := "save"
	if ks := doc.keys(); len(ks) > 0 {
		choice = "k:" + ks[0]
	}
	for {
		keys, cur := doc.keys(), doc.values()
		opts := make([]huh.Option[string], 0, len(keys)+4)
		for _, k := range keys {
			opts = append(opts, huh.NewOption(varLabel(k, cur[k], reveal, orig), "k:"+k))
		}
		toggle := "Show secret values"
		if reveal {
			toggle = "Hide secret values"
		}
		opts = append(opts,
			huh.NewOption("+ Add a variable", "add"),
			huh.NewOption(toggle, "reveal"),
			huh.NewOption("Done (review and save)", "save"),
			huh.NewOption("Quit without saving", "quit"))
		if err := newForm(huh.NewGroup(huh.NewSelect[string]().
			Title(fmt.Sprintf("%s: %d variables", file, len(keys))).
			Description("↑/↓ move · enter select · / filter").
			Options(opts...).Height(minInt(len(opts)+3, 18)).Value(&choice))).Run(); err != nil {
			return abort(err)
		}
		switch {
		case choice == "save":
			return 0
		case choice == "quit":
			fmt.Fprintln(os.Stderr, "quit without saving")
			return 1
		case choice == "reveal":
			reveal = !reveal
		case choice == "add":
			var key, source string
			if err := newForm(huh.NewGroup(
				huh.NewInput().Title("Variable name").Value(&key).Validate(validKey),
				huh.NewSelect[string]().Title("Value source").Options(sourceOptions(false)...).Value(&source),
			)).Run(); err != nil {
				return abort(err)
			}
			if code := changeValue(res, doc, key, source, project, ""); code != 0 {
				return code
			}
			choice = "k:" + key
		default:
			key := strings.TrimPrefix(choice, "k:")
			if code := editVariable(res, doc, key, cur[key], reveal, orig, project, keys, &choice); code != 0 {
				return code
			}
		}
	}
}

// editVariable is the per-variable menu: edit inline, enter a new value, use a
// generated/vault value, rename or delete.
func editVariable(res *cliResolver, doc *envDoc, key, val string, reveal bool, orig map[string]string, project string, keys []string, choice *string) int {
	action := "inline"
	secret := secretKeyRe.MatchString(key)
	srcOpts := []huh.Option[string]{huh.NewOption("Generate random", "gen")}
	if !offline {
		srcOpts = append(srcOpts, huh.NewOption("Read from Vaultwarden", "vw"),
			huh.NewOption("Vaultwarden: read, or generate + store if missing", "vwgen"))
	}
	if err := newForm(huh.NewGroup(huh.NewSelect[string]().
		Title(varLabel(key, val, reveal, orig)).
		Options(
			huh.NewOption("Edit inline (change the current value in place)", "inline"),
			huh.NewOption("Enter a new value", "new"),
			huh.NewOption("Generate or take from the vault…", "source"),
			huh.NewOption("Rename the variable", "rename"),
			huh.NewOption("Delete this entry", "delete"),
			huh.NewOption("Back", "back")).
		Value(&action))).Run(); err != nil {
		return abort(err)
	}
	switch action {
	case "inline":
		nv := val
		if err := newForm(huh.NewGroup(huh.NewInput().Title("Edit " + key).
			Description("change the value in place; enter to confirm").Value(&nv))).Run(); err != nil {
			return abort(err)
		}
		if nv != val {
			doc.set(key, quoteIfNeeded(nv))
		}
	case "new":
		var nv string
		in := huh.NewInput().Title("New value for " + key).Value(&nv)
		if secret {
			in = in.EchoMode(huh.EchoModePassword).Description("hidden while typing")
		}
		if err := newForm(huh.NewGroup(in)).Run(); err != nil {
			return abort(err)
		}
		doc.set(key, quoteIfNeeded(nv))
	case "source":
		var source string
		if err := newForm(huh.NewGroup(huh.NewSelect[string]().Title("New value for " + key).Options(srcOpts...).Value(&source))).Run(); err != nil {
			return abort(err)
		}
		return changeValue(res, doc, key, source, project, val)
	case "rename":
		nw := key
		if err := newForm(huh.NewGroup(huh.NewInput().Title("New name").Value(&nw).Validate(validKey))).Run(); err != nil {
			return abort(err)
		}
		if nw != key {
			doc.rename(key, nw)
			*choice = "k:" + nw
		}
	case "delete":
		ok := false
		if err := newForm(huh.NewGroup(huh.NewConfirm().Title("Delete " + key + "?").
			Affirmative("Delete").Negative("Keep").Value(&ok))).Run(); err != nil {
			return abort(err)
		}
		if ok {
			doc.del(key)
			*choice = nextChoice(keys, key)
		}
	}
	return 0
}

// changeValue asks for a new value from the chosen source and applies it.
// A failure (for example a locked vault) is reported and the menu continues.
func changeValue(res *cliResolver, doc *envDoc, key, source, project, current string) int {
	v, _, err := askValue(res, key, source, project, current)
	if err != nil {
		return abort(err)
	}
	q, err := resolve(res, key, v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not set %s: %v\n", key, err)
		return 0
	}
	doc.set(key, q)
	return 0
}
