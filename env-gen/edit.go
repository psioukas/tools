package main

import (
	"fmt"
	"os"
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
		_, _, prefix, _ := entry(d.lines[i])
		d.lines[i] = prefix + key + "=" + quoted
		return
	}
	d.lines = append(d.lines, key+"="+quoted)
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
	} else if code := editMenu(res, doc, project); code != 0 {
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
		if !offline {
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

func editMenu(res *cliResolver, doc *envDoc, project string) int {
	choice := "save"
	if ks := doc.keys(); len(ks) > 0 {
		choice = "k:" + ks[0]
	}
	for {
		var opts []huh.Option[string]
		orig := doc.values()
		for _, k := range doc.keys() {
			opts = append(opts, huh.NewOption(fmt.Sprintf("%-26s %s", k, display(k, orig[k])), "k:"+k))
		}
		opts = append(opts,
			huh.NewOption("+ Add a variable", "add"),
			huh.NewOption("Done (review and save)", "save"),
			huh.NewOption("Quit without saving", "quit"))
		if err := newForm(huh.NewGroup(huh.NewSelect[string]().Title("Edit variables").Options(opts...).Value(&choice))).Run(); err != nil {
			return abort(err)
		}
		switch {
		case choice == "save":
			return 0
		case choice == "quit":
			fmt.Fprintln(os.Stderr, "quit without saving")
			return 1
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
		default:
			key := strings.TrimPrefix(choice, "k:")
			action := "change"
			if err := newForm(huh.NewGroup(huh.NewSelect[string]().Title(key).Options(
				huh.NewOption("Change value", "change"),
				huh.NewOption("Rename", "rename"),
				huh.NewOption("Delete", "delete"),
				huh.NewOption("Back", "back")).Value(&action))).Run(); err != nil {
				return abort(err)
			}
			switch action {
			case "change":
				var source string
				if err := newForm(huh.NewGroup(huh.NewSelect[string]().Title("New value for " + key).Options(sourceOptions(false)...).Value(&source))).Run(); err != nil {
					return abort(err)
				}
				cur, _ := doc.get(key)
				if code := changeValue(res, doc, key, source, project, cur); code != 0 {
					return code
				}
			case "rename":
				nw := key
				if err := newForm(huh.NewGroup(huh.NewInput().Title("New name").Value(&nw).Validate(validKey))).Run(); err != nil {
					return abort(err)
				}
				doc.rename(key, nw)
			case "delete":
				ok := false
				if err := newForm(huh.NewGroup(huh.NewConfirm().Title("Delete " + key + "?").Value(&ok))).Run(); err != nil {
					return abort(err)
				}
				if ok {
					doc.del(key)
				}
			}
		}
	}
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
