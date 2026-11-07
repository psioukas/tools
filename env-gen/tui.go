package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

func newForm(groups ...*huh.Group) *huh.Form {
	f := huh.NewForm(groups...).WithOutput(os.Stderr) // keep stdout clean for eval "$(env-gen setup)"
	if os.Getenv("ACCESSIBLE") != "" {                // plain line prompts, used for scripted tests
		f = f.WithAccessible(true)
	}
	return f
}

func validLen(s string) error {
	if n, err := strconv.Atoi(s); err != nil || n <= 0 {
		return errors.New("positive number required")
	}
	return nil
}

func validKey(s string) error {
	if !keyRe.MatchString(s) {
		return errors.New("use letters, digits, underscore; not starting with a digit")
	}
	return nil
}

// pickVaultItem offers recently used items first, then lets the user search the
// vault or type a name.
func pickVaultItem(bw *Bw) (item string, fields []string, err error) {
	std := []string{"password", "username", "uri", "notes"}
	fields = append([]string{}, std...)
	mode := "search"
	if recent := loadRecent(); len(recent) > 0 {
		opts := make([]huh.Option[string], 0, len(recent)+2)
		for _, r := range recent {
			label := r.Name
			if len(r.Fields) > 0 {
				label += "  (" + strings.Join(r.Fields, ", ") + ")"
			}
			opts = append(opts, huh.NewOption(label, "r:"+r.Name))
		}
		opts = append(opts, huh.NewOption("Search the vault…", "search"), huh.NewOption("Type a name", "type"))
		choice := opts[0].Value
		if err = newForm(huh.NewGroup(huh.NewSelect[string]().Title("Vault item (recent first)").Options(opts...).Value(&choice))).Run(); err != nil {
			return
		}
		if strings.HasPrefix(choice, "r:") {
			item = strings.TrimPrefix(choice, "r:")
			for _, r := range recent {
				if r.Name == item {
					for _, f := range r.Fields {
						if !containsStr(fields, f) {
							fields = append(fields, f)
						}
					}
				}
			}
			recordItem(item)
			return
		}
		mode = choice
	}
	var search string
	if bw.Session != "" && mode == "search" {
		if err = newForm(huh.NewGroup(huh.NewInput().Title("Search vault (blank to type a name)").Value(&search))).Run(); err != nil {
			return
		}
	}
	if search != "" {
		items, lerr := bw.Search(search)
		if lerr == nil && len(items) > 0 {
			opts := make([]huh.Option[string], len(items))
			for i, it := range items {
				opts[i] = huh.NewOption(it.Name, it.Name)
			}
			if err = newForm(huh.NewGroup(huh.NewSelect[string]().Title("Vault item").Options(opts...).Value(&item))).Run(); err != nil {
				return
			}
			for _, it := range items {
				if it.Name == item {
					for _, f := range it.Fields {
						fields = append(fields, f.Name)
					}
				}
			}
			recordItem(item)
			return
		}
		fmt.Fprintln(os.Stderr, "no matches (or search failed); type the name instead")
	}
	err = newForm(huh.NewGroup(huh.NewInput().Title("Vault item name").Value(&item).
		Validate(func(s string) error {
			if s == "" {
				return errors.New("required")
			}
			return nil
		}))).Run()
	if err == nil {
		recordItem(item)
	}
	return
}

var secretKeyRe = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|_key$|^key$|salt|jwt|credential)`)

var exampleNames = []string{".env.example", ".env.sample", ".env.dist", "example.env", ".env.template.example"}

func findExample() string {
	for _, n := range exampleNames {
		if st, err := os.Stat(n); err == nil && !st.IsDir() {
			return n
		}
	}
	return ""
}

func projectName() string {
	wd, err := os.Getwd()
	if err != nil {
		return "project"
	}
	return filepath.Base(wd)
}

func charsetOptions() []huh.Option[string] {
	return []huh.Option[string]{huh.NewOption("alphanumeric", "alnum"), huh.NewOption("hex", "hex"), huh.NewOption("with symbols", "symbols")}
}

// suggest returns the source runNew proposes for a variable from an example file.
func suggest(key string) string {
	if secretKeyRe.MatchString(key) {
		if offline {
			return "gen"
		}
		return "vwgen"
	}
	return "keep"
}

// quickValue is the non-interactive value for a suggested source.
func quickValue(key, example, project, source string) (value, tpl string) {
	if source == "vwgen" || source == "gen" {
		n, cs := genDefaults()
		v := fmt.Sprintf("{{vwgen:%s/%s:%s:%s}}", project, key, n, cs)
		if source == "gen" {
			v = fmt.Sprintf("{{gen:%s:%s}}", n, cs)
		}
		return v, v
	}
	return example, quoteIfNeeded(example)
}

// askValue prompts for the details of one variable and returns the value used
// for the env line plus the value that goes into a saved template. project and
// example are set when building from an example file.
func askValue(res *cliResolver, key, source, project, example string) (value, tplValue string, err error) {
	switch source {
	case "keep":
		return example, quoteIfNeeded(example), nil
	case "literal", "secret":
		value = example
		in := huh.NewInput().Title("Value for " + key).Value(&value).Validate(noPlaceholder)
		if source == "secret" {
			value = ""
			in = in.EchoMode(huh.EchoModePassword)
		}
		if err = newForm(huh.NewGroup(in)).Run(); err != nil {
			return
		}
		tplValue = quoteIfNeeded(value)
		if source == "secret" {
			tplValue = "{{prompt:" + key + "}}" // never write typed secrets into a template
		}
		return
	case "gen":
		n, cs := genDefaults()
		if err = newForm(huh.NewGroup(
			huh.NewInput().Title("Length").Value(&n).Validate(validLen),
			huh.NewSelect[string]().Title("Charset").Options(charsetOptions()...).Value(&cs),
		)).Run(); err != nil {
			return
		}
		value = fmt.Sprintf("{{gen:%s:%s}}", n, cs)
		return value, value, nil
	case "vw", "vwgen":
		var item string
		field := "password"
		fields := []string{"password", "username", "uri", "notes"}
		if source == "vwgen" && project != "" {
			item, field = project, key
		} else if item, fields, err = pickVaultItem(res.bw); err != nil {
			return
		}
		var fs []huh.Field
		if source == "vwgen" {
			n, cs := genDefaults()
			if project != "" {
				fs = append(fs, huh.NewInput().Title("Vault item").Value(&item))
			}
			fs = append(fs,
				huh.NewInput().Title("Field (password, notes, or custom name)").Value(&field),
				huh.NewInput().Title("Length").Value(&n).Validate(validLen),
				huh.NewSelect[string]().Title("Charset").Options(charsetOptions()...).Value(&cs))
			if err = newForm(huh.NewGroup(fs...)).Run(); err != nil {
				return
			}
			value = fmt.Sprintf("{{vwgen:%s/%s:%s:%s}}", item, field, n, cs)
		} else {
			opts := make([]huh.Option[string], len(fields))
			for i, f := range fields {
				opts[i] = huh.NewOption(f, f)
			}
			if err = newForm(huh.NewGroup(huh.NewSelect[string]().Title("Field").Options(opts...).Value(&field))).Run(); err != nil {
				return
			}
			value = fmt.Sprintf("{{vw:%s/%s}}", item, field)
		}
		return value, value, nil
	}
	return "", "", fmt.Errorf("unknown source %q", source)
}

func sourceOptions(fromExample bool) []huh.Option[string] {
	var o []huh.Option[string]
	if fromExample {
		o = append(o, huh.NewOption("Keep the example value", "keep"), huh.NewOption("Skip this variable", "skip"))
	}
	o = append(o,
		huh.NewOption("Literal value", "literal"),
		huh.NewOption("Literal secret (hidden input)", "secret"),
		huh.NewOption("Generate random", "gen"))
	if offline {
		return o
	}
	return append(o,
		huh.NewOption("Read from Vaultwarden", "vw"),
		huh.NewOption("Vaultwarden: read, or generate + store if missing", "vwgen"))
}

// addManual loops asking for variables by hand.
func addManual(res *cliResolver) (lines, tpl []string, err error) {
	for {
		var key, source string
		if err = newForm(huh.NewGroup(
			huh.NewInput().Title("Variable name").Value(&key).Validate(validKey),
			huh.NewSelect[string]().Title("Value source").Options(sourceOptions(false)...).Value(&source),
		)).Run(); err != nil {
			return
		}
		v, t, aerr := askValue(res, key, source, "", "")
		if aerr != nil {
			return lines, tpl, aerr
		}
		lines = append(lines, key+"="+v)
		tpl = append(tpl, key+"="+t)
		var again bool
		if err = newForm(huh.NewGroup(huh.NewConfirm().Title("Add another variable?").Value(&again))).Run(); err != nil || !again {
			return
		}
	}
}

// fromExample builds the plan for every variable in an example file.
func fromExample(res *cliResolver, path string) (lines, tpl []string, err error) {
	pairs, err := parseEnv(path)
	if err != nil {
		return
	}
	if len(pairs) == 0 {
		return nil, nil, fmt.Errorf("%s has no variables", path)
	}
	project := projectName()
	fmt.Fprintf(os.Stderr, "\nUsing %s (%d variables). Suggestions:\n", path, len(pairs))
	for _, p := range pairs {
		src := suggest(p.Key)
		if src == "gen" {
			fmt.Fprintf(os.Stderr, "  %-28s generate (one-time, not stored)\n", p.Key)
		} else if src == "vwgen" {
			fmt.Fprintf(os.Stderr, "  %-28s generate + store in vault item %q\n", p.Key, project)
		} else {
			fmt.Fprintf(os.Stderr, "  %-28s keep example value (%s)\n", p.Key, orNone(p.Value))
		}
	}
	mode := "accept"
	if err = newForm(huh.NewGroup(huh.NewSelect[string]().Title("How do you want to fill these in?").Options(
		huh.NewOption("Accept the suggestions", "accept"),
		huh.NewOption("Customize each variable", "custom"),
		huh.NewOption("Cancel", "cancel")).Value(&mode))).Run(); err != nil {
		return
	}
	if mode == "cancel" {
		return nil, nil, huh.ErrUserAborted
	}
	for _, p := range pairs {
		source := suggest(p.Key)
		var v, t string
		if mode == "custom" {
			if err = newForm(huh.NewGroup(huh.NewSelect[string]().
				Title(fmt.Sprintf("%s  (example: %s)", p.Key, orNone(p.Value))).
				Options(sourceOptions(true)...).Value(&source))).Run(); err != nil {
				return
			}
			if source == "skip" {
				continue
			}
			if v, t, err = askValue(res, p.Key, source, project, p.Value); err != nil {
				return
			}
		} else {
			v, t = quickValue(p.Key, p.Value, project, source)
		}
		lines = append(lines, p.Key+"="+v)
		tpl = append(tpl, p.Key+"="+t)
	}
	return
}

// runNew is the interactive builder. It assembles template lines, shows them
// (never resolved secrets), optionally saves them as a template, then renders.
// If an example file (.env.example, ...) is present it is the starting point.
func runNew(res *cliResolver, out string, force, dry bool, from string, blank bool) int {
	var lines, tplLines []string
	var err error
	if from == "" && !blank {
		from = findExample()
	}
	if from != "" {
		if lines, tplLines, err = fromExample(res, from); err != nil {
			return abort(err)
		}
		var more bool
		if err = newForm(huh.NewGroup(huh.NewConfirm().Title("Add more variables by hand?").Value(&more))).Run(); err != nil {
			return abort(err)
		}
		if more {
			l, t, merr := addManual(res)
			lines, tplLines = append(lines, l...), append(tplLines, t...)
			if merr != nil {
				return abort(merr)
			}
		}
	} else {
		if lines, tplLines, err = addManual(res); err != nil {
			return abort(err)
		}
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "nothing to write")
		return 1
	}

	saveTpl := false
	backup := projectName() // empty = no backup
	if offline {
		backup = ""
	}
	fmt.Fprintf(os.Stderr, "\nPlan (secrets are resolved only when written):\n  %s\n\n", strings.Join(tplLines, "\n  "))
	var proceed bool
	fields := []huh.Field{huh.NewInput().Title("Output file").Value(&out)}
	if !offline {
		fields = append(fields, huh.NewInput().Title("Back up ALL variables to this vault item").Description("a duplicate of every value is kept in the vault; leave empty to skip").Value(&backup))
	}
	fields = append(fields,
		huh.NewConfirm().Title("Also save this plan as a reusable template?").Value(&saveTpl),
		huh.NewConfirm().Title("Write now?").Affirmative("Write").Negative("Cancel").Value(&proceed))
	if err := newForm(huh.NewGroup(fields...)).Run(); err != nil {
		return abort(err)
	}
	if !proceed {
		fmt.Fprintln(os.Stderr, "cancelled")
		return 1
	}
	content, err := renderLines(lines, res)
	if err == nil && strings.TrimSpace(backup) != "" {
		err = backupContent(res.bw, strings.TrimSpace(backup), content, dry) // before writing: no copy, no .env
	}
	if err == nil {
		err = writeEnv(out, content, force, dry)
	}
	if err == nil && saveTpl {
		tplPath := out + ".template"
		if !strings.HasSuffix(out, ".env") {
			tplPath = out + ".env.template"
		}
		err = writeEnv(tplPath, strings.Join(tplLines, "\n")+"\n", force, dry)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", out)
	return 0
}

func noPlaceholder(s string) error {
	if strings.Contains(s, "{{") {
		return errors.New("literal values can't contain {{ (use a generate/vault source)")
	}
	return nil
}

func abort(err error) int {
	if errors.Is(err, huh.ErrUserAborted) {
		fmt.Fprintln(os.Stderr, "aborted")
		return 130
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	return 1
}
