package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
)

func newForm(groups ...*huh.Group) *huh.Form {
	f := huh.NewForm(groups...)
	if os.Getenv("ACCESSIBLE") != "" { // plain line prompts, used for scripted tests
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

// pickVaultItem lets the user search the vault; falls back to typing the name.
func pickVaultItem(bw *Bw) (item string, fields []string, err error) {
	fields = []string{"password", "username", "uri", "notes"}
	var search string
	if bw.Session != "" {
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
	return
}

// runNew is the interactive builder. It assembles template lines, shows them
// (never resolved secrets), optionally saves them as a template, then renders.
func runNew(res *cliResolver, out string, force, dry bool) int {
	var lines, tplLines []string
	for {
		var key, source string
		err := newForm(huh.NewGroup(
			huh.NewInput().Title("Variable name").Value(&key).Validate(validKey),
			huh.NewSelect[string]().Title("Value source").Options(
				huh.NewOption("Literal value", "literal"),
				huh.NewOption("Literal secret (hidden input)", "secret"),
				huh.NewOption("Generate random", "gen"),
				huh.NewOption("Read from Vaultwarden", "vw"),
				huh.NewOption("Vaultwarden: read, or generate + store if missing", "vwgen"),
			).Value(&source),
		)).Run()
		if err != nil {
			return abort(err)
		}
		var value string
		switch source {
		case "literal", "secret":
			in := huh.NewInput().Title("Value").Value(&value).Validate(noPlaceholder)
			if source == "secret" {
				in = in.EchoMode(huh.EchoModePassword)
			}
			if err = newForm(huh.NewGroup(in)).Run(); err != nil {
				return abort(err)
			}
			tplValue := quoteIfNeeded(value)
			if source == "secret" {
				tplValue = "{{prompt:" + key + "}}" // never write typed secrets into a template
			}
			lines = append(lines, key+"="+value) // quoted by renderLines
			tplLines = append(tplLines, key+"="+tplValue)
			goto more
		case "gen":
			n, cs := "32", "alnum"
			if err = newForm(huh.NewGroup(
				huh.NewInput().Title("Length").Value(&n).Validate(validLen),
				huh.NewSelect[string]().Title("Charset").Options(
					huh.NewOption("alphanumeric", "alnum"), huh.NewOption("hex", "hex"), huh.NewOption("with symbols", "symbols")).Value(&cs),
			)).Run(); err != nil {
				return abort(err)
			}
			value = fmt.Sprintf("{{gen:%s:%s}}", n, cs)
		case "vw", "vwgen":
			item, fields, perr := pickVaultItem(res.bw)
			if perr != nil {
				return abort(perr)
			}
			field := "password"
			opts := make([]huh.Option[string], len(fields))
			for i, f := range fields {
				opts[i] = huh.NewOption(f, f)
			}
			fs := []huh.Field{huh.NewSelect[string]().Title("Field").Options(opts...).Value(&field)}
			n, cs := "32", "alnum"
			if source == "vwgen" {
				// a new item has no custom fields to pick; allow typing any field name
				fs = []huh.Field{huh.NewInput().Title("Field (password, notes, or custom name)").Value(&field)}
				fs = append(fs,
					huh.NewInput().Title("Length").Value(&n).Validate(validLen),
					huh.NewSelect[string]().Title("Charset").Options(
						huh.NewOption("alphanumeric", "alnum"), huh.NewOption("hex", "hex"), huh.NewOption("with symbols", "symbols")).Value(&cs))
			}
			if err = newForm(huh.NewGroup(fs...)).Run(); err != nil {
				return abort(err)
			}
			if source == "vw" {
				value = fmt.Sprintf("{{vw:%s/%s}}", item, field)
			} else {
				value = fmt.Sprintf("{{vwgen:%s/%s:%s:%s}}", item, field, n, cs)
			}
		}
		lines = append(lines, key+"="+value)
		tplLines = append(tplLines, key+"="+value)
	more:
		var again bool
		if err = newForm(huh.NewGroup(huh.NewConfirm().Title("Add another variable?").Value(&again))).Run(); err != nil {
			return abort(err)
		}
		if !again {
			break
		}
	}

	saveTpl := false
	var tplPath string
	fmt.Fprintf(os.Stderr, "\nPlan (secrets are resolved only when written):\n  %s\n\n", strings.Join(tplLines, "\n  "))
	var proceed bool
	if err := newForm(huh.NewGroup(
		huh.NewInput().Title("Output file").Value(&out),
		huh.NewConfirm().Title("Also save this plan as a reusable template?").Value(&saveTpl),
		huh.NewConfirm().Title("Write now?").Affirmative("Write").Negative("Cancel").Value(&proceed),
	)).Run(); err != nil {
		return abort(err)
	}
	if !proceed {
		fmt.Fprintln(os.Stderr, "cancelled")
		return 1
	}
	content, err := renderLines(lines, res)
	if err == nil {
		err = writeEnv(out, content, force, dry)
	}
	if err == nil && saveTpl {
		tplPath = out + ".template"
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
