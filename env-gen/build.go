package main

import (
	"fmt"
	"regexp"
	"strings"
)

var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// quoteIfNeeded wraps values dotenv parsers would mangle (spaces, #, quotes, $...).
func quoteIfNeeded(v string) string {
	if v == "" || !strings.ContainsAny(v, " \t#\"'$`\\\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(v) + `"`
}

// renderLines renders "KEY=VALUE" entries (values may hold placeholders) into env-file text.
func renderLines(lines []string, r Resolver) (string, error) {
	var sb strings.Builder
	for _, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		k = strings.TrimSpace(k)
		if !ok || !keyRe.MatchString(k) {
			return "", fmt.Errorf("bad entry %q: want KEY=VALUE with KEY like [A-Za-z_][A-Za-z0-9_]*", l)
		}
		val, err := Render(v, r)
		if err != nil {
			return "", fmt.Errorf("%s: %w", k, err)
		}
		if t := strings.TrimSpace(v); !strings.HasPrefix(t, `"`) && !strings.HasPrefix(t, "'") {
			val = quoteIfNeeded(val) // literals and generated/vault values alike
		}
		sb.WriteString(k + "=" + val + "\n")
	}
	return sb.String(), nil
}

var wholePlaceholderLine = regexp.MustCompile(`^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*=)(\{\{[^{}]+\}\})\s*$`)

// RenderTemplate renders template text line by line. When a line's whole value
// is a single placeholder, the resolved value is quoted if a dotenv parser
// would otherwise mangle it (spaces, #, $, quotes). Mixed values are left as written.
func RenderTemplate(src string, r Resolver) (string, error) {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if m := wholePlaceholderLine.FindStringSubmatch(l); m != nil {
			v, err := Render(m[2], r)
			if err != nil {
				return "", err
			}
			lines[i] = m[1] + quoteIfNeeded(v)
			continue
		}
		v, err := Render(l, r)
		if err != nil {
			return "", err
		}
		lines[i] = v
	}
	return strings.Join(lines, "\n"), nil
}
