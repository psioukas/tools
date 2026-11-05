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
		if val == v { // literal: quote if needed
			val = quoteIfNeeded(val)
		}
		sb.WriteString(k + "=" + val + "\n")
	}
	return sb.String(), nil
}
