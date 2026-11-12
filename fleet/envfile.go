package main

import (
	"bytes"
	"io"
	"sort"
	"strings"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// doc is an env file held as raw lines so comments, order and `export` survive edits.
// (Small copy of the editor logic in env-gen; fleet talks to env-gen only for the vault.)
type doc struct{ lines []string }

func parseDoc(b []byte) *doc {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return &doc{}
	}
	return &doc{lines: strings.Split(s, "\n")}
}

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

func parseValue(v string) string {
	switch {
	case len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"':
		return strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\n`, "\n").Replace(v[1 : len(v)-1])
	case len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'':
		return v[1 : len(v)-1]
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

func quoteIfNeeded(v string) string {
	if v == "" || !strings.ContainsAny(v, " \t#\"'$`\\\n") {
		return v
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v) + `"`
}

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

func (d *doc) find(key string) int {
	idx := -1
	for i, l := range d.lines {
		if k, _, _, ok := entry(l); ok && k == key {
			idx = i
		}
	}
	return idx
}

func (d *doc) set(key, value string) {
	q := quoteIfNeeded(value)
	if i := d.find(key); i >= 0 {
		_, raw, prefix, _ := entry(d.lines[i])
		d.lines[i] = prefix + key + "=" + q + trailingComment(raw)
		return
	}
	d.lines = append(d.lines, key+"="+q)
}

func (d *doc) del(key string) {
	var out []string
	for _, l := range d.lines {
		if k, _, _, ok := entry(l); ok && k == key {
			continue
		}
		out = append(out, l)
	}
	d.lines = out
}

func (d *doc) values() map[string]string {
	m := map[string]string{}
	for _, l := range d.lines {
		if k, raw, _, ok := entry(l); ok {
			m[k] = parseValue(raw)
		}
	}
	return m
}

func (d *doc) bytes() []byte {
	if len(d.lines) == 0 {
		return nil
	}
	return []byte(strings.Join(d.lines, "\n") + "\n")
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
