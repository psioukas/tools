package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// parseEnv reads a dotenv file into ordered pairs. Handles comments, `export`,
// single/double quotes (with \n \" \\ escapes in double quotes) and inline
// comments on unquoted values.
func parseEnv(path string) ([]kv, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseEnvReader(f, path)
}

func parseEnvReader(r io.Reader, path string) ([]kv, error) {
	var out []kv
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !keyRe.MatchString(k) {
			return nil, fmt.Errorf("%s:%d: not KEY=VALUE: %q", path, n, line)
		}
		out = append(out, kv{k, parseValue(strings.TrimSpace(v))})
	}
	return out, sc.Err()
}

func parseValue(v string) string {
	switch {
	case len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"':
		r := strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\n`, "\n")
		return r.Replace(v[1 : len(v)-1])
	case len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'':
		return v[1 : len(v)-1]
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}
