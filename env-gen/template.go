package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var placeholderRe = regexp.MustCompile(`\{\{\s*([^{}]+?)\s*\}\}`)

// Resolver supplies values for the vw / vwgen / prompt placeholders.
type Resolver interface {
	VW(item, field string) (string, error)
	VWGen(item, field string, n int, charset string) (string, error)
	Prompt(label string) (string, error)
}

const (
	alnum   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	hexset  = "0123456789abcdef"
	symbols = alnum + "!@#$%^&*()-_=+[]{}"
)

func charsetFor(name string) (string, error) {
	switch name {
	case "", "alnum":
		return alnum, nil
	case "hex":
		return hexset, nil
	case "symbols":
		return symbols, nil
	}
	return "", fmt.Errorf("unknown charset %q (alnum|hex|symbols)", name)
}

func generate(n int, charset string) (string, error) {
	var sb strings.Builder
	max := big.NewInt(int64(len(charset)))
	for i := 0; i < n; i++ {
		x, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		sb.WriteByte(charset[x.Int64()])
	}
	return sb.String(), nil
}

// splitItemField splits "Item Name/field" on the last slash (default field: password).
func splitItemField(s string) (string, string) {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, "password"
}

// Render replaces every placeholder in src.
//
//	{{gen:N[:charset]}}            random value
//	{{prompt:Label}}               ask interactively
//	{{vw:Item/field}}              read from Vaultwarden
//	{{vwgen:Item/field:N[:cs]}}    read from Vaultwarden, or generate + store if missing
func Render(src string, r Resolver) (string, error) {
	var firstErr error
	out := placeholderRe.ReplaceAllStringFunc(src, func(m string) string {
		if firstErr != nil {
			return m
		}
		inner := strings.TrimSpace(placeholderRe.FindStringSubmatch(m)[1])
		kind, rest, _ := strings.Cut(inner, ":")
		parts := strings.Split(rest, ":")
		val, err := func() (string, error) {
			switch kind {
			case "gen":
				n, err := strconv.Atoi(parts[0])
				if err != nil || n <= 0 {
					return "", fmt.Errorf("gen needs a positive length")
				}
				cs := ""
				if len(parts) > 1 {
					cs = parts[1]
				}
				set, err := charsetFor(cs)
				if err != nil {
					return "", err
				}
				return generate(n, set)
			case "prompt":
				return r.Prompt(rest)
			case "vw":
				item, field := splitItemField(rest)
				return r.VW(item, field)
			case "vwgen":
				if len(parts) < 2 {
					return "", fmt.Errorf("vwgen needs Item/field:N")
				}
				n, err := strconv.Atoi(parts[1])
				if err != nil || n <= 0 {
					return "", fmt.Errorf("vwgen needs a positive length")
				}
				cs := ""
				if len(parts) > 2 {
					cs = parts[2]
				}
				if _, err := charsetFor(cs); err != nil {
					return "", err
				}
				item, field := splitItemField(parts[0])
				return r.VWGen(item, field, n, cs)
			}
			return "", fmt.Errorf("unknown placeholder kind %q", kind)
		}()
		if err != nil {
			firstErr = fmt.Errorf("{{%s}}: %w", inner, err)
			return m
		}
		return val
	})
	return out, firstErr
}
