package main

import (
	"strings"
	"testing"
)

type fake struct{ stored map[string]string }

func (f *fake) VW(i, fl string) (string, error) {
	if i == "db" && fl == "password" {
		return "s3cret", nil
	}
	return "", errNotFound
}
func (f *fake) VWGen(i, fl string, n int, cs string) (string, error) {
	set, _ := charsetFor(cs)
	v, _ := generate(n, set)
	f.stored[i+"/"+fl] = v
	return v, nil
}
func (f *fake) Prompt(l string) (string, error) { return "answer-" + l, nil }

func TestRender(t *testing.T) {
	f := &fake{stored: map[string]string{}}
	out, err := Render("A={{vw:db}}\nB={{ vw:db/password }}\nC={{gen:8:hex}}\nD={{prompt:Name}}\nE={{vwgen:app/key:16}}", f)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	if lines[0] != "A=s3cret" || lines[1] != "B=s3cret" || len(lines[2]) != 10 || lines[3] != "D=answer-Name" || len(lines[4]) != 18 {
		t.Fatalf("bad output: %q", out)
	}
	if f.stored["app/key"] == "" {
		t.Fatal("vwgen did not store")
	}
}

func TestRenderErrors(t *testing.T) {
	f := &fake{stored: map[string]string{}}
	for _, s := range []string{"{{nope:1}}", "{{gen:x}}", "{{gen:4:wat}}", "{{vw:missing}}"} {
		if _, err := Render(s, f); err == nil {
			t.Errorf("expected error for %s", s)
		}
	}
}

func TestRenderLines(t *testing.T) {
	f := &fake{stored: map[string]string{}}
	out, err := renderLines([]string{"A=plain", "B=has space", "C={{vw:db}}", "D=pa$$ #x"}, f)
	if err != nil {
		t.Fatal(err)
	}
	want := "A=plain\nB=\"has space\"\nC=s3cret\nD=\"pa$$ #x\"\n"
	if out != want {
		t.Fatalf("got %q want %q", out, want)
	}
	for _, bad := range []string{"noequals", "1BAD=x", "A B=x"} {
		if _, err := renderLines([]string{bad}, f); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

type spacey struct{ fake }

func (spacey) VW(i, f string) (string, error) { return "a b#c", nil }

func TestRenderTemplateQuotes(t *testing.T) {
	out, err := RenderTemplate("A={{vw:x}}\nB=pre-{{vw:x}}\n# {{gen:1}}\n", &spacey{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "A=\"a b#c\"\nB=pre-a b#c\n") {
		t.Fatalf("got %q", out)
	}
}

func TestRenderLinesQuotesGenerated(t *testing.T) {
	out, err := renderLines([]string{"A={{vw:db}}x", `B="keep"`}, &fake{stored: map[string]string{}})
	if err != nil || out != "A=s3cretx\nB=\"keep\"\n" {
		t.Fatalf("%q %v", out, err)
	}
	out, _ = renderLines([]string{"C={{vw:db}}"}, &spacey{})
	if out != "C=\"a b#c\"\n" {
		t.Fatalf("%q", out)
	}
}
