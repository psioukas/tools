package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var envNameRe = regexp.MustCompile(`^(\.env(\..+)?|.+\.env(\..+)?)$`)

func isEnvName(name string) bool {
	return envNameRe.MatchString(name) && !strings.HasSuffix(name, ".bak") && !strings.HasSuffix(name, "~")
}

func isExampleName(name string) bool {
	for _, n := range exampleNames {
		if name == n {
			return true
		}
	}
	return strings.HasSuffix(name, ".example") || strings.HasSuffix(name, ".sample") || strings.HasSuffix(name, ".dist")
}

// safePath maps a client-supplied relative path to an absolute one inside the root.
// It rejects absolute paths, "..", symlink escapes and non-.env file names.
func (s *uiServer) safePath(rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.ContainsRune(rel, 0) {
		return "", errors.New("bad path")
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path outside the allowed root")
	}
	if !isEnvName(filepath.Base(clean)) {
		return "", errors.New("only .env-style files are allowed")
	}
	full := filepath.Join(s.root, clean)
	dir, err := filepath.EvalSymlinks(filepath.Dir(full))
	if err != nil {
		return "", errors.New("directory not found")
	}
	if dir != s.root && !strings.HasPrefix(dir, s.root+string(filepath.Separator)) {
		return "", errors.New("path outside the allowed root")
	}
	full = filepath.Join(dir, filepath.Base(full))
	if st, err := os.Lstat(full); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("symlinked files are not allowed")
	}
	return full, nil
}

func (s *uiServer) rel(full string) string {
	r, err := filepath.Rel(s.root, full)
	if err != nil {
		return full
	}
	return filepath.ToSlash(r)
}

// ---- projects ----------------------------------------------------------------------------------

type uiProject struct {
	Dir   string   `json:"dir"`
	Files []string `json:"files"`
}

func (s *uiServer) projects(w http.ResponseWriter, r *http.Request, _ *uiSession) (any, int, error) {
	skip := map[string]bool{".git": true, "node_modules": true, "vendor": true, ".cache": true}
	byDir := map[string][]string{}
	count := 0
	_ = filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(s.root, p)
		if d.IsDir() {
			if skip[d.Name()] || (rel != "." && strings.Count(rel, string(filepath.Separator)) >= 3) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink == 0 && isEnvName(d.Name()) && count < 2000 {
			dir := filepath.ToSlash(filepath.Dir(rel))
			byDir[dir] = append(byDir[dir], d.Name())
			count++
		}
		return nil
	})
	var out []uiProject
	for d, files := range byDir {
		sort.Strings(files)
		out = append(out, uiProject{Dir: d, Files: files})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return map[string]any{"projects": out}, 0, nil
}

// ---- reading files -------------------------------------------------------------------------------

type uiVar struct {
	Key      string `json:"key"`
	Secret   bool   `json:"secret"`
	HasValue bool   `json:"has_value"`
	Value    string `json:"value,omitempty"` // omitted for secret-looking keys; use /api/value
	Suggest  string `json:"suggest,omitempty"`
}

func (s *uiServer) getFile(w http.ResponseWriter, r *http.Request, _ *uiSession) (any, int, error) {
	full, err := s.safePath(r.URL.Query().Get("path"))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	doc, err := loadDoc(full)
	if err != nil {
		return nil, http.StatusNotFound, errors.New("cannot read file")
	}
	example := isExampleName(filepath.Base(full))
	var vars []uiVar
	for _, k := range doc.keys() {
		v, _ := doc.get(k)
		uv := uiVar{Key: k, Secret: secretKeyRe.MatchString(k), HasValue: v != ""}
		if !uv.Secret {
			uv.Value = v
		}
		if example {
			uv.Suggest = suggest(k)
		}
		vars = append(vars, uv)
	}
	return map[string]any{"path": s.rel(full), "example": example, "vars": vars, "project": filepath.Base(filepath.Dir(full))}, 0, nil
}

func (s *uiServer) getValue(w http.ResponseWriter, r *http.Request, _ *uiSession) (any, int, error) {
	full, err := s.safePath(r.URL.Query().Get("path"))
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	doc, err := loadDoc(full)
	if err != nil {
		return nil, http.StatusNotFound, errors.New("cannot read file")
	}
	v, ok := doc.get(r.URL.Query().Get("key"))
	if !ok {
		return nil, http.StatusNotFound, errors.New("no such variable")
	}
	return map[string]string{"value": v}, 0, nil
}

// ---- saving ----------------------------------------------------------------------------------------

type uiSource struct {
	Kind    string `json:"kind"` // literal | gen | vw | vwgen
	Value   string `json:"value"`
	Item    string `json:"item"`
	Field   string `json:"field"`
	Length  int    `json:"length"`
	Charset string `json:"charset"`
}

type uiOp struct {
	Op     string    `json:"op"` // set | delete | rename
	Key    string    `json:"key"`
	NewKey string    `json:"new_key"`
	Source *uiSource `json:"source"`
}

type saveReq struct {
	Path       string `json:"path"`
	To         string `json:"to"` // create a new file from Path (e.g. .env from .env.example)
	Overwrite  bool   `json:"overwrite"`
	BackupItem string `json:"backup_item"`
	Preview    bool   `json:"preview"`
	Ops        []uiOp `json:"ops"`
}

func validSource(src *uiSource) error {
	if src == nil {
		return errors.New("missing value source")
	}
	switch src.Kind {
	case "literal":
		return nil
	case "gen", "vwgen":
		if src.Length < 5 || src.Length > 128 {
			return errors.New("length must be 5-128")
		}
		if _, err := charsetFor(src.Charset); err != nil {
			return err
		}
	}
	switch src.Kind {
	case "gen":
		return nil
	case "vw", "vwgen":
		if strings.TrimSpace(src.Item) == "" {
			return errors.New("vault item required")
		}
		return nil
	}
	return fmt.Errorf("unknown source %q", src.Kind)
}

func (s *uiServer) save(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	var req saveReq
	if err := decode(r, &req); err != nil {
		return nil, http.StatusBadRequest, errors.New("bad request")
	}
	src, err := s.safePath(req.Path)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	dst := src
	if req.To != "" {
		if dst, err = s.safePath(req.To); err != nil {
			return nil, http.StatusBadRequest, err
		}
		if _, err := os.Stat(dst); err == nil && !req.Overwrite {
			return nil, http.StatusConflict, errors.New("target file already exists")
		}
	}
	doc, err := loadDoc(src)
	if err != nil {
		return nil, http.StatusNotFound, errors.New("cannot read file")
	}
	orig := doc.values()
	if len(req.Ops) > 500 {
		return nil, http.StatusBadRequest, errors.New("too many changes")
	}
	for _, op := range req.Ops {
		if !keyRe.MatchString(op.Key) {
			return nil, http.StatusBadRequest, fmt.Errorf("bad variable name %q", op.Key)
		}
		switch op.Op {
		case "set":
			if err := validSource(op.Source); err != nil {
				return nil, http.StatusBadRequest, fmt.Errorf("%s: %w", op.Key, err)
			}
		case "rename":
			if !keyRe.MatchString(op.NewKey) {
				return nil, http.StatusBadRequest, fmt.Errorf("bad new name %q", op.NewKey)
			}
		case "delete":
		default:
			return nil, http.StatusBadRequest, fmt.Errorf("unknown op %q", op.Op)
		}
	}
	bw := s.newBw(sess.bwSession)
	res := &cliResolver{bw: bw, in: bufio.NewReader(strings.NewReader(""))}
	for _, op := range req.Ops {
		switch op.Op {
		case "delete":
			doc.del(op.Key)
		case "rename":
			doc.rename(op.Key, op.NewKey)
		case "set":
			if req.Preview { // never resolve (or store) anything while previewing
				if op.Source.Kind == "literal" { // typed values are known, so the diff is exact
					doc.set(op.Key, quoteIfNeeded(op.Source.Value))
				} else {
					doc.set(op.Key, "«"+op.Source.Kind+"»")
				}
				continue
			}
			v, err := s.resolveSource(res, op.Source)
			if err != nil {
				return nil, http.StatusBadGateway, fmt.Errorf("%s: %w", op.Key, err)
			}
			doc.set(op.Key, quoteIfNeeded(v))
		}
	}
	summary := diffSummary(orig, doc)
	if req.Preview {
		return map[string]any{"preview": true, "changes": summary, "target": s.rel(dst)}, 0, nil
	}
	if item := strings.TrimSpace(req.BackupItem); item != "" {
		if err := backupContent(bw, item, doc.String(), false); err != nil {
			return nil, http.StatusBadGateway, err
		}
	}
	if old, err := os.ReadFile(dst); err == nil {
		_ = os.WriteFile(dst+".bak", old, 0o600)
	}
	if err := os.WriteFile(dst, []byte(doc.String()), 0o600); err != nil {
		return nil, http.StatusInternalServerError, errors.New("could not write file")
	}
	return map[string]any{"saved": true, "changes": summary, "path": s.rel(dst)}, 0, nil
}

func (s *uiServer) resolveSource(res *cliResolver, src *uiSource) (string, error) {
	switch src.Kind {
	case "literal":
		return src.Value, nil
	case "gen":
		return genSecret(src.Length, src.Charset)
	case "vw":
		f := src.Field
		if f == "" {
			f = "password"
		}
		return res.VW(src.Item, f)
	default: // vwgen
		f := src.Field
		if f == "" {
			f = "password"
		}
		return res.VWGen(src.Item, f, src.Length, src.Charset)
	}
}

func diffSummary(orig map[string]string, doc *envDoc) []map[string]string {
	final := doc.values()
	var out []map[string]string
	for _, k := range doc.keys() {
		if v, had := orig[k]; !had {
			out = append(out, map[string]string{"sign": "+", "key": k})
		} else if v != final[k] {
			out = append(out, map[string]string{"sign": "~", "key": k})
		}
	}
	var gone []string
	for k := range orig {
		if _, still := final[k]; !still {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		out = append(out, map[string]string{"sign": "-", "key": k})
	}
	return out
}

// ---- vault helpers ------------------------------------------------------------------------------------

func (s *uiServer) vaultSearch(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		return map[string]any{"items": []string{}}, 0, nil
	}
	items, err := s.newBw(sess.bwSession).Search(q)
	if err != nil {
		return nil, http.StatusBadGateway, errors.New("vault search failed")
	}
	names := []string{}
	for i, it := range items {
		if i >= 50 {
			break
		}
		names = append(names, it.Name)
	}
	return map[string]any{"items": names}, 0, nil
}

func (s *uiServer) vaultFields(w http.ResponseWriter, r *http.Request, sess *uiSession) (any, int, error) {
	item := r.URL.Query().Get("item")
	fields := []string{"password", "username", "uri", "notes"}
	if it, err := s.newBw(sess.bwSession).get(item); err == nil {
		for _, f := range it.Fields {
			fields = append(fields, f.Name)
		}
	} else if !errors.Is(err, errNotFound) {
		return nil, http.StatusBadGateway, errors.New("vault lookup failed")
	}
	return map[string]any{"fields": fields}, 0, nil
}

func (s *uiServer) vaultRecent(w http.ResponseWriter, r *http.Request, _ *uiSession) (any, int, error) {
	return map[string]any{"items": loadRecent()}, 0, nil
}
