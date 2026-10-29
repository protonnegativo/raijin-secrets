// Package sources decides whether a path or a git repository is allowed to be scanned.
//
// It is the scope of raijin-secrets. The other Raijin tools scope hosts and use raijin-core/scope; this
// one scopes sources, which have their own syntax, so it stays in the tool. It shares only "!" and "#".
//
// A scope file has one rule per line:
//
//	/srv/app                     a local path and everything under it
//	./checkout                   a path relative to the working directory
//	https://github.com/acme/api  a git repository (and the files in it)
//	https://github.com/acme/*    every repository whose URL starts with the text before the *; the * must
//	                             follow a "/", so https://github.com* is an error, not a prefix
//	!/srv/app/vendor             an exclusion; exclusions win over inclusions
//
// A file:// repository is also matched by the path rules: file:///srv/app is the path /srv/app.
// Blank lines and lines starting with # are ignored.
//
// A path is compared after symlinks are resolved, so a link inside an allowed directory that points
// outside it is not allowed. A repository URL with a "." or ".." path segment is never allowed.
//
// An invalid scope is reported as a *scope.ParseError of raijin-core, with one LineError per invalid line,
// so the tool can answer with the same structured errors as the others (see scope.SchemaErrors).
package sources

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/protonnegativo/raijin-core/scope"
)

type rule struct {
	exclude bool
	// path is a cleaned absolute path and rpath the same path with symlinks resolved; url is a
	// normalized repository URL.
	path   string
	rpath  string
	url    string
	prefix bool // url ended in /*: any URL that starts with it
}

// Scope is a parsed set of include and exclude rules.
type Scope struct {
	rules []rule
}

// Load reads a scope file.
func Load(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return Parse(lines)
}

// Parse builds a Scope from rule lines. An invalid scope is a *scope.ParseError that lists every invalid
// line, not just the first.
func Parse(lines []string) (*Scope, error) {
	s := &Scope{}
	var bad []*scope.LineError
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := rule{}
		if strings.HasPrefix(line, "!") {
			r.exclude = true
			line = strings.TrimSpace(line[1:])
		}
		if line == "" {
			bad = append(bad, &scope.LineError{Line: i + 1, Rule: strings.TrimSpace(raw), Reason: "empty exclusion", Hint: "write the path or repository after '!', or delete the line"})
			continue
		}
		switch {
		case strings.HasPrefix(line, "file://"):
			r.path = Path(strings.TrimPrefix(line, "file://"))
		case strings.Contains(line, "://"):
			if le := checkURLRule(i+1, line); le != nil {
				bad = append(bad, le)
				continue
			}
			if strings.HasSuffix(line, "*") {
				r.prefix = true
				r.url = strings.ToLower(strings.TrimSuffix(line, "*"))
			} else {
				r.url = NormalizeURL(line)
			}
		default:
			r.path = Path(line)
		}
		if r.path != "" {
			r.rpath = resolve(r.path)
		}
		s.rules = append(s.rules, r)
	}
	if len(s.includes()) == 0 {
		bad = append(bad, &scope.LineError{Reason: "no include rules", Hint: "add a path or a repository URL that is allowed, such as '/srv/app' or 'https://github.com/acme/api'; '!' lines only exclude"})
	}
	if len(bad) > 0 {
		return nil, &scope.ParseError{Lines: bad}
	}
	return s, nil
}

// checkURLRule rejects the URL rules that would allow more than they say, or could never match.
func checkURLRule(n int, line string) *scope.LineError {
	if i := strings.Index(line, "*"); i >= 0 && i != len(line)-1 {
		return &scope.LineError{Line: n, Rule: line, Reason: "misplaced wildcard", Hint: "a '*' is only allowed as the last character, after a '/': 'https://github.com/acme/*'"}
	}
	if strings.HasSuffix(line, "*") && !strings.HasSuffix(line, "/*") {
		stem := strings.TrimSuffix(line, "*")
		return &scope.LineError{Line: n, Rule: line, Reason: "wildcard does not follow a '/'", Hint: fmt.Sprintf("'%s' is a plain prefix and would also allow '%s.evil.example'; write '%s/*' for everything under it, or the exact URL for one repository", line, stem, stem)}
	}
	if hasDotSegment(strings.TrimSuffix(line, "*")) {
		return &scope.LineError{Line: n, Rule: line, Reason: "'.' or '..' segment in rule", Hint: "write the URL without '.' and '..' segments"}
	}
	return nil
}

func (s *Scope) includes() []rule {
	var out []rule
	for _, r := range s.rules {
		if !r.exclude {
			out = append(out, r)
		}
	}
	return out
}

// Allowed reports whether a target is in scope: a local path, a repository URL, or a file inside a
// repository ("https://github.com/acme/api/config/prod.env").
func (s *Scope) Allowed(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	t := newTarget(target)
	if t.bad {
		return false
	}
	included := false
	for _, r := range s.rules {
		if !r.match(t) {
			continue
		}
		if r.exclude {
			return false
		}
		included = true
	}
	return included
}

// target is what is checked, prepared once for all the rules.
type target struct {
	raw   string
	isURL bool
	bad   bool // a URL with a "." or ".." segment: it can name another repository than it starts with
	// path and rpath: the cleaned absolute path of a local target (or file:// URL) and the same with
	// symlinks resolved. Empty for a repository URL.
	path, rpath string
}

func newTarget(raw string) target {
	t := target{raw: raw, isURL: strings.Contains(raw, "://")}
	p := raw
	if t.isURL {
		if !strings.HasPrefix(raw, "file://") {
			t.bad = hasDotSegment(raw)
			return t
		}
		p = strings.TrimPrefix(raw, "file://")
	}
	t.path = Path(p)
	t.rpath = resolve(t.path)
	return t
}

func (r rule) match(t target) bool {
	if r.path != "" {
		if t.path == "" {
			return false
		}
		if r.exclude {
			// Fail closed: an exclusion holds for the path as written and for where it really leads.
			return under(t.path, r.path) || under(t.rpath, r.rpath)
		}
		// An inclusion holds only for where the path really leads, so a link out of the directory
		// does not carry the target with it.
		return under(t.rpath, r.rpath)
	}
	if !t.isURL || t.path != "" {
		return false
	}
	if r.prefix {
		return strings.HasPrefix(strings.ToLower(t.raw), r.url)
	}
	u := NormalizeURL(t.raw)
	return u == r.url || strings.HasPrefix(u, r.url+"/")
}

// under reports whether p is dir or inside it. Both are cleaned absolute paths.
func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// hasDotSegment is true when the path of a URL has a "." or ".." segment, written out or percent-encoded.
func hasDotSegment(u string) bool {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	_, path, found := strings.Cut(u, "/")
	if !found {
		return false
	}
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	path = strings.NewReplacer("%2e", ".", "%2E", ".", "\\", "/").Replace(path)
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// resolve returns p with symlinks resolved. For a path that does not exist (or not all of it), the
// longest existing parent is resolved and the rest is appended, so a file that is not there yet is
// still judged by where its directory leads.
func resolve(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	dir := filepath.Dir(p)
	if dir == p {
		return p
	}
	return filepath.Join(resolve(dir), filepath.Base(p))
}

// Path returns the cleaned absolute form of a local path. A relative path is taken from the working
// directory.
func Path(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

// NormalizeURL lowercases the scheme and host part of a repository URL and removes a trailing "/" and
// ".git", so https://GitHub.com/acme/api.git and https://github.com/acme/api are the same repository.
func NormalizeURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimSuffix(u, ".git")
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		host, path, _ := strings.Cut(rest, "/")
		u = strings.ToLower(u[:i+3]+host) + "/" + path
		u = strings.TrimSuffix(u, "/")
	}
	return u
}
