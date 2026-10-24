// Package scope decides whether a path or a git repository is allowed to be scanned.
//
// A scope file has one rule per line:
//
//	/srv/app                     a local path and everything under it
//	./checkout                   a path relative to the working directory
//	https://github.com/acme/api  a git repository (and the files in it)
//	https://github.com/acme/*    every repository whose URL starts with the text before the *
//	!/srv/app/vendor             an exclusion; exclusions win over inclusions
//
// A file:// repository is also matched by the path rules: file:///srv/app is the path /srv/app.
// Blank lines and lines starting with # are ignored.
package scope

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type rule struct {
	exclude bool
	// path is a cleaned absolute path; url is a normalized repository URL.
	path   string
	url    string
	prefix bool // url ended in *: any URL that starts with it
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

// Parse builds a Scope from rule lines.
func Parse(lines []string) (*Scope, error) {
	s := &Scope{}
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
			return nil, fmt.Errorf("scope line %d: empty exclusion", i+1)
		}
		switch {
		case strings.HasPrefix(line, "file://"):
			r.path = Path(strings.TrimPrefix(line, "file://"))
		case strings.Contains(line, "://"):
			if strings.HasSuffix(line, "*") {
				r.prefix = true
				line = strings.TrimSuffix(line, "*")
				r.url = strings.ToLower(line)
			} else {
				r.url = NormalizeURL(line)
			}
		default:
			r.path = Path(line)
		}
		s.rules = append(s.rules, r)
	}
	if len(s.includes()) == 0 {
		return nil, fmt.Errorf("scope has no include rules")
	}
	return s, nil
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
	included := false
	for _, r := range s.rules {
		if !r.match(target) {
			continue
		}
		if r.exclude {
			return false
		}
		included = true
	}
	return included
}

func (r rule) match(target string) bool {
	isURL := strings.Contains(target, "://")
	if r.path != "" {
		p := target
		if isURL {
			if !strings.HasPrefix(target, "file://") {
				return false
			}
			p = strings.TrimPrefix(target, "file://")
		}
		p = Path(p)
		return p == r.path || strings.HasPrefix(p, strings.TrimSuffix(r.path, "/")+"/")
	}
	if !isURL {
		return false
	}
	if r.prefix {
		return strings.HasPrefix(strings.ToLower(target), r.url)
	}
	u := NormalizeURL(target)
	return u == r.url || strings.HasPrefix(u, r.url+"/")
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
