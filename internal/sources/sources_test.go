package sources

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-core/scope"
)

func TestAllowed(t *testing.T) {
	s, err := Parse([]string{
		"# comment",
		"/srv/app",
		"!/srv/app/vendor",
		"https://github.com/acme/api",
		"https://gitlab.example.com/team/*",
		"!https://github.com/acme/api/secrets",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"/srv/app":                                    true,
		"/srv/app/config/prod.env":                    true,
		"/srv/app/../app/a.env":                       true,
		"/srv/application":                            false,
		"/srv/app/vendor/lib.js":                      false,
		"/srv/other":                                  false,
		"file:///srv/app":                             true,
		"file:///srv/app/vendor/x":                    false,
		"https://github.com/acme/api":                 true,
		"https://GitHub.com/acme/api.git":             true,
		"https://github.com/acme/api/config/prod.env": true,
		"https://github.com/acme/api/secrets/x.env":   false,
		"https://github.com/acme/apiary":              false,
		"https://gitlab.example.com/team/one":         true,
		"https://gitlab.example.com/other/one":        false,
		"":                                            false,
	}
	for target, want := range cases {
		if got := s.Allowed(target); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestRelativePathsUseTheWorkingDirectory(t *testing.T) {
	s, err := Parse([]string{"checkout"})
	if err != nil {
		t.Fatal(err)
	}
	abs, _ := filepath.Abs("checkout/a.env")
	if !s.Allowed("checkout/a.env") || !s.Allowed("./checkout") || !s.Allowed(abs) || s.Allowed("other") {
		t.Error("a relative rule should match the same path written relative or absolute")
	}
}

func TestNeedsAnInclude(t *testing.T) {
	if _, err := Parse([]string{"!/srv/app"}); err == nil {
		t.Error("a scope with only exclusions should be an error")
	}
}

func TestURLWildcardMustFollowASlash(t *testing.T) {
	// "https://github.com*" used to be a plain prefix that also allowed https://github.com.evil.com.
	_, err := Parse([]string{"https://github.com*"})
	var pe *scope.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want a *scope.ParseError, got %v", err)
	}
	if pe.Lines[0].Line != 1 || pe.Lines[0].Rule != "https://github.com*" || !strings.Contains(pe.Lines[0].Hint, "https://github.com/*") {
		t.Errorf("the error should name the line and offer the fix: %+v", pe.Lines[0])
	}
	if _, err := Parse([]string{"https://github.com/ac*me/x"}); err == nil {
		t.Error("a wildcard in the middle of a rule should be an error")
	}

	s, err := Parse([]string{"https://github.com/*"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://github.com/acme/api":          true,
		"https://github.com.evil.com/acme/api": false,
		"https://github.com.evil.com":          false,
		"https://github.com@evil.com/acme/api": false,
		"https://evil.com/github.com/acme":     false,
	}
	for target, want := range cases {
		if got := s.Allowed(target); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestURLDotSegmentsAreNeverAllowed(t *testing.T) {
	s, err := Parse([]string{"https://gitlab.com/acme/*", "https://gitlab.com/exact/repo", "!https://gitlab.com/acme/secret"})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://gitlab.com/acme/api":                   true,
		"https://gitlab.com/acme/../evil/x":             false,
		"https://gitlab.com/acme/%2e%2e/evil/x":         false,
		"https://gitlab.com/acme/%2E%2e/evil/x":         false,
		"https://gitlab.com/acme/./api":                 false,
		"https://gitlab.com/acme/api/..":                false,
		"https://gitlab.com/exact/repo/../../evil/x":    false,
		"https://gitlab.com/acme/sub/../secret/x":       false,
		"https://gitlab.com/acme/..\\evil/x":            false,
		"https://gitlab.com/acme/api?next=../../x":      true,
		"https://gitlab.com/acme/secret/x":              false,
		"https://gitlab.com/acme/api.with.dots/x.y.git": true,
	}
	for target, want := range cases {
		if got := s.Allowed(target); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", target, got, want)
		}
	}
	if _, err := Parse([]string{"https://gitlab.com/acme/../evil/*"}); err == nil {
		t.Error("a rule with a .. segment should be an error")
	}
}

func TestSymlinkOutOfAllowedDirectoryIsNotAllowed(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "app")
	outside := filepath.Join(root, "outside")
	inside := filepath.Join(app, "real")
	for _, d := range []string{app, outside, inside, filepath.Join(app, "vendor")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string) {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(outside, "secret.env"))
	write(filepath.Join(inside, "ok.env"))
	write(filepath.Join(app, "vendor", "lib.env"))
	link := func(target, name string) string {
		p := filepath.Join(app, name)
		if err := os.Symlink(target, p); err != nil {
			t.Skip("symlinks are not available:", err)
		}
		return p
	}
	toOutside := link(outside, "link-out")
	toFile := link(filepath.Join(outside, "secret.env"), "link-file")
	toInside := link(inside, "link-in")
	toVendor := link(filepath.Join(app, "vendor"), "link-vendor")

	s, err := Parse([]string{app, "!" + filepath.Join(app, "vendor")})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		filepath.Join(app, "real", "ok.env"):         true,
		filepath.Join(app, "new-file.env"):           true, // does not exist yet
		toInside:                                     true,
		filepath.Join(toInside, "ok.env"):            true,
		toOutside:                                    false,
		filepath.Join(toOutside, "secret.env"):       false,
		toFile:                                       false,
		"file://" + filepath.Join(toOutside, "x"):    false,
		filepath.Join(toOutside, "does-not-exist"):   false,
		filepath.Join(toVendor, "lib.env"):           false, // an exclusion holds through a link
		filepath.Join(app, "vendor", "lib.env"):      false,
		filepath.Join(outside, "secret.env"):         false,
		filepath.Join(app, "..", "outside", "a.env"): false,
	}
	for target, want := range cases {
		if got := s.Allowed(target); got != want {
			t.Errorf("Allowed(%q) = %v, want %v", strings.TrimPrefix(target, root), got, want)
		}
	}
}

func TestAllowedDirectoryThatIsItselfASymlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "data", "app")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "srv-app")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks are not available:", err)
	}
	s, err := Parse([]string{link})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{filepath.Join(link, "a.env"), filepath.Join(real, "a.env")} {
		if !s.Allowed(target) {
			t.Errorf("%s should be allowed: the rule names the same directory", strings.TrimPrefix(target, root))
		}
	}
	if s.Allowed(filepath.Join(root, "data", "other.env")) {
		t.Error("a sibling of the real directory should not be allowed")
	}
}

func TestInvalidScopeListsEveryLineInTheSharedFormat(t *testing.T) {
	_, err := Parse([]string{"/srv/app", "https://github.com*", "!", "https://gitlab.com/a/../b/*"})
	errs := scope.SchemaErrors(err)
	if len(errs) != 3 {
		t.Fatalf("want one error per invalid line, got %+v", errs)
	}
	for i, line := range []string{"line 2:", "line 3:", "line 4:"} {
		if errs[i].Kind != "scope" || !strings.HasPrefix(errs[i].Hint, line) {
			t.Errorf("error %d = %+v, want kind scope and a hint starting %q", i, errs[i], line)
		}
	}

	_, err = Parse([]string{"!/srv/app"})
	errs = scope.SchemaErrors(err)
	if len(errs) != 1 || errs[0].Kind != "scope" || !strings.Contains(errs[0].Hint, "no include rules") {
		t.Errorf("only exclusions: %+v", errs)
	}
}
