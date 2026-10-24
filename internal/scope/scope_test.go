package scope

import (
	"path/filepath"
	"testing"
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
