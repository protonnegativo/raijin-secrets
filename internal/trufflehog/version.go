package trufflehog

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

// Engine is one entry of engines.json: the tested version and where to install it from. trufflehog's
// go.mod has replace directives, so "go install" does not build it; the hint installs the release.
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Release string `json:"release,omitempty"`
}

// Engines parses engines.json.
func Engines(b []byte) (map[string]Engine, error) {
	var m map[string]Engine
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion returns the first X.Y.Z in s (trufflehog --version prints "trufflehog 3.99.3").
func ParseVersion(s string) ([3]int, bool) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

// Untested is true when installed is a different major version than tested, or older. A newer minor or
// patch of the same major is fine: the weekly drift job tests those.
func Untested(installed, tested [3]int) bool {
	if installed[0] != tested[0] {
		return true
	}
	for i := 1; i < 3; i++ {
		if installed[i] != tested[i] {
			return installed[i] < tested[i]
		}
	}
	return false
}

// Version runs "trufflehog --version" with a short timeout and returns its output; "" when it fails.
func Version(bin string) string {
	if bin == "" {
		bin = "trufflehog"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, bin, "--version").CombinedOutput()
	return string(out)
}

// VersionHint is the engine_version hint for the output of "trufflehog --version", or "" when the
// version is tested, newer within the same major, or unparseable (the check never fails a run).
func VersionHint(output string, e Engine) string {
	installed, ok := ParseVersion(output)
	tested, ok2 := ParseVersion(e.Version)
	if !ok || !ok2 || !Untested(installed, tested) {
		return ""
	}
	return fmt.Sprintf("trufflehog %d.%d.%d is not the tested %s; results may be incomplete. Install the tested version: "+
		"curl -sSfL https://raw.githubusercontent.com/%s/main/scripts/install.sh | sh -s -- -b /usr/local/bin v%s, or run raijin-mcp update",
		installed[0], installed[1], installed[2], e.Version, e.Release, e.Version)
}
