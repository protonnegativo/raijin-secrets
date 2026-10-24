package trufflehog

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestArgsTurnVerificationOffByDefault(t *testing.T) {
	got := strings.Join(Args([]string{"src"}, Options{Extra: []string{"--concurrency=2"}}), " ")
	if got != "filesystem --json --no-update --no-verification --concurrency=2 src" {
		t.Errorf("args: %s", got)
	}
	if strings.Contains(strings.Join(Args([]string{"src"}, Options{Verify: true}), " "), "--no-verification") {
		t.Error("--verify must drop --no-verification")
	}
}

func TestParse(t *testing.T) {
	in := `{"level":"info-0","msg":"running source"}
{"SourceMetadata":{"Data":{"Git":{"commit":"abc","file":"a.env","repository":"file:///r","line":3}}},"DetectorName":"Github","DecoderName":"BASE64","Verified":false,"VerificationError":"timeout","Raw":"ghp_x","RawV2":"","ExtraData":{"k":"v"}}
not json
{"SourceMetadata":{"Data":{"Filesystem":{"file":"b.env","line":1}}},"DetectorName":"AWS","Verified":true,"Raw":"AKIA","RawV2":"AKIA:s"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"c.env","line":1}}},"DetectorName":"AWS","Raw":""}
`
	rs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("want 2 results, got %+v", rs)
	}
	g := rs[0]
	if g.Source != "Git" || g.Commit != "abc" || g.File != "a.env" || g.Line != 3 || g.Repository != "file:///r" || g.Status() != "unknown" || g.DecoderName != "BASE64" {
		t.Errorf("git result: %+v", g)
	}
	if f := rs[1]; f.Source != "Filesystem" || f.Status() != "verified" || f.Value() != "AKIA:s" || f.Shown() != "AKIA" {
		t.Errorf("filesystem result: %+v", f)
	}
}

func TestLinesFromFilesAndGit(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.env")
	os.WriteFile(file, []byte("one\r\ntwo\n"), 0o600)
	var l Lines
	if s, ok := l.Line(Result{Source: "Filesystem", File: file, Line: 2}); !ok || s != "two" {
		t.Errorf("file line: %q %v", s, ok)
	}
	if _, ok := l.Line(Result{Source: "Filesystem", File: file, Line: 9}); ok {
		t.Error("a line past the end is not readable")
	}
	if _, ok := l.Line(Result{Commit: "abc", File: "a.env", Line: 1, Repository: "https://example.com/r"}); ok {
		t.Error("a remote repository is not read")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	git := func(args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid"}, args...)...).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", "a.env")
	git("commit", "-q", "-m", "a")
	commit := git("rev-parse", "HEAD")
	os.WriteFile(file, []byte("changed\n"), 0o600)
	if s, ok := l.Line(Result{Source: "Git", Commit: commit, File: "a.env", Line: 1, Repository: "file://" + dir}); !ok || s != "one" {
		t.Errorf("git line should come from the commit, not the work tree: %q %v", s, ok)
	}
}
