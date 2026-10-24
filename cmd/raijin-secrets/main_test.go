package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = "../../testdata/sample.jsonl"

func scopeFile(t *testing.T, rules string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sampleScope covers every sample result but outside/.
func sampleScope(t *testing.T) string {
	return scopeFile(t, "app\nci\ndocs\nnode_modules\ntests\nfile:///nonexistent/shop\n")
}

type output struct {
	Summary  string
	Findings []struct {
		ID, Severity, Confidence, Secret string
		Locations                        []string
	}
	Groups  []struct{ ID, Detector string }
	Omitted map[string]int
	Errors  []struct{ Kind, Hint string }
	Raw     string
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", sampleScope(t), "--input", sample}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", sampleScope(t), "--input", sample}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-secrets v"+version) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", sampleScope(t), "--input", sample}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", sampleScope(t), "--input", sample}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
	want := `"summary":"12 results, 9 secrets, 8 findings (3 critical, 1 high, 3 medium, 1 low), 4 verified, 1 groups"`
	if !strings.Contains(out.String(), want) {
		t.Errorf("summary: %s", out.String())
	}
	if !strings.Contains(out.String(), `"omitted":{"duplicates":1,"out_of_scope":1}`) {
		t.Errorf("omitted: %s", out.String())
	}
}

func TestSecretValuesStayOutOfStdout(t *testing.T) {
	for _, format := range []string{"json", "table"} {
		var out, errb bytes.Buffer
		run([]string{"--format", format, "--scope", sampleScope(t), "--input", sample}, &out, &errb)
		for _, v := range []string{"AKIAFAKEFAKEFAKE0001", "fakeSecretfakeSecret", "ghp_fakefake", "xoxb-0000000000-0000000000", "npm_fakefake", "sk_live_fakefake", "fakeddapikey"} {
			if strings.Contains(out.String(), v) {
				t.Errorf("%s: secret %s leaked: %s", format, v, out.String())
			}
		}
	}
}

// fakeEngine writes a trufflehog stand-in that records its arguments and prints the sample.
func fakeEngine(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	abs, _ := filepath.Abs(sample)
	bin = filepath.Join(dir, "trufflehog")
	script := "#!/bin/sh\necho \"$@\" >> " + argsFile + "\necho '{\"level\":\"info-0\"}' >&2\ncat " + abs + "\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func TestLiveRunWithoutVerification(t *testing.T) {
	bin, argsFile := fakeEngine(t)
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	raw := filepath.Join(dir, "raw.jsonl")
	sc := sampleScope(t)
	os.WriteFile(sc, []byte("app\nci\ndocs\nnode_modules\ntests\nfile:///nonexistent/shop\n"+repo+"\n"), 0o600)
	var out, errb bytes.Buffer
	code := run([]string{"--trufflehog", bin, "--scope", sc, "--raw", raw, "-p", "app", "-p", "/elsewhere", "-g", repo, "--", "--concurrency=1"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	args, _ := os.ReadFile(argsFile)
	want := "filesystem --json --no-update --no-verification --concurrency=1 app\ngit --json --no-update --no-verification --concurrency=1 file://" + repo + "\n"
	if string(args) != want {
		t.Errorf("engine args:\ngot  %q\nwant %q", args, want)
	}
	var o output
	if err := json.Unmarshal(out.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	// the sample ran twice: /elsewhere and outside/ twice are out of scope, every result is a duplicate the second time
	if o.Raw != raw || o.Omitted["out_of_scope"] != 3 || o.Omitted["duplicates"] != 14 {
		t.Errorf("raw and omitted: %s", out.String())
	}
	if !strings.HasSuffix(o.Summary, ", verification off") {
		t.Errorf("summary should say verification is off: %s", o.Summary)
	}
	fi, err := os.Stat(raw)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("raw file must be private: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(raw); !strings.Contains(string(b), "AKIAFAKEFAKEFAKE0001") || strings.Contains(string(b), "info-0") {
		t.Error("raw should hold the engine's stdout, with the full values")
	}
}

func TestVerifyPassesThrough(t *testing.T) {
	bin, argsFile := fakeEngine(t)
	var out, errb bytes.Buffer
	if code := run([]string{"--trufflehog", bin, "--verify", "--scope", sampleScope(t), "--raw", filepath.Join(t.TempDir(), "r"), "-p", "app"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	args, _ := os.ReadFile(argsFile)
	if strings.Contains(string(args), "--no-verification") || !strings.Contains(out.String(), "verification on") {
		t.Errorf("--verify should let trufflehog verify: %s / %s", args, out.String())
	}
}

func TestMissingEngine(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--trufflehog", filepath.Join(t.TempDir(), "nope"), "--scope", sampleScope(t), "-p", "app"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var o output
	json.Unmarshal(out.Bytes(), &o)
	if len(o.Errors) != 1 || o.Errors[0].Kind != "missing_engine" || !strings.Contains(o.Errors[0].Hint, "--trufflehog") || o.Raw != "" {
		t.Errorf("missing engine: %s", out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-p", "app"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d", code)
	}
	if code := run([]string{"--scope", scopeFile(t, "/only/here\n"), "-p", "/elsewhere"}, &out, &errb); code != 1 {
		t.Errorf("nothing in scope: exit %d", code)
	}
	if code := run([]string{"--bogus"}, &out, &errb); code != 1 {
		t.Errorf("bad flag: exit %d", code)
	}
}

func TestMaxBytesPointsToTheInput(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"--max-bytes", "900", "--scope", sampleScope(t), "--input", sample}, &out, &errb)
	if out.Len() > 901 || !strings.Contains(out.String(), `"truncated":true`) || !strings.Contains(out.String(), "read "+sample) {
		t.Errorf("budget: %d bytes: %s", out.Len(), out.String())
	}
}
