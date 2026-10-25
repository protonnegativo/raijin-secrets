// Package trufflehog runs the trufflehog binary and parses its JSON output.
package trufflehog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// ErrNotFound is returned when the trufflehog binary is not on PATH.
var ErrNotFound = errors.New("trufflehog binary not found")

// Result is one secret trufflehog found at one place. Only the fields an agent acts on are decoded;
// the full line stays in the raw file.
type Result struct {
	DetectorName      string
	DecoderName       string
	Verified          bool
	VerificationError string
	Raw               string
	RawV2             string
	ExtraData         map[string]any
	SecretParts       map[string]any
	// Where it was found, from SourceMetadata.
	Source     string // the source kind: Filesystem, Git, Github...
	File       string
	Line       int
	Commit     string
	Repository string
	Link       string
}

// Status is "verified", "unknown" (verification failed with an error) or "unverified".
func (r Result) Status() string {
	switch {
	case r.Verified:
		return "verified"
	case r.VerificationError != "":
		return "unknown"
	}
	return "unverified"
}

// Value is the secret that identifies the result: RawV2 when trufflehog sets it (it pairs a key with its
// secret, or a token with its host), Raw otherwise.
func (r Result) Value() string {
	if r.RawV2 != "" {
		return r.RawV2
	}
	return r.Raw
}

// Shown is the part of the secret written redacted: Raw, the key itself.
func (r Result) Shown() string {
	if r.Raw != "" {
		return r.Raw
	}
	return r.RawV2
}

// Options are the trufflehog settings Raijin passes through.
type Options struct {
	Binary string
	// Verify lets trufflehog verify each secret, which sends it to the provider's API. Off by default.
	Verify bool
	Extra  []string
	// Raw, if set, receives trufflehog's JSON output unchanged.
	Raw io.Writer
	// Stats, if set, adds up the output lines of every scan.
	Stats *Stats
}

// Filesystem scans local paths.
func Filesystem(ctx context.Context, paths []string, opt Options) ([]Result, string, error) {
	return run(ctx, append([]string{"filesystem"}, append(baseArgs(opt), paths...)...), opt)
}

// Git scans the history of one git repository (a file:// or remote URL).
func Git(ctx context.Context, repo string, opt Options) ([]Result, string, error) {
	return run(ctx, append([]string{"git"}, append(baseArgs(opt), repo)...), opt)
}

// baseArgs are the flags every scan gets. --no-verification is on unless Verify is set, so by default
// no secret leaves the machine.
func baseArgs(opt Options) []string {
	args := []string{"--json", "--no-update"}
	if !opt.Verify {
		args = append(args, "--no-verification")
	}
	return append(args, opt.Extra...)
}

// Args is the full command line for a filesystem scan, for tests and docs.
func Args(paths []string, opt Options) []string {
	return append([]string{"filesystem"}, append(baseArgs(opt), paths...)...)
}

func run(ctx context.Context, args []string, opt Options) ([]Result, string, error) {
	bin := opt.Binary
	if bin == "" {
		bin = "trufflehog"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, "", ErrNotFound
	}
	cmd := exec.CommandContext(ctx, path, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	var r io.Reader = stdout
	if opt.Raw != nil {
		r = io.TeeReader(stdout, opt.Raw)
	}
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	results, st, parseErr := ParseStats(r)
	if opt.Stats != nil {
		opt.Stats.Lines += st.Lines
		opt.Stats.Bad += st.Bad
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		return results, tail(stderr.String(), 3), parseErr
	}
	// 183 is trufflehog's exit code for "results found" with --fail: not an error.
	var exit *exec.ExitError
	if waitErr != nil && !(errors.As(waitErr, &exit) && exit.ExitCode() == 183) {
		return results, tail(stderr.String(), 3), fmt.Errorf("trufflehog exited: %w", waitErr)
	}
	return results, "", nil
}

type line struct {
	SourceMetadata struct {
		Data map[string]map[string]any
	}
	DetectorName      string
	DecoderName       string
	Verified          bool
	VerificationError string
	Raw               string
	RawV2             string
	ExtraData         map[string]any
	SecretParts       map[string]any
	Level             string // set on log lines
}

// Stats counts the output lines Parse read: Lines results or would-be results, Bad of them without the
// fields Raijin needs (DetectorName, SourceMetadata.Data and Raw or RawV2), or not JSON at all. A Bad
// line that grows means trufflehog's output format may have changed.
type Stats struct {
	Lines, Bad int
}

// Parse reads trufflehog JSON output, one result per line. Log lines are skipped; lines that are not
// results are skipped too, and counted in Stats by ParseStats.
func Parse(r io.Reader) ([]Result, error) {
	results, _, err := ParseStats(r)
	return results, err
}

// ParseStats is Parse, and also counts the lines that were not results.
func ParseStats(r io.Reader) ([]Result, Stats, error) {
	var results []Result
	var st Stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var l line
		if b[0] != '{' || json.Unmarshal(b, &l) != nil {
			st.Lines++
			st.Bad++
			continue
		}
		if l.DetectorName == "" && l.Level != "" {
			continue // a log line
		}
		st.Lines++
		if l.DetectorName == "" || (l.Raw == "" && l.RawV2 == "") || len(l.SourceMetadata.Data) == 0 {
			st.Bad++
			continue
		}
		res := Result{
			DetectorName: l.DetectorName, DecoderName: l.DecoderName, Verified: l.Verified,
			VerificationError: l.VerificationError, Raw: l.Raw, RawV2: l.RawV2,
			ExtraData: l.ExtraData, SecretParts: l.SecretParts,
		}
		for kind, d := range l.SourceMetadata.Data {
			res.Source = kind
			res.File = str(d["file"])
			if res.File == "" {
				res.File = str(d["path"])
			}
			res.Commit = str(d["commit"])
			res.Repository = str(d["repository"])
			res.Link = str(d["link"])
			if n, ok := d["line"].(float64); ok {
				res.Line = int(n)
			}
		}
		results = append(results, res)
	}
	return results, st, sc.Err()
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
