// Command raijin-secrets runs trufflehog and returns a small, grouped, ranked result for AI agents.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strings"

	coreschema "github.com/protonnegativo/raijin-core/schema"
	"github.com/protonnegativo/raijin-core/scope"
	"github.com/protonnegativo/raijin-core/state"
	raijinsecrets "github.com/protonnegativo/raijin-secrets"
	"github.com/protonnegativo/raijin-secrets/internal/banner"
	"github.com/protonnegativo/raijin-secrets/internal/reduce"
	"github.com/protonnegativo/raijin-secrets/internal/schema"
	"github.com/protonnegativo/raijin-secrets/internal/sources"
	"github.com/protonnegativo/raijin-secrets/internal/trufflehog"
)

// version is the release this binary was built from, read once from the build info.
var version = buildVersion(debug.ReadBuildInfo())

// buildVersion is the module version when the binary was installed with go install ...@vX.Y.Z or
// @latest, and otherwise "dev" with the VCS revision (12 chars) and +dirty for a local go build. Go
// 1.24 stamps local builds with a pseudo-version (v0.0.0-<time>-<rev>[+dirty]), which is not a release.
func buildVersion(bi *debug.BuildInfo, ok bool) string {
	if !ok || bi == nil {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" && !strings.Contains(v, "+dirty") && !pseudoRe.MatchString(v) {
		return v
	}
	v := "dev"
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" {
		if len(rev) > 12 {
			rev = rev[:12]
		}
		v += "-" + rev
	}
	if dirty {
		v += "+dirty"
	}
	return v
}

// pseudoRe matches the time-revision suffix of a Go pseudo-version.
var pseudoRe = regexp.MustCompile(`\d{14}-[0-9a-f]{12}$`)

// versionLine is what --version prints: the release and the tested engine version.
func versionLine() string {
	line := "raijin-secrets " + version
	if e, ok := engines()["trufflehog"]; ok && e.Version != "" {
		line += " (tested with trufflehog " + e.Version + ")"
	}
	return line
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-secrets", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var paths, repos, inputs multi
	fs.Var(&paths, "p", "local path to scan as files (repeatable; trufflehog filesystem)")
	fs.Var(&repos, "g", "git repository to scan with its history: a file:// or remote URL, or a local path (repeatable; trufflehog git)")
	list := fs.String("l", "", "file with one target per line: URLs are git repositories, anything else a path")
	scopeFile := fs.String("scope", "", "scope file (required): paths, repository URLs, URL prefixes with *, !exclusions")
	verify := fs.Bool("verify", false, "let trufflehog verify each secret: this SENDS the secret to the provider's API (off by default)")
	noContext := fs.Bool("no-context", false, "do not read the source line of each finding")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for trufflehog's full JSON output, with the full secret values (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	fs.Var(&inputs, "input", "read existing trufflehog JSON output instead of running trufflehog (repeatable)")
	bin := fs.String("trufflehog", "trufflehog", "path to the trufflehog binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-secrets --scope scope.txt (-p path | -g repo | -l targets.txt | --input results.jsonl) [flags] [-- extra trufflehog args]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-secrets", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, versionLine())
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-secrets: --scope is required")
		return 1
	}
	res := schema.Result{
		Tool:     "raijin-secrets",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}
	sc, err := sources.Load(*scopeFile)
	if err != nil {
		// An invalid scope is never a warning: nothing runs, and the errors say what to write instead.
		res.Errors = append(res.Errors, scope.SchemaErrors(err)...)
		res.Summary = "invalid scope file, nothing scanned"
		write(stdout, &res, *format, *pretty)
		return 1
	}
	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed
	if !*noContext {
		opt.Line = (&trufflehog.Lines{}).Line
	}

	var results []trufflehog.Result
	var stats trufflehog.Stats
	verification := ""
	if len(inputs) > 0 {
		for _, in := range inputs {
			b, err := os.ReadFile(in)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-secrets:", err)
				return 1
			}
			r, st, err := trufflehog.ParseStats(bytes.NewReader(b))
			if err != nil {
				fmt.Fprintln(stderr, "raijin-secrets:", err)
				return 1
			}
			stats.Lines += st.Lines
			stats.Bad += st.Bad
			results = append(results, r...)
		}
		res.Target = strings.Join(inputs, ", ")
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-secrets:", err)
				return 1
			}
			for _, l := range lines {
				if strings.Contains(l, "://") {
					repos = append(repos, l)
				} else {
					paths = append(paths, l)
				}
			}
		}
		inPaths := filter(paths, false, sc, res.Omitted)
		inRepos := filter(repos, true, sc, res.Omitted)
		if len(inPaths)+len(inRepos) == 0 {
			fmt.Fprintln(stderr, "raijin-secrets: no targets in scope")
			return 1
		}
		res.Target = targetSummary(inPaths, inRepos, res.Omitted["out_of_scope"])

		if *rawPath == "" {
			f, err := os.CreateTemp("", "raijin-secrets-*.jsonl")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-secrets:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		// The raw file holds the full secret values: only the user can read it.
		raw, err := os.OpenFile(*rawPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-secrets:", err)
			return 1
		}
		defer raw.Close()
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if e, ok := engines()["trufflehog"]; ok {
			if hint := trufflehog.VersionHint(trufflehog.Version(*bin), e); hint != "" {
				res.Errors = append(res.Errors, schema.Error{Kind: "engine_version", Hint: hint})
			}
		}
		topt := trufflehog.Options{Binary: *bin, Verify: *verify, Extra: fs.Args(), Raw: raw, Stats: &stats}
		scans := []func() ([]trufflehog.Result, string, error){}
		if len(inPaths) > 0 {
			scans = append(scans, func() ([]trufflehog.Result, string, error) { return trufflehog.Filesystem(ctx, inPaths, topt) })
		}
		for _, repo := range inRepos {
			scans = append(scans, func() ([]trufflehog.Result, string, error) { return trufflehog.Git(ctx, repo, topt) })
		}
		for _, scan := range scans {
			r, stderrTail, err := scan()
			switch {
			case errors.Is(err, trufflehog.ErrNotFound):
				res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install trufflehog (https://github.com/trufflesecurity/trufflehog#floppy_disk-installation) or pass --trufflehog <path>, or run raijin-mcp update"})
				res.Summary = "trufflehog not found, nothing scanned"
				res.Raw = ""
				raw.Close()
				os.Remove(*rawPath)
				write(stdout, &res, *format, *pretty)
				return 2
			case err != nil:
				hint := err.Error()
				if stderrTail != "" {
					hint += ": " + stderrTail
				}
				res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: hint})
			}
			results = append(results, r...)
		}
		verification = "verification off"
		if *verify {
			verification = "verification on"
		}
	}

	if stats.Bad > 0 {
		src := res.Raw
		if src == "" {
			src = strings.Join(inputs, ", ")
		}
		res.Errors = append(res.Errors, schema.Error{Kind: "engine_format", Hint: fmt.Sprintf("%d of %d trufflehog results had no DetectorName, SourceMetadata.Data and Raw or RawV2, or were not JSON; the engine's output format may have changed. Read %s for the full output", stats.Bad, stats.Lines, src)})
		res.Omitted["unparsed"] += stats.Bad
	}

	findings, groups, omitted, allLocations := reduce.Reduce(results, opt)
	res.Findings, res.Groups = findings, groups
	for k, v := range omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = state.Mark(st, res.Findings, allLocations,
				func(f *schema.Finding) string { return f.Fingerprint },
				func(f *schema.Finding) { f.New = true })
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, len(results)-omitted["out_of_scope"]-omitted["duplicates"], verification, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + strings.Join(inputs, ", "); src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// engines are the tested engine versions from engines.json.
func engines() map[string]trufflehog.Engine {
	m, _ := trufflehog.Engines(raijinsecrets.EnginesJSON)
	return m
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// filter keeps the targets the scope allows. A git repository given as a local path becomes a file://
// URL, which is what trufflehog git takes.
func filter(targets []string, git bool, sc *sources.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if git && !strings.Contains(t, "://") {
			t = "file://" + sources.Path(t)
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, t)
	}
	return out
}

func targetSummary(paths, repos []string, skipped int) string {
	var parts []string
	if len(paths)+len(repos) == 1 {
		parts = append(parts, append(paths, repos...)[0])
	} else {
		if len(paths) > 0 {
			parts = append(parts, fmt.Sprintf("%d path(s)", len(paths)))
		}
		if len(repos) > 0 {
			parts = append(parts, fmt.Sprintf("%d repo(s)", len(repos)))
		}
	}
	s := strings.Join(parts, ", ")
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, results int, verification string, newCount int) string {
	bySev := map[string]int{}
	verified := 0
	for _, f := range res.Findings {
		bySev[f.Severity]++
		if f.Confidence == "verified" {
			verified++
		}
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d results, %d secrets, %d findings", results, len(res.Findings)+len(res.Groups)+res.Omitted["findings"], len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d verified, %d groups", verified, len(res.Groups))
	if verification != "" {
		s += ", " + verification
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			status := "unverified"
			if f.Confidence == "verified" {
				status = "verified"
			} else if f.Status != "" {
				status = f.Status
			}
			fmt.Fprintf(w, "%-8s %s %s %s (%d)%s\n", strings.ToUpper(f.Severity), f.Title, f.Value, status, max(f.Count, len(f.Locations)), mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "group    %s %s (%d)\n", g.Detector, g.Value, max(g.Count, len(g.Locations)))
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	_ = coreschema.Write(w, res, pretty)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
