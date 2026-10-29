package reduce

import (
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-secrets/internal/schema"
	"github.com/protonnegativo/raijin-secrets/internal/sources"
	"github.com/protonnegativo/raijin-secrets/internal/trufflehog"
)

func sample(t *testing.T) []trufflehog.Result {
	t.Helper()
	f, err := os.Open("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rs, err := trufflehog.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func sampleOpt(t *testing.T) Options {
	t.Helper()
	sc, err := sources.Parse([]string{"app", "ci", "docs", "node_modules", "tests", "file:///nonexistent/shop"})
	if err != nil {
		t.Fatal(err)
	}
	opt := Defaults()
	opt.InScope = sc.Allowed
	return opt
}

func fsResult(det, raw, file string, line int) trufflehog.Result {
	return trufflehog.Result{DetectorName: det, Raw: raw, Source: "Filesystem", File: file, Line: line}
}

func TestSampleRanking(t *testing.T) {
	findings, groups, omitted, _ := Reduce(sample(t), sampleOpt(t))
	var got []string
	for _, f := range findings {
		got = append(got, f.Severity+" "+f.Title+" "+f.Confidence+f.Status)
	}
	want := []string{
		"critical AWS verified", "critical AWS verified", "critical Stripe verified",
		"high Datadog verified",
		"medium Slack unknown", "medium Github ", "medium Slack ",
		"low Calendly ",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("ranking:\ngot  %q\nwant %q", got, want)
	}
	if len(groups) != 1 || groups[0].Detector != "NpmToken" || len(groups[0].Locations) != 2 {
		t.Errorf("groups: %+v", groups)
	}
	if omitted["out_of_scope"] != 1 || omitted["duplicates"] != 1 {
		t.Errorf("omitted: %v", omitted)
	}
}

// Lossless: the same secret in many places is one entry that lists every place; only the exact repeat
// (same detector, secret, status and location) collapses.
func TestSameSecretManyPlacesIsOneEntry(t *testing.T) {
	rs := []trufflehog.Result{
		fsResult("Github", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "a.env", 10),
		fsResult("Github", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "a.env", 2),
		fsResult("Github", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "b.env", 1),
		fsResult("Github", "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "b.env", 1),
	}
	findings, _, omitted, _ := Reduce(rs, Defaults())
	if len(findings) != 1 {
		t.Fatalf("want one finding, got %+v", findings)
	}
	if got := strings.Join(findings[0].Locations, " "); got != "a.env:2 a.env:10 b.env:1" {
		t.Errorf("every location, lines in number order: %s", got)
	}
	if omitted["duplicates"] != 1 {
		t.Errorf("one exact duplicate: %v", omitted)
	}
}

// Lossless: two detectors that match the same value are two entries; so are two values of one detector.
func TestDetectorAndValueSplitEntries(t *testing.T) {
	rs := []trufflehog.Result{
		fsResult("URI", "https://u:pppppppppppp@example.com", "a.env", 1),
		fsResult("Github", "https://u:pppppppppppp@example.com", "a.env", 1),
		fsResult("Github", "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "a.env", 1),
	}
	findings, _, omitted, _ := Reduce(rs, Defaults())
	if len(findings) != 3 || len(omitted) != 0 {
		t.Errorf("three entries, nothing omitted: %+v %v", findings, omitted)
	}
}

// Lossless: RawV2 (a key paired with its secret) identifies the secret, so one key id paired with two
// secrets is two entries.
func TestRawV2SplitsPairs(t *testing.T) {
	a := fsResult("AWS", "AKIAAAAAAAAAAAAAAAAA", "a.env", 1)
	a.RawV2 = "AKIAAAAAAAAAAAAAAAAA:secret-one-secret-one-secret-one-secret-1"
	b := a
	b.RawV2 = "AKIAAAAAAAAAAAAAAAAA:secret-two-secret-two-secret-two-secret-2"
	findings, _, _, _ := Reduce([]trufflehog.Result{a, b}, Defaults())
	if len(findings) != 2 || findings[0].ID == findings[1].ID {
		t.Fatalf("two pairs, two ids: %+v", findings)
	}
	if findings[0].Value != findings[1].Value || !strings.HasPrefix(findings[0].Value, "AKIA…(20)#") {
		t.Errorf("both show the same redacted key id: %q %q", findings[0].Value, findings[1].Value)
	}
}

// Lossless: the same secret verified at one place and unknown at another keeps both statuses.
func TestStatusesAreKept(t *testing.T) {
	v := fsResult("Stripe", "sk_live_cccccccccccccccccccccccc", "a.py", 1)
	v.Verified = true
	u := fsResult("Stripe", "sk_live_cccccccccccccccccccccccc", "b.py", 1)
	u.VerificationError = "timeout"
	findings, _, _, _ := Reduce([]trufflehog.Result{u, v}, Defaults())
	if len(findings) != 2 {
		t.Fatalf("two statuses, two entries: %+v", findings)
	}
	if findings[0].Confidence != "verified" || findings[0].ID != ID("Stripe", v.Raw) {
		t.Errorf("verified first, with the plain id: %+v", findings[0])
	}
	if findings[1].Status != "unknown" || findings[1].Error != "timeout" || findings[1].ID != ID("Stripe", v.Raw)+"-unknown" {
		t.Errorf("unknown second, with its error and the status in its id: %+v", findings[1])
	}
}

// Lossless: a verified secret is a finding even when it is only in a test or docs path.
func TestVerifiedIsNeverAGroup(t *testing.T) {
	v := fsResult("Stripe", "sk_live_dddddddddddddddddddddddd", "tests/fixtures/a.py", 1)
	v.Verified = true
	u := fsResult("Stripe", "sk_live_eeeeeeeeeeeeeeeeeeeeeeee", "tests/fixtures/a.py", 2)
	findings, groups, _, _ := Reduce([]trufflehog.Result{v, u}, Defaults())
	if len(findings) != 1 || findings[0].Confidence != "verified" || len(groups) != 1 {
		t.Errorf("verified finding, unverified group: %+v %+v", findings, groups)
	}
}

// An unverified secret seen in production code and in a test is a finding with both places.
func TestOneProductionPlaceMakesAFinding(t *testing.T) {
	rs := []trufflehog.Result{
		fsResult("Slack", "xoxb-1111111111-2222222222-ffffffffffff", "tests/a.py", 1),
		fsResult("Slack", "xoxb-1111111111-2222222222-ffffffffffff", "src/a.py", 1),
	}
	findings, groups, _, _ := Reduce(rs, Defaults())
	if len(findings) != 1 || len(findings[0].Locations) != 2 || len(groups) != 0 {
		t.Errorf("one finding with both places: %+v %+v", findings, groups)
	}
}

func TestNonProd(t *testing.T) {
	for file, want := range map[string]bool{
		"src/app.py": false, "config/prod.env": false, "tests/a.py": true, "pkg/x_test.go": true,
		"web/a.spec.ts": true, "test_api.py": true, ".env.example": true, "README.md": true,
		"node_modules/x/index.js": true, "vendor/github.com/x/y.go": true, "docs/guide.html": true,
		"contest/a.py": false, "latest.env": false,
	} {
		if NonProd(file) != want {
			t.Errorf("NonProd(%q) = %v", file, !want)
		}
	}
}

func TestSeverity(t *testing.T) {
	for _, c := range []struct{ status, class, want string }{
		{"verified", "cloud", "critical"}, {"verified", "", "high"},
		{"unknown", "cloud", "medium"}, {"unverified", "cloud", "medium"}, {"unverified", "", "low"},
	} {
		if got := Severity(c.status, c.class); got != c.want {
			t.Errorf("Severity(%s, %s) = %s, want %s", c.status, c.class, got, c.want)
		}
	}
	if Class("aws") != "cloud" || Class("PrivateKey") != "key" || Class("Calendly") != "" {
		t.Error("detector classes")
	}
}

func TestLocations(t *testing.T) {
	g := trufflehog.Result{Commit: "0123456789abcdef0123", File: "a.env", Line: 3, Repository: "file:///r", DecoderName: "BASE64"}
	if got := Location(g, false); got != "0123456789ab:a.env:3 [BASE64]" {
		t.Errorf("git location: %s", got)
	}
	if got := Location(g, true); got != "file:///r 0123456789ab:a.env:3 [BASE64]" {
		t.Errorf("git location with repo: %s", got)
	}
	if got := Location(trufflehog.Result{File: "a.env"}, false); got != "a.env" {
		t.Errorf("no line: %s", got)
	}
	if got := ScopeTarget(g); got != "file:///r/a.env" {
		t.Errorf("scope target: %s", got)
	}
}

func TestTwoRepositoriesPrefixTheLocation(t *testing.T) {
	a := trufflehog.Result{DetectorName: "Github", Raw: "ghp_gggggggggggggggggggggggggggggggggggg", Commit: "aaaaaaaaaaaaaaaa", File: "x", Line: 1, Repository: "https://example.com/one"}
	b := a
	b.Repository = "https://example.com/two"
	findings, _, _, _ := Reduce([]trufflehog.Result{a, b}, Defaults())
	if got := strings.Join(findings[0].Locations, "|"); got != "https://example.com/one aaaaaaaaaaaa:x:1|https://example.com/two aaaaaaaaaaaa:x:1" {
		t.Errorf("locations: %s", got)
	}
}

func TestSecretsNeverReachTheOutput(t *testing.T) {
	aws := fsResult("AWS", "AKIAHHHHHHHHHHHHHHHH", "a.env", 1)
	aws.RawV2 = "AKIAHHHHHHHHHHHHHHHH:ssssssssssssssssssssssssssssssssssssssss"
	aws.SecretParts = map[string]any{"key": "AKIAHHHHHHHHHHHHHHHH", "secret": "ssssssssssssssssssssssssssssssssssssssss", "host": "example.com"}
	aws.ExtraData = map[string]any{"arn": "arn:aws:iam::1:user/x", "leak": "ssssssssssssssssssssssssssssssssssssssss", "rotation_guide": "https://x", "version": 2}
	opt := Defaults()
	opt.Line = func(trufflehog.Result) (string, bool) {
		return "export AWS=AKIAHHHHHHHHHHHHHHHH SECRET=ssssssssssssssssssssssssssssssssssssssss HOST=example.com OTHER=b64QmFzZTY0RW5jb2RlZFNlY3JldFZhbHVlMTIzNDU2", true
	}
	findings, _, _, _ := Reduce([]trufflehog.Result{aws}, opt)
	b, _ := schema.Marshal(findings)
	s := string(b)
	for _, leak := range []string{"AKIAHHHHHHHHHHHHHHHH", "ssssssssssssssss", "QmFzZTY0RW5jb2Rl", "rotation_guide", `"version"`} {
		if strings.Contains(s, leak) {
			t.Errorf("%s leaked: %s", leak, s)
		}
	}
	if !strings.Contains(s, "HOST=example.com") || !strings.Contains(s, `"arn":"arn:aws:iam::1:user/x"`) {
		t.Errorf("public parts and extra data should stay: %s", s)
	}
}

func TestContextIsCutAroundTheSecret(t *testing.T) {
	red := newRedactor([]trufflehog.Result{{Raw: "tok_1234567890abcdef"}})
	line := strings.Repeat("a ", 100) + "key=tok_1234567890abcdef " + strings.Repeat("b ", 100)
	c := red.context(line, 60)
	if !strings.Contains(c, "key=tok_…(20)#") || !strings.HasPrefix(c, "...") || !strings.HasSuffix(c, "...") || len([]rune(c)) != 66 {
		t.Errorf("context: %q", c)
	}
	if red.context("no secret here", 60) != "" {
		t.Error("a line without the secret has no context")
	}
}

func TestRedact(t *testing.T) {
	for in, want := range map[string]string{
		"AKIAIOSFODNN7EXAMPL0": "AKIA…(20)#",
		"short123":             "sh…(8)#",
		"abc":                  "…(3)#",
	} {
		if got := Redact(in); !strings.HasPrefix(got, want) || len(got) != len(want)+8 {
			t.Errorf("Redact(%q) = %q", in, got)
		}
	}
	if !strings.HasSuffix(Redact("x"), Hash("x")[:8]) || !strings.HasSuffix(ID("AWS", "x"), Hash("x")[:8]) || !strings.HasPrefix(ID("AWS", "x"), "aws-") {
		t.Error("hash suffix")
	}
}

func TestMaxItemsCountsWhatItCuts(t *testing.T) {
	opt := sampleOpt(t)
	opt.MaxItems = 3
	findings, _, omitted, all := Reduce(sample(t), opt)
	if len(findings) != 3 || omitted["findings"] != 5 || len(all) != 8 {
		t.Errorf("findings %d, omitted %v, state locations %d", len(findings), omitted, len(all))
	}
}

func TestFitCutsGroupsThenContextThenLocations(t *testing.T) {
	findings, groups, omitted, _ := Reduce(sample(t), sampleOpt(t))
	for i := range findings {
		findings[i].Context = "some context line for the budget test"
	}
	res := schema.Result{Tool: "raijin-secrets", Findings: findings, Groups: groups, Omitted: omitted}
	full := size(res)
	Fit(&res, full-10)
	if !res.Budget.Truncated || res.Omitted["locations"] != 2 || res.Omitted["context"] != 0 || len(res.Findings) != 8 {
		t.Errorf("a small cut takes group data first: %v", res.Omitted)
	}
	Fit(&res, 1200)
	if size(res) > 1200 || res.Omitted["context"] == 0 || res.Omitted["groups"] != 1 {
		t.Errorf("then groups and context: size %d, omitted %v", size(res), res.Omitted)
	}
	n := 0
	for _, f := range res.Findings {
		n += max(f.Count, len(f.Locations))
	}
	if n+res.Omitted["findings"] == 0 {
		t.Error("the counts must survive the cut")
	}
	if res.Findings[0].ID != findings[0].ID {
		t.Error("the top finding stays")
	}
}
