// Package reduce turns raw trufflehog results into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every secret trufflehog reported is kept, with its detector,
// its verification status and every place it was found. The same secret found in many places is one
// entry that lists every place. Only exact duplicates are dropped. Secret values are redacted; the full
// values stay in the raw file. A byte budget can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/protonnegativo/raijin-secrets/internal/schema"
	"github.com/protonnegativo/raijin-secrets/internal/trufflehog"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems    int // 0 keeps every finding
	MaxBytes    int
	MaxContext  int // longest context line, in characters
	MaxLocation int // longest location string
	InScope     func(target string) bool
	// Line returns the source line of a result for its context; nil writes no context.
	Line func(trufflehog.Result) (string, bool)
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 32000, MaxContext: 120, MaxLocation: 300}
}

// classes are the detectors whose secrets give access to infrastructure, code, data, money or an
// account that sends messages or bills by use. A secret from one of them is critical when verified and
// medium when not; any other detector's is high when verified and low when not. The class is the tag.
var classes = map[string]string{}

func init() {
	for class, names := range map[string][]string{
		"cloud": {"AWS", "AWSSessionKey", "Azure", "AzureStorage", "AzureSAS", "AzureBatch", "AzureContainerRegistry",
			"AzureSearchAdminKey", "AzureEntra", "GCP", "GCPApplicationDefaultCredentials", "GoogleOauth2", "Alibaba",
			"DigitalOceanToken", "DigitalOceanV2", "Heroku", "CloudflareApiToken", "CloudflareGlobalApiKey",
			"CloudflareCaKey", "Linode", "Scaleway", "Netlify", "Vercel", "Okta", "HashiCorpVaultAuth", "IBMCloudUserKey",
			"TencentCloudKey", "Fastly", "Pulumi"},
		"key": {"PrivateKey", "JWT", "Ssh"},
		"code": {"Github", "GitHubApp", "GithubApp", "GitHubOauth2", "GitHubOauth2V2", "Gitlab", "GitlabV2", "Bitbucket",
			"AzureDevopsPersonalAccessToken", "CircleCI", "TravisCI", "JenkinsAPIToken", "Buildkite", "BuildkiteV2",
			"TerraformCloudPersonalToken", "Dockerhub", "DockerHub", "NpmToken", "NpmTokenV2", "PyPI", "RubyGems",
			"Artifactory", "JFrog", "Postman", "Sentry", "SentryToken"},
		"database": {"Postgres", "MongoDB", "MySQL", "JDBC", "URI", "Redis", "SQLServer", "FTP", "LDAP", "Snowflake",
			"Databricks", "DatabricksToken", "PlanetScale", "PlanetScaleDb", "Supabase", "SupabaseToken", "ElasticCloud"},
		"payment": {"Stripe", "StripePaymentIntent", "Square", "SquareApp", "PaypalOauth", "Braintree", "Shopify",
			"Razorpay", "Plaid", "Coinbase", "Adyen"},
		"messaging": {"Slack", "SlackWebhook", "Twilio", "TwilioApiKey", "SendGrid", "Mailgun", "Mailchimp", "Postmark",
			"TelegramBotToken", "DiscordBotToken", "DiscordWebhook", "MicrosoftTeamsWebhook", "Mailjet", "Sendinblue",
			"Brevo"},
		"ai": {"OpenAI", "OpenAIAdmin", "Anthropic", "HuggingFace", "Replicate", "Groq", "Cohere", "MistralAI",
			"DeepSeek", "ElevenLabs", "Perplexity"},
	} {
		for _, n := range names {
			classes[strings.ToLower(n)] = class
		}
	}
}

// Class is the risk class of a detector ("cloud", "code"...), or "" for any other detector.
func Class(detector string) string {
	return classes[strings.ToLower(detector)]
}

// Severity is fixed by the verification status and the detector's class.
//
//	verified, class     critical
//	verified            high
//	not verified, class medium
//	not verified        low
func Severity(status, class string) string {
	switch {
	case status == "verified" && class != "":
		return "critical"
	case status == "verified":
		return "high"
	case class != "":
		return "medium"
	}
	return "low"
}

var statusRank = map[string]int{"verified": 2, "unknown": 1, "unverified": 0}

// nonProd are path segments of test, example, documentation and vendored code: an unverified secret
// found only under them is a group, not a finding.
var nonProd = map[string]bool{}

// nonProdFile matches file names of tests, examples and docs: foo_test.go, foo.spec.ts, test_foo.py,
// .env.example, config.sample.yml, README.md.
var nonProdFile = regexp.MustCompile(`(?i)(_test\.|\.test\.|\.spec\.|^test_|\.example$|\.example\.|\.sample$|\.sample\.|\.dist$|\.md$|\.rst$|\.adoc$)`)

func init() {
	for _, s := range []string{"test", "tests", "testing", "testdata", "test-data", "test_data", "__tests__", "__mocks__",
		"spec", "specs", "fixture", "fixtures", "example", "examples", "sample", "samples", "demo", "demos", "doc", "docs",
		"mock", "mocks", "vendor", "node_modules", "bower_components", "third_party", "third-party", "site-packages",
		".venv", "venv"} {
		nonProd[s] = true
	}
}

// NonProd is true when a file is test, example, documentation or vendored code, by its path.
func NonProd(file string) bool {
	parts := strings.Split(strings.ReplaceAll(file, "\\", "/"), "/")
	for _, p := range parts[:len(parts)-1] {
		if nonProd[strings.ToLower(p)] {
			return true
		}
	}
	return nonProdFile.MatchString(parts[len(parts)-1])
}

type entry struct {
	detector, value, shown, status string
	errs                           map[string]bool
	extra                          map[string]map[string]bool
	locs                           map[string]trufflehog.Result
	prod                           bool // at least one location is not test, example, docs or vendored code
}

// Reduce collapses the results into findings and groups: one entry per secret (detector, value and
// verification status), listing every place it was found. It also returns every location per finding
// fingerprint, before any budget, for --state.
func Reduce(results []trufflehog.Result, opt Options) ([]schema.Finding, []schema.Group, map[string]int, map[string][]string) {
	omitted := map[string]int{}
	var kept []trufflehog.Result
	for _, r := range results {
		if opt.InScope != nil && !opt.InScope(ScopeTarget(r)) {
			omitted["out_of_scope"]++
			continue
		}
		kept = append(kept, r)
	}
	repos := map[string]bool{}
	for _, r := range kept {
		if r.Commit != "" {
			repos[r.Repository] = true
		}
	}
	red := newRedactor(kept)

	entries := map[string]*entry{}
	for _, r := range kept {
		key := r.DetectorName + "\x00" + r.Value() + "\x00" + r.Status()
		e := entries[key]
		if e == nil {
			e = &entry{detector: r.DetectorName, value: r.Value(), shown: r.Shown(), status: r.Status(),
				errs: map[string]bool{}, extra: map[string]map[string]bool{}, locs: map[string]trufflehog.Result{}}
			entries[key] = e
		}
		loc := cut(Location(r, len(repos) > 1), opt.MaxLocation)
		if _, dup := e.locs[loc]; dup {
			omitted["duplicates"]++
			continue
		}
		e.locs[loc] = r
		if !NonProd(r.File) {
			e.prod = true
		}
		if r.VerificationError != "" {
			e.errs[r.VerificationError] = true
		}
		for k, v := range r.ExtraData {
			if k == "rotation_guide" || k == "version" {
				continue
			}
			s := strings.TrimSpace(fmt.Sprint(v))
			if v == nil || s == "" {
				continue
			}
			if e.extra[k] == nil {
				e.extra[k] = map[string]bool{}
			}
			e.extra[k][s] = true
		}
	}

	// The id is the detector and a hash of the value. The same secret with two statuses (verified at one
	// place, unknown at another) is two entries: the less verified one gets the status in its id.
	ids := map[string][]*entry{}
	for _, e := range entries {
		base := ID(e.detector, e.value)
		ids[base] = append(ids[base], e)
	}
	findings, groups := []schema.Finding{}, []schema.Group{}
	allLocations := map[string][]string{}
	for base, es := range ids {
		sort.Slice(es, func(i, j int) bool { return statusRank[es[i].status] > statusRank[es[j].status] })
		for i, e := range es {
			id := base
			if i > 0 {
				id += "-" + e.status
			}
			locs := sortLocations(e.locs)
			sec := schema.Secret{Value: Redact(e.shown), Error: cut(joinSet(e.errs, " | "), 200)}
			if e.status == "unknown" {
				sec.Status = "unknown"
			}
			if len(e.extra) > 0 {
				sec.Extra = map[string]string{}
				for k, vs := range e.extra {
					sec.Extra[k] = cut(red.text(joinSet(vs, " | ")), 100)
				}
			}
			if e.status != "verified" && !e.prod {
				groups = append(groups, schema.Group{ID: id, Detector: e.detector, Secret: sec, Locations: locs, Count: len(locs)})
				continue
			}
			if opt.Line != nil {
				for _, l := range locs {
					if line, ok := opt.Line(e.locs[l]); ok {
						if c := red.context(line, opt.MaxContext); c != "" {
							sec.Context = c
							break
						}
					}
				}
			}
			class := Class(e.detector)
			f := schema.Finding{ID: id, Title: e.detector, Severity: Severity(e.status, class), Secret: sec,
				Locations: locs, Count: len(locs), Fingerprint: fingerprint(id)}
			if e.status == "verified" {
				f.Confidence = "verified"
			}
			if class != "" {
				f.Tags = []string{class}
			}
			allLocations[f.Fingerprint] = locs
			findings = append(findings, f)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if (a.Status == "unknown") != (b.Status == "unknown") {
			return a.Status == "unknown"
		}
		if len(a.Locations) != len(b.Locations) {
			return len(a.Locations) > len(b.Locations)
		}
		return a.ID < b.ID
	})
	sort.SliceStable(groups, func(i, j int) bool {
		if len(groups[i].Locations) != len(groups[j].Locations) {
			return len(groups[i].Locations) > len(groups[j].Locations)
		}
		return groups[i].ID < groups[j].ID
	})
	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	return findings, groups, omitted, allLocations
}

// ID is the lowercase detector name and the first 8 hex digits of the SHA-256 of the secret value:
// "aws-1a2b3c4d". The same secret has the same id in the next run.
func ID(detector, value string) string {
	sum := sha256.Sum256([]byte(value))
	return strings.ToLower(detector) + "-" + hex.EncodeToString(sum[:4])
}

// Hash is the full SHA-256 of a secret value in hex, of which the id keeps the first 8 digits.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// ScopeTarget is what the scope is checked against: the file path for a filesystem result, the
// repository URL and the file for a git result.
func ScopeTarget(r trufflehog.Result) string {
	switch {
	case r.Repository != "" && r.File != "":
		return strings.TrimSuffix(r.Repository, "/") + "/" + r.File
	case r.Repository != "":
		return r.Repository
	case r.File != "":
		return r.File
	}
	return r.Link
}

// Location is one place a secret was found: "file:line", "commit:file:line" for git (the commit cut to
// 12 hex digits), with the repository first ("repo commit:file:line") when the results come from more
// than one repository, and " [BASE64]" (or another decoder) when the secret was in decoded text.
func Location(r trufflehog.Result, withRepo bool) string {
	var s string
	switch {
	case r.File != "":
		s = r.File
		if r.Commit != "" {
			s = short(r.Commit) + ":" + s
		}
		if r.Line > 0 {
			s += ":" + strconv.Itoa(r.Line)
		}
	case r.Commit != "":
		s = short(r.Commit)
	default:
		s = r.Link
	}
	if withRepo && r.Commit != "" && r.Repository != "" {
		s = r.Repository + " " + s
	}
	if d := r.DecoderName; d != "" && d != "PLAIN" {
		s += " [" + d + "]"
	}
	return s
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

// sortLocations orders locations by repository, commit, file and line (as a number, so a.env:2 comes
// before a.env:10), then by text.
func sortLocations(m map[string]trufflehog.Result) []string {
	out := make([]string, 0, len(m))
	for l := range m {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := m[out[i]], m[out[j]]
		switch {
		case a.Repository != b.Repository:
			return a.Repository < b.Repository
		case a.Commit != b.Commit:
			return a.Commit < b.Commit
		case a.File != b.File:
			return a.File < b.File
		case a.Line != b.Line:
			return a.Line < b.Line
		}
		return out[i] < out[j]
	})
	return out
}

// Redact writes a secret as its first characters, its length and the first 8 hex digits of its SHA-256:
// "AKIA…(20)#1a2b3c4d". It shows 4 characters of a secret of 16 or more, 2 of one of 8 or more, none of
// a shorter one. The hash tells apart two secrets with the same start, and an agent that has a value
// can check it is this one.
func Redact(s string) string {
	r := []rune(s)
	n := 0
	switch {
	case len(r) >= 16:
		n = 4
	case len(r) >= 8:
		n = 2
	}
	return string(r[:n]) + "…(" + strconv.Itoa(len(r)) + ")#" + Hash(s)[:8]
}

// opaque is a long run of token characters: once the known secrets are redacted, any such run left in
// a context line or extra value is cut too, so a secret trufflehog found in decoded (base64) text, or
// one it did not report, never reaches the output.
var opaque = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{32,}`)

// publicPart are SecretParts keys that name where a secret is used, not the secret.
var publicPart = map[string]bool{"host": true, "url": true, "endpoint": true, "domain": true, "region": true,
	"username": true, "user": true, "database": true, "port": true}

// redactor knows every secret value of the run and replaces them in free text.
type redactor struct {
	values []string // longest first
}

func newRedactor(results []trufflehog.Result) *redactor {
	set := map[string]bool{}
	for _, r := range results {
		for _, v := range []string{r.Raw, r.RawV2} {
			if len(v) >= 6 {
				set[v] = true
			}
		}
		for k, v := range r.SecretParts {
			if s, ok := v.(string); ok && len(s) >= 6 && !publicPart[k] {
				set[s] = true
			}
		}
	}
	red := &redactor{}
	for v := range set {
		red.values = append(red.values, v)
	}
	sort.Slice(red.values, func(i, j int) bool {
		if len(red.values[i]) != len(red.values[j]) {
			return len(red.values[i]) > len(red.values[j])
		}
		return red.values[i] < red.values[j]
	})
	return red
}

// text replaces every known secret and every long opaque string with its redacted form.
func (red *redactor) text(s string) string {
	for _, v := range red.values {
		if strings.Contains(s, v) {
			s = strings.ReplaceAll(s, v, Redact(v))
		}
	}
	return opaque.ReplaceAllStringFunc(s, Redact)
}

// context is a redacted source line cut to max characters around the first redacted secret. It is ""
// when nothing in the line was redacted: the secret is not on it in plain text.
func (red *redactor) context(line string, max int) string {
	s := strings.TrimSpace(red.text(line))
	i := strings.Index(s, "…(")
	if i < 0 {
		return ""
	}
	r := []rune(s)
	if max <= 0 || len(r) <= max {
		return s
	}
	at := len([]rune(s[:i]))
	start := at - max/3
	if start < 0 {
		start = 0
	}
	end := start + max
	if end > len(r) {
		end, start = len(r), len(r)-max
	}
	out := string(r[start:end])
	if start > 0 {
		out = "..." + out
	}
	if end < len(r) {
		out += "..."
	}
	return out
}

func joinSet(set map[string]bool, sep string) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, sep)
}

func cut(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the context lines of the lowest-ranked findings, then their
// locations (each keeps one, and its count), then the lowest-ranked findings. Every cut is counted in
// Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		if len(g.Locations) == 0 {
			continue
		}
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if f.Context == "" {
			continue
		}
		before := size(f)
		res.Omitted["context"]++
		f.Context = ""
		total += size(f) - before
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
