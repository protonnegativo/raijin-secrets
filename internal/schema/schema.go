// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every secret trufflehog reported is listed, in a finding
// or in a group, with every place it was found, and anything a budget cuts is counted in Omitted. What an
// agent can rebuild is left out of the JSON to save tokens: empty lists, the budget when nothing was cut,
// a count equal to the locations listed, and fields at their documented default.
//
// raijin-secrets adds the redacted secret (secret, status, error, extra, context) to findings
// and groups. The full secret value is never written to stdout: it stays in the raw file.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "->" stays "->" instead of "->", which costs
// tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out. It holds the
	// full secret values.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Secret is one secret value as an agent reads it: redacted, with what trufflehog said about it. Zero
// values are left out: no status means unverified.
type Secret struct {
	// Value is the redacted secret: its first characters, its length and the first 8 hex digits of its
	// SHA-256, "AKIA…(20)#1a2b3c4d". The id of the finding or group ends in the same 8 digits of the
	// SHA-256 of the value that identifies the secret (see reduce.ID).
	Value string `json:"secret"`
	// Status is "unknown" when verification was attempted and failed with an error. A verified secret
	// has confidence "verified" instead; no status and no confidence means unverified.
	Status string `json:"status,omitempty"`
	// Error is trufflehog's verification error, for status "unknown".
	Error string `json:"error,omitempty"`
	// Extra is trufflehog's ExtraData (account, token type, host, user...), redacted, without the
	// rotation guide link and the detector version.
	Extra map[string]string `json:"extra,omitempty"`
	// Context is the line the secret was found on, at the first location, with every secret redacted and
	// cut around the secret. Left out when the file cannot be read.
	Context string `json:"context,omitempty"`
}

// Finding is one secret worth acting on, with every place it was found. The same tool and ID in two runs
// is the same finding.
type Finding struct {
	ID string `json:"id"`
	// Title is the trufflehog detector that found the secret (AWS, Github, Postgres...).
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" when the provider accepted the secret; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the risk class of the detector (cloud, code, database...), when it has one.
	Tags []string `json:"tags,omitempty"`
	Secret
	// Locations are every place the secret was found: "file:line" or "commit:file:line", plus
	// " [BASE64]" (or another decoder) when trufflehog found it in decoded text.
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Group is one unverified secret found only in test, example, documentation or vendored paths, with
// every place it was found.
type Group struct {
	ID       string `json:"id"`
	Detector string `json:"detector"`
	Secret
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}
