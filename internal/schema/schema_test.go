package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-secrets",
		Findings: []Finding{{ID: "github-ab12cd34", Title: "Github", Severity: "medium", Secret: Secret{Value: "ghp_…(40)"}, Locations: []string{"a.env:1", "b.env:3"}, Count: 2, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "npmtoken-ef56ab78", Detector: "NpmToken", Secret: Secret{Value: "npm_…(40)"}, Locations: []string{"test/a.js:1"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "tags", "status", "error", "extra", "context", "new", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestSecretFieldsAreInline(t *testing.T) {
	f := Finding{ID: "aws-x", Title: "AWS", Severity: "critical", Confidence: "verified", Tags: []string{"cloud"}, Secret: Secret{Value: "AKIA…(20)", Extra: map[string]string{"account": "123"}, Context: "key = AKIA…(20)"}, Locations: []string{"prod.env:1"}}
	b, _ := json.Marshal(f)
	want := `{"id":"aws-x","title":"AWS","severity":"critical","confidence":"verified","tags":["cloud"],"secret":"AKIA…(20)","extra":{"account":"123"},"context":"key = AKIA…(20)","locations":["prod.env:1"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "aws-x", Locations: []string{"a.env:1"}, Count: 7}},
		Groups:   []Group{{ID: "npmtoken-y", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["a.env:1"],"count":7`) || !strings.Contains(s, `"count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}
