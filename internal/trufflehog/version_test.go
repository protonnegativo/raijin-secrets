package trufflehog

import (
	"strings"
	"testing"

	raijinsecrets "github.com/protonnegativo/raijin-secrets"
)

func TestEnginesJSON(t *testing.T) {
	m, err := Engines(raijinsecrets.EnginesJSON)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := m["trufflehog"]
	if _, vok := ParseVersion(e.Version); !ok || !vok || e.Release == "" {
		t.Errorf("engines.json needs trufflehog with a version and a release: %+v", m)
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string][3]int{
		"trufflehog 3.99.3\n":  {3, 99, 3},
		"trufflehog v3.88.0\n": {3, 88, 0},
		"trufflehog dev":       {},
	} {
		got, ok := ParseVersion(in)
		if got != want || ok != (want != [3]int{}) {
			t.Errorf("%q: %v %v", in, got, ok)
		}
	}
}

func TestUntestedVersions(t *testing.T) {
	tested := [3]int{3, 99, 3}
	for v, want := range map[[3]int]bool{
		{3, 99, 3}: false, {3, 99, 4}: false, {3, 100, 0}: false,
		{3, 99, 2}: true, {3, 80, 9}: true, {4, 0, 0}: true, {2, 99, 9}: true,
	} {
		if Untested(v, tested) != want {
			t.Errorf("%v: want %v", v, want)
		}
	}
	e := Engine{Version: "3.99.3", Release: "trufflesecurity/trufflehog"}
	if h := VersionHint("trufflehog 3.80.0", e); !strings.HasPrefix(h, "trufflehog 3.80.0 is not the tested 3.99.3") || !strings.Contains(h, "v3.99.3") {
		t.Errorf("hint: %s", h)
	}
	if VersionHint("trufflehog 3.100.1", e) != "" || VersionHint("garbage", e) != "" {
		t.Error("a newer minor and an unparseable version are silent")
	}
}

func TestParseStatsCountsChangedFormat(t *testing.T) {
	// DetectorName renamed to Detector, as a future trufflehog might
	in := `{"level":"info-0","msg":"running source"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"a.env","line":1}}},"Detector":"AWS","Raw":"AKIA"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"b.env","line":1}}},"DetectorName":"AWS","Raw":"AKIA"}
not json
`
	rs, st, err := ParseStats(strings.NewReader(in))
	if err != nil || len(rs) != 1 || st != (Stats{Lines: 3, Bad: 2}) {
		t.Errorf("results %d, stats %+v, err %v", len(rs), st, err)
	}
}
