package state

import (
	"path/filepath"
	"testing"

	"github.com/protonnegativo/raijin-secrets/internal/schema"
)

func TestMarkAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	st, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	first := []schema.Finding{{ID: "aws-ab12cd34", Fingerprint: "fp1"}}
	if n := st.Mark(first, map[string][]string{"fp1": {"a"}}); n != 1 || !first[0].New {
		t.Fatalf("first run: n=%d new=%v", n, first[0].New)
	}
	if err := st.Save(path); err != nil {
		t.Fatal(err)
	}

	st, _ = Load(path)
	same := []schema.Finding{{ID: "aws-ab12cd34", Fingerprint: "fp1"}}
	if n := st.Mark(same, map[string][]string{"fp1": {"a"}}); n != 0 || same[0].New {
		t.Errorf("same finding on the same location should not be new: n=%d", n)
	}

	newPlace := []schema.Finding{{ID: "aws-ab12cd34", Fingerprint: "fp1"}}
	if n := st.Mark(newPlace, map[string][]string{"fp1": {"a", "b"}}); n != 1 || !newPlace[0].New {
		t.Errorf("a new location should mark the finding as new: n=%d", n)
	}
}
