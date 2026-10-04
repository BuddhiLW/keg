// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package okf_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BuddhiLW/keg/pkg/okf"
)

var update = flag.Bool("update", false, "rewrite golden files")

// golden compares got with testdata/golden/name, rewriting it on -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from golden:\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// TestGoldenComplete completes every testdata/complete/*.md, real node
// shapes taken from KEG kegs, and compares with its golden output.
func TestGoldenComplete(t *testing.T) {
	ins, err := filepath.Glob(filepath.Join("testdata", "complete", "*.md"))
	if err != nil || len(ins) == 0 {
		t.Fatalf("no golden inputs: %v", err)
	}
	d := okf.Defaults{Type: "Note", Title: "From heading", Tags: []string{"keg", "okf"}, Actor: "human:pedro", At: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}
	for _, in := range ins {
		t.Run(filepath.Base(in), func(t *testing.T) {
			buf, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			out, added, err := okf.Complete(string(buf), d)
			got := out + "\n<!-- added: " + strings.Join(added, " ") + " -->\n"
			if err != nil {
				got = "error: " + err.Error() + "\n"
			}
			golden(t, "complete/"+filepath.Base(in), got)
		})
	}
}

func TestGoldenIndexAndLog(t *testing.T) {
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	golden(t, "index.md", okf.RenderIndex(okf.Version, "BLW Zettelkasten", []okf.Item{
		{Title: "Sorry, planned but not yet available", Link: "0/README.md", Description: "This is a filler"},
		{Title: "Knowledge management", Link: "1/README.md"},
		{Title: "`tmux` really is awesome", Link: "10/README.md", Description: "Most of the utilities\npresent in `tmux`"},
	}))
	golden(t, "log.md", okf.RenderLog("BLW Zettelkasten update log", []okf.Change{
		{At: at.Add(-72 * time.Hour), Kind: "Update", Title: "Knowledge management", Link: "/1/README.md"},
		{At: at, Kind: "Update", Title: "`tmux` really is awesome", Link: "/10/README.md"},
		{At: at.Add(-1 * time.Hour), Kind: "Creation", Title: "Sorry, planned", Link: "/0/README.md"},
	}))
}
