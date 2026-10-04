// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package okf_test

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/BuddhiLW/keg/pkg/okf"
)

var at = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func defaults() okf.Defaults {
	return okf.Defaults{Type: "Note", Title: "A title", Tags: []string{"go", "keg"}, Actor: "human:pedro", At: at}
}

func TestSplit(t *testing.T) {
	block, body, ok := okf.Split("---\na: 1\n---\n# T\n")
	if !ok || block != "a: 1\n" || body != "# T\n" {
		t.Fatalf("got %q %q %v", block, body, ok)
	}
	if _, _, ok := okf.Split("# no front matter\n"); ok {
		t.Fatal("plain markdown has no front matter")
	}
	if _, _, ok := okf.Split("---\na: 1\n"); ok {
		t.Fatal("an unclosed block is not front matter")
	}
}

func TestCompleteAddsBlockToPlainNode(t *testing.T) {
	out, added, err := okf.Complete("# A title\n\nbody\n", defaults())
	if err != nil {
		t.Fatal(err)
	}
	want := "---\ntype: Note\ntitle: A title\ntags: [go, keg]\ngenerated: {by: 'human:pedro', at: \"2026-10-04T12:00:00Z\"}\n---\n# A title\n\nbody\n"
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	if !reflect.DeepEqual(added, []string{"type", "title", "tags", "generated"}) {
		t.Fatalf("added %v", added)
	}
	if okf.CheckConcept(out) != "" {
		t.Fatalf("completed node does not conform: %s", okf.CheckConcept(out))
	}
}

func TestCompleteKeepsExistingKeysVerbatim(t *testing.T) {
	in := "---\ntitle: \"Mine\"\npublished: \"2023-01-06\"\ndraft: true\nweird:   kept\n---\n\n# Mine\n"
	out, added, err := okf.Complete(in, defaults())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "---\ntitle: \"Mine\"\npublished: \"2023-01-06\"\ndraft: true\nweird:   kept\n") {
		t.Fatalf("existing keys were rewritten:\n%s", out)
	}
	if !strings.HasSuffix(out, "---\n\n# Mine\n") {
		t.Fatalf("body changed:\n%s", out)
	}
	if !reflect.DeepEqual(added, []string{"type", "tags", "generated", "status"}) {
		t.Fatalf("added %v", added)
	}
	if !strings.Contains(out, `at: "2023-01-06T00:00:00Z"`) {
		t.Fatalf("generated.at should come from published:\n%s", out)
	}
	if !strings.Contains(out, "status: draft\n") {
		t.Fatalf("draft should map to status: draft:\n%s", out)
	}
}

func TestCompleteWithoutTagsWritesNoTagsKey(t *testing.T) {
	out, added, err := okf.Complete("# T\n", okf.Defaults{Type: "Note"})
	if err != nil || out != "---\ntype: Note\n---\n# T\n" || !reflect.DeepEqual(added, []string{"type"}) {
		t.Fatalf("got %q %v %v", out, added, err)
	}
}

func TestProblemString(t *testing.T) {
	if s := (okf.Problem{Path: "1/README.md", Kind: okf.NoType}).String(); s != "1/README.md: no type" {
		t.Fatal(s)
	}
}

func TestCompleteIsIdempotent(t *testing.T) {
	once, _, _ := okf.Complete("# A title\n", defaults())
	twice, added, err := okf.Complete(once, defaults())
	if err != nil || twice != once || added != nil {
		t.Fatalf("second pass changed content: %v %v", added, err)
	}
}

func TestCompleteRefusesBlankTypeAndBadYAML(t *testing.T) {
	if _, _, err := okf.Complete("---\ntype:\n---\n", defaults()); err != okf.ErrBlankKey {
		t.Fatalf("blank type: %v", err)
	}
	if _, _, err := okf.Complete("---\na: [\n---\n", defaults()); err == nil {
		t.Fatal("bad yaml must be an error, not a guess")
	}
}

func TestCheckConcept(t *testing.T) {
	cases := map[string]string{
		"# plain\n":                  okf.NoFrontMatter,
		"---\na: [\n---\n":           okf.BadYAML,
		"---\ntitle: x\n---\n":       okf.NoType,
		"---\ntype: \"\"\n---\n":     okf.NoType,
		"---\ntype: Note\n---\nbody": "",
	}
	for in, want := range cases {
		if got := okf.CheckConcept(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestRenderIndexAndLogConform(t *testing.T) {
	idx := okf.RenderIndex(okf.Version, "Nodes", []okf.Item{{Title: "One", Link: "1/README.md", Description: "first\nline"}})
	if !strings.HasPrefix(idx, "---\nokf_version: \"0.2\"\n---\n") || !strings.Contains(idx, "* [One](1/README.md) - first line\n") {
		t.Fatalf("index:\n%s", idx)
	}
	if okf.CheckIndex(idx, true) != "" || okf.CheckIndex(idx, false) == "" {
		t.Fatal("okf_version is allowed only in the root index")
	}
	log := okf.RenderLog("Log", []okf.Change{
		{At: at.Add(-48 * time.Hour), Kind: "Update", Title: "Old", Link: "/1/README.md"},
		{At: at, Kind: "Update", Title: "New", Link: "/2/README.md"},
	})
	if !strings.HasPrefix(log, "# Log\n\n## 2026-10-04\n* **Update**: [New](/2/README.md)\n\n## 2026-10-02\n") {
		t.Fatalf("log:\n%s", log)
	}
	if okf.CheckLog(log) != "" || okf.CheckLog("## yesterday\n") == "" {
		t.Fatal("log date headings")
	}
}

func TestCheckBundle(t *testing.T) {
	bundle := fstest.MapFS{
		"index.md":           {Data: []byte("---\nokf_version: \"0.2\"\n---\n# x\n")},
		"log.md":             {Data: []byte("# Log\n\n## 2026-10-04\n")},
		"1/README.md":        {Data: []byte("---\ntype: Note\n---\n# One\n")},
		"2/README.md":        {Data: []byte("# Two\n")},
		"2/index.md":         {Data: []byte("---\nokf_version: \"0.2\"\n---\n")},
		".git/x.md":          {Data: []byte("ignored")},
		"dex/nodes.tsv":      {Data: []byte("not markdown")},
		"3/notes/README.txt": {Data: []byte("not markdown")},
	}
	files, err := okf.Survey(bundle)
	if err != nil {
		t.Fatal(err)
	}
	ps := okf.Check(files)
	want := []okf.Problem{{Path: "2/README.md", Kind: okf.NoFrontMatter}, {Path: "2/index.md", Kind: okf.IndexFrontMatter}}
	if !reflect.DeepEqual(ps, want) {
		t.Fatalf("got %v want %v", ps, want)
	}
}
