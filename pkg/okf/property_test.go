// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package okf_test

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/BuddhiLW/keg/pkg/okf"
)

var cfg = &quick.Config{MaxCount: 2000}

// words are the atoms generated text is built from, chosen to stress
// YAML and markdown: colons, quotes, hashes and the delimiter itself.
var words = []string{"note", "a: b", "'q'", `"dq"`, "#tag", "---", "- item", "x", "ü", "  ", "{", "[1]", "true", "2023-01-06"}

func word(r *rand.Rand) string { return words[r.Intn(len(words))] }

func phrase(r *rand.Rand) string {
	n := 1 + r.Intn(4)
	ws := make([]string, n)
	for i := range ws {
		ws[i] = word(r)
	}
	return strings.Join(ws, " ")
}

// Doc is a generated KEG node: an optional front matter of well-formed
// keys over a markdown body that may itself contain delimiter lines.
type Doc struct {
	Front   bool
	Keys    map[string]string
	Body    string
	Content string
}

func (Doc) Generate(r *rand.Rand, _ int) reflect.Value {
	d := Doc{Front: r.Intn(3) > 0, Keys: map[string]string{}}
	for _, k := range []string{"title", "description", "published", "draft", "type", "tags", "custom"} {
		if r.Intn(2) == 0 {
			continue
		}
		switch k {
		case "draft":
			d.Keys[k] = fmt.Sprint(r.Intn(2) == 0)
		case "type":
			d.Keys[k] = fmt.Sprintf("%q", "Note "+phrase(r))
		case "tags":
			d.Keys[k] = fmt.Sprintf("[%q]", phrase(r))
		default:
			d.Keys[k] = fmt.Sprintf("%q", phrase(r))
		}
	}
	var b strings.Builder
	if r.Intn(2) == 0 {
		b.WriteString("# " + phrase(r) + "\n")
	}
	for i := r.Intn(5); i > 0; i-- {
		b.WriteString(phrase(r) + "\n")
	}
	d.Body = b.String()
	d.Content = d.Body
	if d.Front {
		keys := make([]string, 0, len(d.Keys))
		for k := range d.Keys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var fm strings.Builder
		for _, k := range keys {
			fm.WriteString(k + ": " + d.Keys[k] + "\n")
		}
		d.Content = okf.Join(fm.String(), d.Body)
	}
	return reflect.ValueOf(d)
}

// Defs are generated Complete defaults.
type Defs struct{ okf.Defaults }

func (Defs) Generate(r *rand.Rand, _ int) reflect.Value {
	d := okf.Defaults{
		Type:  "Note",
		Title: phrase(r),
		Actor: "human:" + word(r),
		At:    time.Unix(r.Int63n(4e9), 0).UTC(),
	}
	for i := r.Intn(3); i > 0; i-- {
		d.Tags = append(d.Tags, phrase(r))
	}
	return reflect.ValueOf(Defs{d})
}

// A body that opens with a `---` rule and holds another one is, per
// OKF, a front matter block; when that block is not YAML, Complete must
// refuse and leave the content alone rather than guess.
func TestPropCompletedDocumentsConform(t *testing.T) {
	prop := func(doc Doc, d Defs) bool {
		out, _, err := okf.Complete(doc.Content, d.Defaults)
		if err != nil {
			return out == doc.Content && okf.CheckConcept(doc.Content) == okf.BadYAML
		}
		return okf.CheckConcept(out) == ""
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestPropCompleteIsIdempotent(t *testing.T) {
	prop := func(doc Doc, d Defs) bool {
		once, _, err := okf.Complete(doc.Content, d.Defaults)
		if err != nil {
			return once == doc.Content
		}
		twice, added, err := okf.Complete(once, d.Defaults)
		return err == nil && twice == once && added == nil
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestPropCompleteKeepsBodyAndExistingKeys(t *testing.T) {
	prop := func(doc Doc, d Defs) bool {
		out, added, err := okf.Complete(doc.Content, d.Defaults)
		if err != nil {
			return out == doc.Content
		}
		// What the input's front matter and body are, as OKF reads them.
		origBlock, origBody, had := okf.Split(doc.Content)
		if !had {
			origBlock, origBody = "", doc.Content
		}
		have, _ := okf.Fields(origBlock)
		block, body, ok := okf.Split(out)
		if !ok || body != origBody || !strings.HasPrefix(block, origBlock) {
			return false
		}
		for _, k := range added {
			if _, was := have[k]; was {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestPropSplitInvertsJoin(t *testing.T) {
	prop := func(doc Doc) bool {
		var block strings.Builder
		for k, v := range doc.Keys {
			block.WriteString(k + ": " + v + "\n")
		}
		b, body, ok := okf.Split(okf.Join(block.String(), doc.Body))
		return ok && b == block.String() && body == doc.Body
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}

// Changes are generated log entries.
type Changes []okf.Change

func (Changes) Generate(r *rand.Rand, _ int) reflect.Value {
	cs := make(Changes, r.Intn(20))
	for i := range cs {
		cs[i] = okf.Change{At: time.Unix(r.Int63n(4e9), 0), Kind: "Update", Title: phrase(r), Link: fmt.Sprintf("/%d/README.md", i)}
	}
	return reflect.ValueOf(cs)
}

func TestPropLogConformsNewestFirstAndKeepsEveryEntry(t *testing.T) {
	prop := func(cs Changes) bool {
		log := okf.RenderLog("Log", cs)
		if okf.CheckLog(log) != "" || strings.Count(log, "* **Update**: ") != len(cs) {
			return false
		}
		var dates []string
		for _, line := range strings.Split(log, "\n") {
			if d, ok := strings.CutPrefix(line, "## "); ok {
				dates = append(dates, d)
			}
		}
		for i := 1; i < len(dates); i++ {
			if dates[i] >= dates[i-1] {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, cfg); err != nil {
		t.Fatal(err)
	}
}
