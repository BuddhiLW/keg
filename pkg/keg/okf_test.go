// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package keg_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/BuddhiLW/keg/pkg/keg"
	"github.com/BuddhiLW/keg/pkg/okf"
	"github.com/BuddhiLW/keg/pkg/seal"
)

// recorder is a FileWriter that keeps what it was asked to write.
type recorder map[string]string

func (r recorder) WriteFile(name string, data []byte) error {
	r[name] = string(data)
	return nil
}

var sealedNode = seal.Envelope{
	Hint:  "a public hint",
	Armor: "-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----\n",
}.Render()

var settings = keg.OKFSettings{NodeType: keg.OKFNodeType, DexType: keg.OKFDexType, Actor: "human:pedro"}

func sampleKeg() fstest.MapFS {
	return fstest.MapFS{
		"keg":            {Data: []byte("updated: 2026-10-04 10:00:00Z\ntitle: Sample\n")},
		"0/README.md":    {Data: []byte("# Planned\n\nfiller\n")},
		"1/README.md":    {Data: []byte("---\ntitle: \"Mine\"\ndescription: \"first node\"\npublished: \"2023-01-06\"\n---\n\n# Mine\n")},
		"2/README.md":    {Data: []byte(sealedNode)},
		"dex/README.md":  {Data: []byte("")},
		"dex/changes.md": {Data: []byte("* 2026-10-04 10:00:00Z [Planned](../0)\n* 2026-10-03 09:00:00Z [a public hint](../2)\n* 2023-01-06 00:00:00Z [Mine](../1)\n")},
		"dex/nodes.tsv":  {Data: []byte("0\t2026-10-04 10:00:00Z\tPlanned\n")},
		"dex/tags":       {Data: []byte("go 0 1\nsecret 2\n")},
	}
}

func collect(t *testing.T, fsys fstest.MapFS) keg.OKFSnapshot {
	t.Helper()
	snap, err := keg.CollectOKF(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// apply writes a plan's writes back into the in-memory keg.
func apply(t *testing.T, fsys fstest.MapFS, ws []keg.OKFWrite) {
	t.Helper()
	r := recorder{}
	if err := keg.ApplyOKF(r, ws); err != nil {
		t.Fatal(err)
	}
	for p, c := range r {
		fsys[p] = &fstest.MapFile{Data: []byte(c)}
	}
}

func TestPlanOKFFixCompletesNodesAndDexDocs(t *testing.T) {
	plan := keg.PlanOKFFix(collect(t, sampleKeg()), settings)

	got := map[string]string{}
	for _, w := range plan.Writes {
		got[w.Path] = w.Content
	}
	want0 := "---\ntype: Note\ntitle: Planned\ntags: [go]\ngenerated: {by: 'human:pedro', at: \"2026-10-04T10:00:00Z\"}\n---\n# Planned\n\nfiller\n"
	if got["0/README.md"] != want0 {
		t.Errorf("node 0:\n%s", got["0/README.md"])
	}
	if !strings.HasPrefix(got["1/README.md"], "---\ntitle: \"Mine\"\ndescription: \"first node\"\npublished: \"2023-01-06\"\ntype: Note\ntags: [go]\n") {
		t.Errorf("node 1 lost its own keys:\n%s", got["1/README.md"])
	}
	if got["dex/README.md"] != "---\ntype: KEG Index\n---\n" || !strings.HasPrefix(got["dex/changes.md"], "---\ntype: KEG Index\n---\n* 2026") {
		t.Errorf("dex docs: %q %q", got["dex/README.md"], got["dex/changes.md"])
	}
	if _, touched := got["2/README.md"]; touched {
		t.Error("a sealed node was rewritten")
	}
	if !reflect.DeepEqual(plan.Skips, []keg.OKFSkip{{Path: "2/README.md", Reason: "sealed"}}) {
		t.Errorf("skips %v", plan.Skips)
	}
}

func TestFixThenIndexMakesTheKegConformExceptSealedNodes(t *testing.T) {
	fsys := sampleKeg()
	if ps := keg.OKFProblems(collect(t, fsys)); len(ps) != 5 {
		t.Fatalf("before: %v", ps)
	}
	apply(t, fsys, keg.PlanOKFFix(collect(t, fsys), settings).Writes)
	snap := collect(t, fsys)
	if !reflect.DeepEqual(keg.OKFProblems(snap), []okf.Problem{{Path: "2/README.md", Kind: "sealed node: " + okf.NoFrontMatter}}) {
		t.Fatalf("after fix: %v", keg.OKFProblems(snap))
	}
	if again := keg.PlanOKFFix(snap, settings); len(again.Writes) != 0 {
		t.Fatalf("fix is not idempotent: %v", again.Writes)
	}
	if len(snap.Dex) != 3 {
		t.Fatalf("dex with front matter no longer parses: %v", snap.Dex)
	}
	if keg.OKFEnabled(snap) {
		t.Fatal("a keg without index.md has not opted in")
	}
	apply(t, fsys, keg.PlanOKFIndex(snap, "Sample"))
	snap = collect(t, fsys)
	if !keg.OKFEnabled(snap) || len(keg.OKFProblems(snap)) != 1 {
		t.Fatalf("after index: %v", keg.OKFProblems(snap))
	}
}

func TestPlanOKFIndexListsNodesWithoutOpeningSealedOnes(t *testing.T) {
	ws := keg.PlanOKFIndex(collect(t, sampleKeg()), "Sample")
	if ws[0].Path != okf.IndexFile || ws[1].Path != okf.LogFile {
		t.Fatalf("paths %v %v", ws[0].Path, ws[1].Path)
	}
	want := "---\nokf_version: \"0.2\"\n---\n\n# Sample\n\n* [Planned](0/README.md)\n* [Mine](1/README.md) - first node\n* [a public hint](2/README.md)\n"
	if ws[0].Content != want {
		t.Fatalf("index:\n%s", ws[0].Content)
	}
	if !strings.Contains(ws[1].Content, "## 2023-01-06\n* **Update**: [Mine](/1/README.md)\n") {
		t.Fatalf("log:\n%s", ws[1].Content)
	}
}

func TestOKFSettingsFor(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if a := keg.OKFSettingsFor(env(""), "pedro").Actor; a != "human:pedro" {
		t.Fatal(a)
	}
	if a := keg.OKFSettingsFor(env("process:ci"), "pedro").Actor; a != "process:ci" {
		t.Fatal(a)
	}
}

func writeKeg(t *testing.T, fsys fstest.MapFS) string {
	t.Helper()
	dir := t.TempDir()
	for p, f := range fsys {
		path := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, f.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDexUpdateKeepsAnOptedInKegConformant(t *testing.T) {
	t.Setenv(keg.EnvOKFActor, "human:tester")
	fsys := sampleKeg()
	snap := collect(t, fsys)
	apply(t, fsys, keg.PlanOKFFix(snap, settings).Writes)
	apply(t, fsys, keg.PlanOKFIndex(collect(t, fsys), "Sample"))
	dir := writeKeg(t, fsys)

	if err := os.MkdirAll(filepath.Join(dir, "3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "3", "README.md"), []byte("# Brand new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := keg.DexUpdate(dir, &keg.DexEntry{N: 3}); err != nil {
		t.Fatal(err)
	}

	after, err := keg.CollectOKF(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	if ps := keg.OKFProblems(after); len(ps) != 1 {
		t.Fatalf("problems after a new node: %v", ps)
	}
	node, _ := os.ReadFile(filepath.Join(dir, "3", "README.md"))
	if !strings.HasPrefix(string(node), "---\ntype: Note\ntitle: Brand new\ngenerated: {by: 'human:tester', at: ") {
		t.Fatalf("new node:\n%s", node)
	}
	index, _ := os.ReadFile(filepath.Join(dir, okf.IndexFile))
	if !strings.Contains(string(index), "\n# Sample\n") || !strings.Contains(string(index), "* [Brand new](3/README.md)\n") {
		t.Fatalf("index not refreshed:\n%s", index)
	}
	changes, _ := os.ReadFile(filepath.Join(dir, "dex", "changes.md"))
	if !strings.HasPrefix(string(changes), "---\ntype: KEG Index\n---\n") {
		t.Fatalf("dex front matter lost:\n%s", changes)
	}
}

func TestWriteDexKeepsDexFrontMatterWithoutOptIn(t *testing.T) {
	fsys := sampleKeg()
	fsys["dex/changes.md"] = &fstest.MapFile{Data: append([]byte("---\ntype: KEG Index\n---\n"), fsys["dex/changes.md"].Data...)}
	dir := writeKeg(t, fsys)
	dex, err := keg.ReadDex(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := keg.WriteDex(dir, dex); err != nil {
		t.Fatal(err)
	}
	changes, _ := os.ReadFile(filepath.Join(dir, "dex", "changes.md"))
	if !strings.HasPrefix(string(changes), "---\ntype: KEG Index\n---\n* 2026-10-04 10:00:00Z [Planned](../0)\n") {
		t.Fatalf("front matter not kept:\n%s", changes)
	}
	if e := keg.LastChanged(dir); e == nil || e.N != 0 {
		t.Fatalf("LastChanged through front matter: %v", e)
	}
}

func TestDexUpdateLeavesAPlainKegAlone(t *testing.T) {
	dir := writeKeg(t, sampleKeg())
	if err := keg.DexUpdate(dir, &keg.DexEntry{N: 0}); err != nil {
		t.Fatal(err)
	}
	node, _ := os.ReadFile(filepath.Join(dir, "0", "README.md"))
	if string(node) != "# Planned\n\nfiller\n" {
		t.Fatalf("a keg that has not opted in was changed:\n%s", node)
	}
	if _, err := os.Stat(filepath.Join(dir, okf.IndexFile)); !os.IsNotExist(err) {
		t.Fatal("index.md written for a keg that has not opted in")
	}
}
