package keg_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/keg"
	"github.com/BuddhiLW/keg/pkg/seal"
	"github.com/BuddhiLW/keg/pkg/seal/sealtest"
)

const becameSecret = "---\nseal: true\nseal-hint: later\n---\n# Salary negotiation\n\nnumbers nobody may see\n"

// A note written in the clear that later gains a directive is sealed by
// AutoSeal, and its plaintext title leaves the index.
func TestNoteThatBecameSecretIsSealedAndLeavesTheIndex(t *testing.T) {
	dir := newKeg(t, "", map[string]string{
		"1": "# Public\n\nhello\n",
		"2": "# Salary negotiation\n\nnumbers nobody may see\n",
	})
	if err := keg.MakeDex(dir); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, filepath.Join(dir, "dex", "nodes.tsv")), "Salary negotiation") {
		t.Fatal("fixture: plaintext title expected in the index before sealing")
	}

	write(t, filepath.Join(dir, "2", "README.md"), becameSecret)
	pending, err := keg.PendingSeals(dir)
	if err != nil || !reflect.DeepEqual(pending, []string{"2"}) {
		t.Fatalf("pending %v %v", pending, err)
	}
	if err := keg.GuardSealed(dir); err == nil || !strings.Contains(err.Error(), "front matter") {
		t.Fatalf("guard must refuse a pending note: %v", err)
	}

	s := sealer(t, dir, sealtest.New(fpA))
	sealed, err := keg.AutoSeal(s, dir)
	if err != nil || !reflect.DeepEqual(sealed, []string{"2"}) {
		t.Fatalf("autoseal %v %v", sealed, err)
	}
	if plaintextAnywhere(t, dir, "Salary") || plaintextAnywhere(t, dir, "numbers nobody") {
		t.Fatal("plaintext or its title still in the keg after autoseal")
	}
	if title, _ := keg.NodeTitle(filepath.Join(dir, "2")); title != "later" {
		t.Fatalf("title %q", title)
	}
	if err := keg.GuardSealed(dir); err != nil {
		t.Fatalf("guard after autoseal: %v", err)
	}
	if again, err := keg.AutoSeal(s, dir); err != nil || len(again) != 0 {
		t.Fatalf("second autoseal: %v %v", again, err)
	}
	plain, err := keg.OpenNode(s, dir, "2")
	if err != nil || string(plain) != becameSecret {
		t.Fatalf("open: %q %v", plain, err)
	}
}

func TestAutoSealUsesTheRecipientsTheNoteNames(t *testing.T) {
	dir := newKeg(t, "", map[string]string{
		"1": "---\nseal: [" + fpB + "]\n---\n# only B\n",
	})
	rec := &sealtest.Recording{Cipher: sealtest.New(fpA, fpB)}
	if _, err := keg.AutoSeal(sealer(t, dir, rec), dir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rec.Calls, []seal.Recipients{{fpB}}) {
		t.Fatalf("recipients %v", rec.Calls)
	}
}

func TestMalformedDirectiveStopsThePublish(t *testing.T) {
	dir := newKeg(t, "", map[string]string{
		"1": "---\nseal: DEADBEEF\n---\n# oops\n",
	})
	err := keg.GuardSealed(dir)
	if err == nil || !strings.Contains(err.Error(), "node 1") {
		t.Fatalf("guard: %v", err)
	}
	if _, err := keg.AutoSeal(sealer(t, dir, sealtest.New(fpA)), dir); err == nil {
		t.Fatal("autoseal accepted a malformed directive")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "1", "README.md")); seal.IsSealed(b) {
		t.Fatal("sealed despite the error")
	}
}

func TestEditingASealedNoteKeepsItsDirective(t *testing.T) {
	dir := newKeg(t, "", map[string]string{"1": becameSecret})
	s := sealer(t, dir, sealtest.New(fpA))
	if _, err := keg.AutoSeal(s, dir); err != nil {
		t.Fatal(err)
	}
	res, err := keg.EditSealedNode(s, dir, "1", func(p string) error {
		b, _ := os.ReadFile(p)
		b = []byte(strings.Replace(string(b), "seal-hint: later", "seal-hint: renamed", 1))
		return os.WriteFile(p, b, 0o600)
	})
	if err != nil || res != keg.Changed {
		t.Fatalf("edit: %v %v", res, err)
	}
	if title, _ := keg.NodeTitle(filepath.Join(dir, "1")); title != "renamed" {
		t.Fatalf("title %q", title)
	}
}
