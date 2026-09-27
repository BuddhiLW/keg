package keg_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/keg"
	"github.com/BuddhiLW/keg/pkg/seal"
	"github.com/BuddhiLW/keg/pkg/seal/sealtest"
)

const (
	fpA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

const kegfile = `updated: 2026-09-27 00:00:00Z
title: private keg
seal:
  recipients: [` + fpA + `]
  topics: [private]
  topic-recipients:
    diary: [` + fpB + `]
`

const secret = "# Why I left\n\nThe real reason, which nobody may read.\n"

func clearEnv(t *testing.T) {
	for _, k := range []string{seal.EnvRecipients, seal.EnvTopicRecipients,
		seal.EnvTopics, seal.EnvGPGBin, seal.EnvGPGHomedir} {
		t.Setenv(k, "")
	}
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
}

// newKeg writes a keg with the given dex/tags lines and nodes.
func newKeg(t *testing.T, tags string, nodes map[string]string) string {
	t.Helper()
	clearEnv(t)
	dir := t.TempDir()
	write(t, filepath.Join(dir, "keg"), kegfile)
	write(t, filepath.Join(dir, "dex", "tags"), tags)
	for id, body := range nodes {
		write(t, filepath.Join(dir, id, "README.md"), body)
	}
	return dir
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// plaintextAnywhere reports whether any file under root contains s.
func plaintextAnywhere(t *testing.T, root, s string) bool {
	found := false
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), s) {
				found = true
			}
		}
		return nil
	})
	return found
}

func sealer(t *testing.T, dir string, c seal.Cipher) seal.Sealer {
	t.Helper()
	st, err := keg.SealSettings(dir)
	if err != nil {
		t.Fatal(err)
	}
	return seal.Sealer{Cipher: c, Policy: st.Policy}
}

func TestSealedNodeTitleNeverLeaks(t *testing.T) {
	dir := newKeg(t, "", map[string]string{"1": secret, "2": secret})
	s := sealer(t, dir, sealtest.New(fpA))

	if err := keg.SealNode(s, dir, "1", "a hard decision"); err != nil {
		t.Fatal(err)
	}
	if err := keg.SealNode(s, dir, "2", ""); err != nil {
		t.Fatal(err)
	}
	if plaintextAnywhere(t, dir, "real reason") || plaintextAnywhere(t, dir, "Why I left") {
		t.Fatal("plaintext or title left in the keg after sealing")
	}
	for id, want := range map[string]string{"1": "a hard decision", "2": keg.SealedTitle} {
		got, err := keg.NodeTitle(filepath.Join(dir, id))
		if err != nil || got != want {
			t.Errorf("node %v title %q %v, want %q", id, got, err, want)
		}
	}
	plain, err := keg.OpenNode(s, dir, "1")
	if err != nil || string(plain) != secret {
		t.Fatalf("open: %q %v", plain, err)
	}
}

func TestTagsSelectTheRecipients(t *testing.T) {
	dir := newKeg(t, "diary 2\n", map[string]string{"1": secret, "2": secret})
	rec := &sealtest.Recording{Cipher: sealtest.New(fpA, fpB)}
	s := sealer(t, dir, rec)
	keg.SealNode(s, dir, "1", "")
	keg.SealNode(s, dir, "2", "")
	want := []seal.Recipients{{fpA}, {fpB}}
	if !reflect.DeepEqual(rec.Calls, want) {
		t.Fatalf("recipients %v, want %v", rec.Calls, want)
	}
	if _, err := keg.OpenNode(sealer(t, dir, sealtest.New(fpA)), dir, "2"); err == nil {
		t.Fatal("the default key opened a diary node")
	}
}

func TestEditSealedNodeUsesAPrivateCopyAndWipesIt(t *testing.T) {
	dir := newKeg(t, "", map[string]string{"1": secret})
	s := sealer(t, dir, sealtest.New(fpA))
	keg.SealNode(s, dir, "1", "hint")

	var copyPath string
	res, err := keg.EditSealedNode(s, dir, "1", func(p string) error {
		copyPath = p
		if strings.HasPrefix(p, dir) {
			t.Errorf("plaintext copy %v is inside the keg", p)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Errorf("copy mode %v", fi.Mode().Perm())
		}
		b, _ := os.ReadFile(p)
		return os.WriteFile(p, append(b, []byte("\nAnd one more thing.\n")...), 0o600)
	})
	if err != nil || res != keg.Changed {
		t.Fatalf("edit: %v %v", res, err)
	}
	if _, err := os.Stat(filepath.Dir(copyPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private copy survived the edit")
	}
	if plaintextAnywhere(t, dir, "one more thing") {
		t.Fatal("edited plaintext written into the keg")
	}
	plain, _ := keg.OpenNode(s, dir, "1")
	if !strings.HasSuffix(string(plain), "And one more thing.\n") {
		t.Fatalf("edit lost: %q", plain)
	}
	if title, _ := keg.NodeTitle(filepath.Join(dir, "1")); title != "hint" {
		t.Fatalf("hint lost: %q", title)
	}
}

func TestEditSealedNodeReportsUnchangedAndEmptied(t *testing.T) {
	dir := newKeg(t, "", map[string]string{"1": secret})
	s := sealer(t, dir, sealtest.New(fpA))
	keg.SealNode(s, dir, "1", "")
	before := read(t, filepath.Join(dir, "1", "README.md"))

	res, err := keg.EditSealedNode(s, dir, "1", func(string) error { return nil })
	if err != nil || res != keg.Unchanged || read(t, filepath.Join(dir, "1", "README.md")) != before {
		t.Fatalf("unchanged edit: %v %v", res, err)
	}
	res, err = keg.EditSealedNode(s, dir, "1", func(p string) error { return os.WriteFile(p, nil, 0o600) })
	if err != nil || res != keg.Emptied {
		t.Fatalf("emptied edit: %v %v", res, err)
	}
}

func TestCreateSealedNodeNeverStoresPlaintext(t *testing.T) {
	dir := newKeg(t, "", nil)
	s := sealer(t, dir, sealtest.New(fpA))
	entry, err := keg.MakeNode(dir)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := keg.CreateSealedNode(s, dir, entry, "", func(p string) error {
		if err := os.WriteFile(p, []byte(secret), 0o600); err != nil {
			return err
		}
		if plaintextAnywhere(t, dir, "real reason") {
			t.Error("plaintext inside the keg while editing")
		}
		return nil
	})
	if err != nil || !ok {
		t.Fatalf("create: %v %v", ok, err)
	}
	if !keg.IsSealedNode(dir, entry.ID()) || plaintextAnywhere(t, dir, "real reason") {
		t.Fatal("new node is not sealed")
	}

	empty, _ := keg.MakeNode(dir)
	ok, err = keg.CreateSealedNode(s, dir, empty, "", func(string) error { return nil })
	if err != nil || ok {
		t.Fatalf("empty create: %v %v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, empty.ID())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty node directory left behind")
	}
}

func TestPublishGuardBlocksPlaintextOfSealedTopics(t *testing.T) {
	dir := newKeg(t, "private 1\ndiary 2\nopen 3\n",
		map[string]string{"1": secret, "2": secret, "3": "# public\n"})
	err := keg.GuardSealed(dir)
	if err == nil || !strings.Contains(err.Error(), "node(s) 1 2 carry") {
		t.Fatalf("guard: %v", err)
	}
	s := sealer(t, dir, sealtest.New(fpA, fpB))
	keg.SealNode(s, dir, "1", "")
	keg.SealNode(s, dir, "2", "")
	if err := keg.GuardSealed(dir); err != nil {
		t.Fatalf("guard after sealing: %v", err)
	}
}

func TestUnsealRefusesASealedTopic(t *testing.T) {
	dir := newKeg(t, "private 1\n", map[string]string{"1": secret, "2": secret})
	s := sealer(t, dir, sealtest.New(fpA))
	keg.SealNode(s, dir, "1", "")
	keg.SealNode(s, dir, "2", "")
	if err := keg.UnsealNode(s, dir, "1"); !errors.Is(err, keg.ErrMustStaySealed) {
		t.Fatalf("unseal of private node: %v", err)
	}
	if err := keg.UnsealNode(s, dir, "2"); err != nil || read(t, filepath.Join(dir, "2", "README.md")) != secret {
		t.Fatalf("unseal: %v", err)
	}
}

func TestRekeyAddsARecipient(t *testing.T) {
	dir := newKeg(t, "", map[string]string{"1": secret})
	keg.SealNode(sealer(t, dir, sealtest.New(fpA)), dir, "1", "")
	t.Setenv(seal.EnvRecipients, fpA+","+fpB)
	if err := keg.RekeyNode(sealer(t, dir, sealtest.New(fpA)), dir, "1"); err != nil {
		t.Fatal(err)
	}
	if _, err := keg.OpenNode(sealer(t, dir, sealtest.New(fpB)), dir, "1"); err != nil {
		t.Fatalf("new recipient cannot open after rekey: %v", err)
	}
}
