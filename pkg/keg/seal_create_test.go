package keg_test

import (
	"errors"
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
	fpC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	fpD = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
)

func TestParseEncryptArgs(t *testing.T) {
	got, err := keg.ParseEncryptArgs([]string{"--to", fpA, "a", "--key=~/k.pub",
		"--homedir", "/vault", "--show-recipients", "public", "--", "--to", "x"})
	if err != nil {
		t.Fatal(err)
	}
	want := keg.EncryptOptions{To: []string{fpA}, Keys: []string{"~/k.pub"},
		Homedir: "/vault", ShowRecipients: true, Hint: "a public --to x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	for _, bad := range [][]string{{"--to"}, {"--key="}, {"--recipient", fpA}, {"--show-recipients=yes"}} {
		if _, err := keg.ParseEncryptArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestPlanEncryptResolvesKeysFilesAndHomedir(t *testing.T) {
	home, _ := os.UserHomeDir()
	files := map[string]string{
		"/keys/a.fpr":                          fpA + "\n",
		filepath.Join(home, "mnt/1/vault.fpr"): " " + fpB + " \n",
	}
	readFile := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	keyFiles := map[string]seal.Fingerprint{"/keys/c.pub": fpC, "/keys/d.pub": fpD}
	var sawHomedir string
	keyFile := func(o seal.GPGOptions, p string) (seal.Fingerprint, error) {
		sawHomedir = o.Homedir
		if fp, ok := keyFiles[p]; ok {
			return fp, nil
		}
		return "", seal.ErrSecretKeyFile
	}
	st := seal.Settings{GPG: seal.GPGOptions{Bin: "gpg"}, KeyFiles: []string{"/keys/d.pub"}}
	o := keg.EncryptOptions{To: []string{"/keys/a.fpr", "~/mnt/1/vault.fpr"},
		Keys: []string{"/keys/c.pub"}, Homedir: "~/mnt/1/gnupg-vault"}

	plan, err := keg.PlanEncrypt(st, o, readFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := (seal.Recipients{fpA, fpB, fpC}); !reflect.DeepEqual(plan.To, want) {
		t.Errorf("recipients %v, want %v (a keg key file locates, it does not add)", plan.To, want)
	}
	vault := filepath.Join(home, "mnt/1/gnupg-vault")
	if plan.GPG.Homedir != vault || sawHomedir != vault {
		t.Errorf("homedir %q, key files read under %q", plan.GPG.Homedir, sawHomedir)
	}
	want := map[seal.Fingerprint]string{fpC: "/keys/c.pub", fpD: "/keys/d.pub"}
	if !reflect.DeepEqual(plan.GPG.KeyFiles, want) {
		t.Errorf("key files %v", plan.GPG.KeyFiles)
	}
	d, err := seal.ParseDirective(plan.Prefill())
	if err != nil || !d.Seal || !reflect.DeepEqual(d.To, plan.To) {
		t.Errorf("prefill %q reads back as %+v %v", plan.Prefill(), d, err)
	}

	if _, err := keg.PlanEncrypt(st, keg.EncryptOptions{Keys: []string{"/keys/secret.asc"}}, readFile, keyFile); !errors.Is(err, seal.ErrSecretKeyFile) {
		t.Errorf("secret key file: %v", err)
	}
	if _, err := keg.PlanEncrypt(st, keg.EncryptOptions{To: []string{"nobody"}}, readFile, keyFile); err == nil {
		t.Error("a --to that is neither fingerprint nor file was accepted")
	}
	if p, _ := keg.PlanEncrypt(seal.Settings{}, keg.EncryptOptions{}, readFile, keyFile); p.Prefill() != nil {
		t.Error("no recipients asked, yet the note is prefilled")
	}
}

func TestCreateEncryptedNodeKeepsItsRecipients(t *testing.T) {
	dir := newKeg(t, "", nil)
	rec := &sealtest.Recording{Cipher: sealtest.New(fpA, fpB)}
	s := sealer(t, dir, rec)
	prefill := []byte(seal.RenderDirective(seal.Recipients{fpB}))

	untouched, _ := keg.MakeNode(dir)
	ok, err := keg.CreateSealedNode(s, dir, untouched, "", prefill, func(string) error { return nil })
	if err != nil || ok {
		t.Fatalf("an edit left as the prefill created a node: %v %v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(dir, untouched.ID())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("untouched node directory left behind")
	}

	failed, _ := keg.MakeNode(dir)
	quit := errors.New("editor quit")
	if _, err := keg.CreateSealedNode(s, dir, failed, "", prefill, func(string) error { return quit }); !errors.Is(err, quit) {
		t.Fatalf("failed edit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, failed.ID())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("node directory left behind by a failed edit")
	}

	entry, _ := keg.MakeNode(dir)
	ok, err = keg.CreateSealedNode(s, dir, entry, "for b", prefill, func(p string) error {
		b, _ := os.ReadFile(p)
		if !strings.HasPrefix(string(b), "---\nseal: ["+fpB+"]") {
			t.Errorf("editor opened %q", b)
		}
		return os.WriteFile(p, append(b, []byte(secret)...), 0o600)
	})
	if err != nil || !ok {
		t.Fatalf("create: %v %v", ok, err)
	}
	if err := keg.RekeyNode(s, dir, entry.ID()); err != nil {
		t.Fatal(err)
	}
	if want := []seal.Recipients{{fpB}, {fpB}}; !reflect.DeepEqual(rec.Calls, want) {
		t.Fatalf("recipients %v, want %v: the rekey must keep the create's recipients", rec.Calls, want)
	}
	if plaintextAnywhere(t, dir, "real reason") {
		t.Fatal("plaintext in the keg")
	}
}
