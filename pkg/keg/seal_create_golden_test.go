package keg_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/keg"
	"github.com/BuddhiLW/keg/pkg/seal"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata")

// golden compares got with testdata/name, or rewrites it under -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if got != string(want) {
		t.Errorf("%v changed (go test -update to accept):\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

// describePlan renders what `keg create encrypt ARGS` would do, with the
// home directory spelled ~ so the record is the same on every machine.
func describePlan(args []string) string {
	return describePlanWith(nil, args)
}

// describePlanWith is describePlan for a user who set these keyrings.
func describePlanWith(keyrings []string, args []string) string {
	home, _ := os.UserHomeDir()
	files := map[string]string{"/keys/b.fpr": fpB + "\n"}
	readFile := func(p string) ([]byte, error) {
		if s, ok := files[p]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	keys := map[string]seal.Fingerprint{"/keys/c.pub": fpC, "/keg/d.pub": fpD}
	keyFile := func(_ seal.GPGOptions, p string) (seal.Fingerprint, error) {
		if fp, ok := keys[p]; ok {
			return fp, nil
		}
		return "", seal.ErrSecretKeyFile
	}
	st := seal.Settings{GPG: seal.GPGOptions{Bin: "gpg"}, KeyFiles: []string{"/keg/d.pub"}, Keyrings: keyrings}

	var b strings.Builder
	fmt.Fprintf(&b, "keg create encrypt %v\n", strings.Join(args, " "))
	o, err := keg.ParseEncryptArgs(args)
	if err != nil {
		fmt.Fprintf(&b, "  error: %v\n", err)
		return b.String()
	}
	fmt.Fprintf(&b, "  hint: %q\n", o.Hint)
	plan, err := keg.PlanEncrypt(st, o, readFile, keyFile)
	if err != nil {
		fmt.Fprintf(&b, "  error: %v\n", err)
		return b.String()
	}
	fmt.Fprintf(&b, "  to: %v\n", plan.To.Strings())
	fmt.Fprintf(&b, "  homedir: %q show-recipients: %v\n",
		strings.Replace(plan.GPG.Homedir, home, "~", 1), plan.GPG.ShowRecipients)
	var rings []string
	for _, r := range plan.Keyrings {
		rings = append(rings, strings.Replace(r, home, "~", 1))
	}
	fmt.Fprintf(&b, "  keyrings: %v\n", rings)
	var located []string
	for fp, p := range plan.GPG.KeyFiles {
		located = append(located, string(fp)[:4]+"="+p)
	}
	sort.Strings(located)
	fmt.Fprintf(&b, "  key files: %v\n", located)
	fmt.Fprintf(&b, "  prefill: %q\n", plan.Prefill())
	return b.String()
}

func TestGoldenCreateEncrypt(t *testing.T) {
	cases := [][]string{
		nil,
		{"a", "note", "to", "self"},
		{"to", fpA},
		{"to", strings.ToLower(fpA), "to", fpA},
		{"to", "/keys/b.fpr", "salary", "talk"},
		{"key", "/keys/c.pub"},
		{"key", "/keys/c.pub", "to", fpA, "homedir", "~/mnt/1/gnupg-vault", "show-recipients", "vault"},
		{"homedir", "/abs/vault"},
		{"show-recipients"},
		{"to"},
		{"homedir", " "},
		{"to", "nobody"},
		{"key", "/keys/secret.asc"},
	}
	var b strings.Builder
	for _, args := range cases {
		b.WriteString(describePlan(args))
	}
	golden(t, "create_encrypt.golden", b.String())
}

func TestGoldenCreateEncryptWithKeyrings(t *testing.T) {
	rings := []string{"~/mnt/1/gnupg-vault", "~/.gnupg"}
	var b strings.Builder
	for _, args := range [][]string{nil, {"key", "/keys/c.pub"}, {"homedir", "/once/only", "hint"}} {
		b.WriteString(describePlanWith(rings, args))
	}
	home, _ := os.UserHomeDir()
	present := func(p string) bool { return p == home+"/.gnupg" }
	for _, st := range []seal.Settings{
		{Keyrings: rings},
		{GPG: seal.GPGOptions{Homedir: "~/mnt/1/gnupg-vault"}},
		{},
	} {
		b.WriteString(strings.ReplaceAll(keg.DescribeKeyrings(st, present), home, "~"))
	}
	golden(t, "create_encrypt_keyrings.golden", b.String())
}

type recordingPrompter struct{ questions []string }

func (p *recordingPrompter) Ask(q string) (string, error) {
	p.questions = append(p.questions, q)
	return "", nil
}

func TestGoldenEncryptQuestions(t *testing.T) {
	p := &recordingPrompter{}
	if _, err := keg.AskEncryptOptions(p); err != nil {
		t.Fatal(err)
	}
	golden(t, "create_encrypt_questions.golden", strings.Join(p.questions, "\n")+"\n")
}
