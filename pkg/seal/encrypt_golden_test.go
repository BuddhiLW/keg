package seal_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/seal"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata")

// golden compares got with testdata/name, or rewrites it under -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
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

func TestGoldenEncryptArgv(t *testing.T) {
	cases := []struct {
		name string
		o    seal.GPGOptions
		to   seal.Recipients
	}{
		{"self", seal.GPGOptions{}, nil},
		{"two keys", seal.GPGOptions{Bin: "gpg"}, seal.Recipients{fpA, fpB}},
		{"key file", seal.GPGOptions{Bin: "gpg", KeyFiles: map[seal.Fingerprint]string{fpB: "/k/b.pub"}}, seal.Recipients{fpA, fpB}},
		{"unused key file", seal.GPGOptions{Bin: "gpg", KeyFiles: map[seal.Fingerprint]string{fpB: "/k/b.pub"}}, seal.Recipients{fpA}},
		{"shown", seal.GPGOptions{Bin: "gpg", ShowRecipients: true}, seal.Recipients{fpA}},
		{"homedir", seal.GPGOptions{Bin: "gpg2", Homedir: "/mnt/1/gnupg-vault"}, seal.Recipients{fpA}},
	}
	var b strings.Builder
	for _, c := range cases {
		fmt.Fprintf(&b, "%v:\n  %v\n", c.name, strings.Join(seal.EncryptArgv(c.o, c.to), " "))
	}
	fmt.Fprintf(&b, "show-keys:\n  %v\n", strings.Join(seal.ShowKeyArgv(seal.GPGOptions{Homedir: "/h"}, "/k/b.pub"), " "))
	golden(t, "encrypt_argv.golden", b.String())
}

func TestGoldenRenderDirective(t *testing.T) {
	var b strings.Builder
	for _, rs := range []seal.Recipients{{fpA}, {fpB, fpA, fpB}} {
		b.WriteString(seal.RenderDirective(rs.Normal()))
		b.WriteString("~~~\n")
	}
	golden(t, "render_directive.golden", b.String())
}
