package seal_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/seal"
)

func TestEncryptArgv(t *testing.T) {
	o := seal.GPGOptions{Bin: "gpg2", Homedir: "/h"}
	got := seal.EncryptArgv(o, seal.Recipients{fpA, fpB})
	want := []string{"gpg2", "--homedir", "/h", "--batch", "--yes", "--quiet", "--armor",
		"--throw-keyids", "--trust-model", "always", "--encrypt",
		"--recipient", fpA, "--recipient", fpB}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
	self := seal.EncryptArgv(seal.GPGOptions{ShowRecipients: true}, nil)
	if self[len(self)-1] != "--default-recipient-self" || contains(self, "--throw-keyids") {
		t.Fatalf("self argv %v", self)
	}
}

func TestDecryptArgvLetsPinentryAsk(t *testing.T) {
	got := seal.DecryptArgv(seal.GPGOptions{})
	if contains(got, "--batch") || !contains(got, "--decrypt") {
		t.Fatalf("%v", got)
	}
}

func TestPlainResult(t *testing.T) {
	ok := seal.ExecResult{Stdout: []byte("x"), Exit: 2,
		Stderr: []byte("[GNUPG:] DECRYPTION_OKAY\n")}
	if p, err := seal.PlainResult(ok); err != nil || string(p) != "x" {
		t.Errorf("wrong-key noise with DECRYPTION_OKAY must succeed: %q %v", p, err)
	}
	bad := seal.ExecResult{Stdout: []byte("partial"), Exit: 0,
		Stderr: []byte("[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] BADMDC\n")}
	if _, err := seal.PlainResult(bad); err == nil {
		t.Error("BADMDC must fail even with exit 0")
	}
	failed := seal.ExecResult{Exit: 2, Stderr: []byte("gpg: decryption failed: No secret key\n")}
	if _, err := seal.PlainResult(failed); err == nil || !strings.Contains(err.Error(), "No secret key") {
		t.Errorf("got %v", err)
	}
}

func TestArmorResultRejectsNonArmor(t *testing.T) {
	if _, err := seal.ArmorResult(seal.ExecResult{Stdout: []byte("plain text")}); err == nil {
		t.Fatal("non-armor accepted")
	}
}

func TestGPGFeedsPlaintextOnStdin(t *testing.T) {
	var gotArgv []string
	var gotIn []byte
	g := seal.GPG{Runner: runnerFunc(func(argv []string, in []byte) seal.ExecResult {
		gotArgv, gotIn = argv, in
		return seal.ExecResult{Stdout: []byte(armor)}
	})}
	if _, err := g.Encrypt([]byte("secret"), seal.Recipients{fpA}); err != nil {
		t.Fatal(err)
	}
	if string(gotIn) != "secret" || contains(gotArgv, "secret") {
		t.Fatalf("plaintext must go to stdin only: argv=%v in=%q", gotArgv, gotIn)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
