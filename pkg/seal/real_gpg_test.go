package seal_test

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/seal"
)

// gpgHome is a throwaway GNUPGHOME holding one passphrase-less key.
type gpgHome struct {
	dir string
	fp  seal.Fingerprint
}

func run(t *testing.T, home string, in []byte, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("gpg", append([]string{"--homedir", home, "--batch", "--quiet"}, args...)...)
	cmd.Stdin = bytes.NewReader(in)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg %v: %v\n%s", args, err, errb.String())
	}
	return out.Bytes()
}

func newHome(t *testing.T, uid string) gpgHome {
	t.Helper()
	dir, err := os.MkdirTemp("", "kegseal")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o700)
	t.Cleanup(func() {
		exec.Command("gpgconf", "--homedir", dir, "--kill", "gpg-agent").Run()
		os.RemoveAll(dir)
	})
	run(t, dir, nil, "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-gen-key", uid, "default", "default", "never")
	var fp seal.Fingerprint
	for _, line := range strings.Split(string(run(t, dir, nil, "--with-colons", "--fingerprint")), "\n") {
		if f := strings.Split(line, ":"); len(f) > 9 && f[0] == "fpr" {
			fp = seal.Fingerprint(f[9])
			break
		}
	}
	if fp == "" {
		t.Fatal("no fingerprint for generated key")
	}
	return gpgHome{dir: dir, fp: fp}
}

func (h gpgHome) importFrom(t *testing.T, other gpgHome) {
	pub := run(t, other.dir, nil, "--armor", "--export", string(other.fp))
	run(t, h.dir, pub, "--import")
}

func (h gpgHome) cipher() seal.GPG { return seal.NewGPG(seal.GPGOptions{Homedir: h.dir}) }

// TestRealGPGMultiKey seals one node to two people and proves each can
// open it alone while a third cannot.
func TestRealGPGMultiKey(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil || testing.Short() {
		t.Skip("gpg not installed or -short")
	}
	alice := newHome(t, "Alice <alice@keg.test>")
	bob := newHome(t, "Bob <bob@keg.test>")
	eve := newHome(t, "Eve <eve@keg.test>")
	alice.importFrom(t, bob)

	cipherConformance(t, alice.cipher(),
		[]seal.Cipher{alice.cipher(), bob.cipher()}, eve.cipher(),
		seal.Recipients{alice.fp, bob.fp})

	s := seal.Sealer{Cipher: alice.cipher(),
		Policy: seal.Policy{Default: seal.Recipients{alice.fp, bob.fp}}}
	stored, err := s.Seal([]byte("shared secret"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, string(alice.fp[24:])) || strings.Contains(stored, string(bob.fp[24:])) {
		t.Fatal("recipient key ids are visible in the ciphertext")
	}
	plain, _, err := seal.Sealer{Cipher: bob.cipher()}.Open([]byte(stored))
	if err != nil || string(plain) != "shared secret" {
		t.Fatalf("bob: %q %v", plain, err)
	}
}
