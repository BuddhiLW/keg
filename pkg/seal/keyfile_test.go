package seal_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/BuddhiLW/keg/pkg/seal"
)

func TestEncryptArgvUsesKeyFiles(t *testing.T) {
	o := seal.GPGOptions{Bin: "gpg", KeyFiles: map[seal.Fingerprint]string{fpB: "/k/b.pub"}}
	got := seal.EncryptArgv(o, seal.Recipients{fpA, fpB})
	want := []string{"gpg", "--batch", "--yes", "--quiet", "--armor", "--throw-keyids",
		"--trust-model", "always", "--encrypt", "--recipient", fpA, "--recipient-file", "/k/b.pub"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestKeyFileResult(t *testing.T) {
	pub := "pub:-:255:22:X:1::::::scESC::::::23::0:\nfpr:::::::::" + fpA + ":\n" +
		"uid:-::::1::H::Test <t@x>::::::::::0:\nsub:-:255:18:Y:1::::::e::::::23:\nfpr:::::::::" + fpB + ":\n"
	if fp, err := seal.KeyFileResult(seal.ExecResult{Stdout: []byte(pub)}); err != nil || fp != fpA {
		t.Errorf("public key: %v %v, want the primary %v", fp, err, fpA)
	}
	sec := "sec:-:255:22:X:1::::::scESC:::+:::23::0:\nfpr:::::::::" + fpA + ":\n"
	if _, err := seal.KeyFileResult(seal.ExecResult{Stdout: []byte(sec)}); !errors.Is(err, seal.ErrSecretKeyFile) {
		t.Errorf("secret key: %v", err)
	}
	two := "pub:-:\nfpr:::::::::" + fpA + ":\npub:-:\nfpr:::::::::" + fpB + ":\n"
	if _, err := seal.KeyFileResult(seal.ExecResult{Stdout: []byte(two)}); err == nil {
		t.Error("a file with two keys was accepted")
	}
	if _, err := seal.KeyFileResult(seal.ExecResult{Exit: 2, Stderr: []byte("gpg: no valid OpenPGP data found.\n")}); err == nil {
		t.Error("a failed run was accepted")
	}
	truncated := "pub:-:\nfpr::::::::\n"
	if _, err := seal.KeyFileResult(seal.ExecResult{Stdout: []byte(truncated)}); err == nil {
		t.Error("a fingerprint record without its fingerprint field was accepted")
	}
}

func TestParseSettingsKeyFilesAndGPGFromEnv(t *testing.T) {
	kegfile := "seal:\n  key-files: [ ~/a.pub , '' ]\n  gpg:\n    bin: gpg\n    homedir: /from/file\n"
	st, err := seal.ParseSettings(kegfile, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.KeyFiles, []string{"~/a.pub"}) || st.GPG.Homedir != "/from/file" || st.GPG.Bin != "gpg" {
		t.Fatalf("keg file: %+v", st)
	}
	env := map[string]string{seal.EnvKeyFiles: "/b.pub, /c.pub", seal.EnvGPGBin: "gpg2", seal.EnvGPGHomedir: "/vault"}
	st, err = seal.ParseSettings(kegfile, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(st.KeyFiles, []string{"/b.pub", "/c.pub"}) || st.GPG.Homedir != "/vault" || st.GPG.Bin != "gpg2" {
		t.Fatalf("environment: %+v", st)
	}
}

// TestRealGPGKeyFile encrypts to a public key file that was never
// imported, and refuses the matching secret key file.
func TestRealGPGKeyFile(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil || testing.Short() {
		t.Skip("gpg not installed or -short")
	}
	vault := newHome(t, "Vault <vault@keg.test>")
	writer := newHome(t, "Writer <writer@keg.test>")
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "vault.pub.gpg")
	secPath := filepath.Join(dir, "vault.sec.asc")
	os.WriteFile(pubPath, run(t, vault.dir, nil, "--export", string(vault.fp)), 0o600)
	os.WriteFile(secPath, run(t, vault.dir, nil, "--pinentry-mode", "loopback", "--passphrase", "",
		"--armor", "--export-secret-keys", string(vault.fp)), 0o600)

	g := writer.cipher()
	fp, err := g.KeyFile(pubPath)
	if err != nil || fp != vault.fp {
		t.Fatalf("key file: %v %v, want %v", fp, err, vault.fp)
	}
	if _, err := g.KeyFile(secPath); !errors.Is(err, seal.ErrSecretKeyFile) {
		t.Fatalf("secret key file: %v", err)
	}

	g.Opts.KeyFiles = map[seal.Fingerprint]string{fp: pubPath}
	stored, err := seal.Sealer{Cipher: g, Policy: seal.Policy{Default: seal.Recipients{fp}}}.Seal([]byte("for the vault"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain, _, err := (seal.Sealer{Cipher: vault.cipher()}).Open([]byte(stored)); err != nil || string(plain) != "for the vault" {
		t.Fatalf("vault: %q %v", plain, err)
	}
	if _, _, err := (seal.Sealer{Cipher: writer.cipher()}).Open([]byte(stored)); err == nil {
		t.Fatal("the writer, not a recipient, opened it")
	}
}
