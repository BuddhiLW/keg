package seal_test

import (
	"errors"
	"math/rand"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"github.com/BuddhiLW/keg/pkg/seal"
	"github.com/BuddhiLW/keg/pkg/seal/sealtest"
)

// tally records which keyrings were asked to decrypt.
type tally struct {
	seal.Cipher
	name  string
	asked *[]string
}

func (t tally) Decrypt(armor string) ([]byte, error) {
	*t.asked = append(*t.asked, t.name)
	return t.Cipher.Decrypt(armor)
}

func TestKeyringsEncryptWithTheFirstOnly(t *testing.T) {
	vault := &sealtest.Recording{Cipher: sealtest.New(fpA)}
	home := &sealtest.Recording{Cipher: sealtest.New(fpB)}
	ks := seal.Keyrings{{Name: "vault", Cipher: vault}, {Name: "home", Cipher: home}}
	if _, err := ks.Encrypt([]byte("x"), nil); err != nil {
		t.Fatal(err)
	}
	if len(vault.Calls) != 1 || len(home.Calls) != 0 {
		t.Fatalf("vault %v home %v", vault.Calls, home.Calls)
	}

	unmounted := seal.GPGKeyrings(seal.GPGOptions{}, []string{"/mnt/vault", ""}, func(string) bool { return false })
	_, err := unmounted.Encrypt([]byte("x"), nil)
	if !errors.Is(err, seal.ErrKeyringMissing) || !strings.Contains(err.Error(), "/mnt/vault") {
		t.Fatalf("an unmounted first keyring must stop the encrypt, not fall back: %v", err)
	}
	if _, err := (seal.Keyrings{}).Encrypt(nil, nil); !errors.Is(err, seal.ErrNoKeyring) {
		t.Fatalf("no keyrings: %v", err)
	}
	if _, err := (seal.Keyrings{}).Decrypt(""); !errors.Is(err, seal.ErrNoKeyring) {
		t.Fatalf("no keyrings: %v", err)
	}
}

func TestKeyringsCanEncrypt(t *testing.T) {
	if err := unmountedFirst().CanEncrypt(); !errors.Is(err, seal.ErrKeyringMissing) || !strings.Contains(err.Error(), "/mnt/vault") {
		t.Fatalf("unmounted first keyring: %v", err)
	}
	mounted := seal.GPGKeyrings(seal.GPGOptions{}, []string{"/mnt/vault", "/gone"}, func(p string) bool { return p == "/mnt/vault" })
	if err := mounted.CanEncrypt(); err != nil {
		t.Fatalf("a missing later keyring must not block encrypting: %v", err)
	}
	if err := (seal.Keyrings{}).CanEncrypt(); !errors.Is(err, seal.ErrNoKeyring) {
		t.Fatalf("no keyrings: %v", err)
	}
}

func unmountedFirst() seal.Keyrings {
	return seal.GPGKeyrings(seal.GPGOptions{}, []string{"/mnt/vault", ""}, func(string) bool { return false })
}

func TestPlainResultNamesAKeyringWithoutTheKey(t *testing.T) {
	noKey := seal.ExecResult{Exit: 2, Stderr: []byte("gpg: ecdh failed in gcry_cipher_decrypt: Checksum error\n" +
		"[GNUPG:] ENC_TO 0000000000000000 18 0\n[GNUPG:] NO_SECKEY 0000000000000000\n[GNUPG:] DECRYPTION_FAILED\n")}
	if _, err := seal.PlainResult(noKey); !errors.Is(err, seal.ErrNoSecretKey) {
		t.Fatalf("no secret key: %v", err)
	}
	tampered := seal.ExecResult{Exit: 2, Stderr: []byte("[GNUPG:] NO_SECKEY 0000000000000000\n[GNUPG:] DECRYPTION_FAILED\n[GNUPG:] BADMDC\n")}
	if _, err := seal.PlainResult(tampered); err == nil || errors.Is(err, seal.ErrNoSecretKey) {
		t.Fatalf("an integrity failure must not read as a missing key: %v", err)
	}
	other := seal.ExecResult{Exit: 2, Stderr: []byte("gpg: something else\n[GNUPG:] DECRYPTION_FAILED\n")}
	if _, err := seal.PlainResult(other); err == nil || errors.Is(err, seal.ErrNoSecretKey) || !strings.Contains(err.Error(), "something else") {
		t.Fatalf("other failure: %v", err)
	}
}

func TestGPGKeyringsNamesAndPresence(t *testing.T) {
	ks := seal.GPGKeyrings(seal.GPGOptions{Bin: "gpg2", Homedir: "/ignored"},
		[]string{"/here", "", "/gone"}, func(p string) bool { return p == "/here" })
	var names []string
	for _, k := range ks {
		names = append(names, k.Name)
	}
	if !reflect.DeepEqual(names, []string{"/here", "gpg default keyring", "/gone"}) {
		t.Fatalf("names %v", names)
	}
	if g, ok := ks[0].Cipher.(seal.GPG); !ok || g.Opts.Homedir != "/here" || g.Opts.Bin != "gpg2" {
		t.Fatalf("first keyring %#v", ks[0].Cipher)
	}
	if g, ok := ks[1].Cipher.(seal.GPG); !ok || g.Opts.Homedir != "" {
		t.Fatalf("default keyring %#v", ks[1].Cipher)
	}
	if _, err := ks[2].Cipher.Decrypt(""); !errors.Is(err, seal.ErrKeyringMissing) {
		t.Fatalf("missing keyring: %v", err)
	}
	solo := seal.GPGKeyrings(seal.GPGOptions{Homedir: "/vault"}, nil, func(string) bool { return true })
	if len(solo) != 1 || solo[0].Name != "/vault" {
		t.Fatalf("no keyrings must mean the homedir alone: %+v", solo)
	}
}

// ringCase is keyrings each holding some keys, and the recipients of a
// message.
type ringCase struct {
	Holds [][]seal.Fingerprint
	To    seal.Recipients
}

func (ringCase) Generate(r *rand.Rand, _ int) reflect.Value {
	pool := []seal.Fingerprint{fpA, fpB, fpC}
	var c ringCase
	for i := 0; i < 1+r.Intn(4); i++ {
		var held []seal.Fingerprint
		for _, fp := range pool {
			if r.Intn(3) == 0 {
				held = append(held, fp)
			}
		}
		c.Holds = append(c.Holds, held)
	}
	c.To = seal.Recipients{pool[r.Intn(len(pool))]}
	return reflect.ValueOf(c)
}

func TestPropKeyringsOpenWithTheFirstThatHoldsAKey(t *testing.T) {
	prop := func(c ringCase) bool {
		armor, _ := sealtest.New(c.To[0]).Encrypt([]byte("secret"), c.To)
		var asked []string
		var ks seal.Keyrings
		first := -1
		for i, held := range c.Holds {
			name := string(rune('a' + i))
			// a Stub always holds its own key; give it one nobody uses
			stub := sealtest.New("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", held...)
			ks = append(ks, seal.Keyring{Name: name, Cipher: tally{stub, name, &asked}})
			for _, h := range held {
				if h == c.To[0] && first < 0 {
					first = i
				}
			}
		}
		plain, err := ks.Decrypt(armor)
		if first < 0 {
			var none *seal.NoKeyringOpened
			return errors.As(err, &none) && len(none.Tried) == len(ks) && len(asked) == len(ks)
		}
		return err == nil && string(plain) == "secret" && len(asked) == first+1
	}
	if err := quick.Check(prop, propConfig); err != nil {
		t.Fatal(err)
	}
}

func TestGoldenNoKeyringOpened(t *testing.T) {
	ks := seal.Keyrings{
		{Name: "/mnt/1/gnupg-vault", Cipher: seal.GPGKeyrings(seal.GPGOptions{}, []string{"/mnt/1/gnupg-vault"}, func(string) bool { return false })[0].Cipher},
		{Name: "gpg default keyring", Cipher: sealtest.New(fpB)},
	}
	armor, _ := sealtest.New(fpA).Encrypt([]byte("x"), seal.Recipients{fpA})
	_, err := ks.Decrypt(armor)
	if !errors.Is(err, seal.ErrKeyringMissing) {
		t.Fatalf("the reasons must stay inspectable: %v", err)
	}
	golden(t, "no_keyring_opened.golden", err.Error()+"\n")
}

// TestRealGPGKeyringsFindTheVault seals to a vault keyring that comes
// second in the list, and opens it although the first keyring holds
// other keys.
func TestRealGPGKeyringsFindTheVault(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil || testing.Short() {
		t.Skip("gpg not installed or -short")
	}
	home := newHome(t, "Home <home@keg.test>")
	vault := newHome(t, "Vault <vault@keg.test>")
	exists := func(string) bool { return true }

	stored, err := seal.Sealer{Cipher: seal.GPGKeyrings(seal.GPGOptions{}, []string{vault.dir}, exists)}.Seal([]byte("vault only"), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	both := seal.GPGKeyrings(seal.GPGOptions{}, []string{home.dir, vault.dir}, exists)
	plain, _, err := seal.Sealer{Cipher: both}.Open([]byte(stored))
	if err != nil || string(plain) != "vault only" {
		t.Fatalf("open through both keyrings: %q %v", plain, err)
	}
	homeOnly := seal.GPGKeyrings(seal.GPGOptions{}, []string{home.dir}, exists)
	_, _, err = seal.Sealer{Cipher: homeOnly}.Open([]byte(stored))
	var none *seal.NoKeyringOpened
	if !errors.As(err, &none) || !strings.Contains(err.Error(), home.dir) {
		t.Fatalf("home alone: %v", err)
	}
}
