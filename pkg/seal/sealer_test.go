package seal_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/seal"
)

// cipherConformance is the contract every Cipher must meet. It runs
// against the stub always and against real gpg when gpg is installed.
func cipherConformance(t *testing.T, writer seal.Cipher, readers []seal.Cipher,
	outsider seal.Cipher, to seal.Recipients) {
	t.Helper()
	plain := []byte("# My private thought\n\nNobody reads this but me.\n")
	armor, err := writer.Encrypt(plain, to)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !seal.IsArmor(armor) {
		t.Fatalf("not armor: %q", armor)
	}
	if strings.Contains(armor, "private thought") {
		t.Fatal("plaintext leaked into the armor")
	}
	for i, r := range readers {
		got, err := r.Decrypt(armor)
		if err != nil {
			t.Fatalf("reader %d: %v", i, err)
		}
		if string(got) != string(plain) {
			t.Fatalf("reader %d got %q", i, got)
		}
	}
	if outsider != nil {
		if _, err := outsider.Decrypt(armor); err == nil {
			t.Fatal("a non-recipient decrypted the message")
		}
	}
}

func TestStubMeetsTheCipherContract(t *testing.T) {
	cipherConformance(t, newStub(fpA),
		[]seal.Cipher{newStub(fpA), newStub(fpB)}, newStub(fpC),
		seal.Recipients{fpA, fpB})
}

func TestSealOpenRoundTrip(t *testing.T) {
	rec := &recording{Cipher: newStub(fpA, fpB)}
	s := seal.Sealer{Cipher: rec, Policy: policy()}

	stored, err := s.Seal([]byte("dear diary"), "Day 1", []string{"diary"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, seal.Header+"hint: Day 1\n") || strings.Contains(stored, "dear diary") {
		t.Fatalf("stored %q", stored)
	}
	if !reflect.DeepEqual(rec.Calls, []seal.Recipients{{fpB}}) {
		t.Fatalf("diary must be sealed to its compartment only, got %v", rec.Calls)
	}

	plain, env, err := s.Open([]byte(stored))
	if err != nil || string(plain) != "dear diary" || env.Hint != "Day 1" {
		t.Fatalf("open: %q %+v %v", plain, env, err)
	}
}

func TestSealRefusesDoubleSealAndMultilineHint(t *testing.T) {
	s := seal.Sealer{Cipher: newStub(fpA), Policy: policy()}
	stored, _ := s.Seal([]byte("x"), "", nil)
	if _, err := s.Seal([]byte(stored), "", nil); !errors.Is(err, seal.ErrAlreadySealed) {
		t.Errorf("double seal: %v", err)
	}
	if _, err := s.Seal([]byte("x"), "a\nb", nil); !errors.Is(err, seal.ErrBadHint) {
		t.Errorf("multi-line hint: %v", err)
	}
	if _, _, err := s.Open([]byte("# plain")); !errors.Is(err, seal.ErrNotSealed) {
		t.Errorf("open plain: %v", err)
	}
}

func TestResealMovesANodeToNewRecipients(t *testing.T) {
	s := seal.Sealer{Cipher: newStub(fpA, fpB, fpC), Policy: policy()}
	stored, _ := s.Seal([]byte("x"), "kept", nil) // default: A
	resealed, err := s.Reseal([]byte(stored), []string{"health"})
	if err != nil {
		t.Fatal(err)
	}
	env, _ := seal.Parse(resealed)
	if env.Hint != "kept" {
		t.Errorf("hint lost: %+v", env)
	}
	if _, err := newStub(fpA).Decrypt(env.Armor); err == nil {
		t.Error("old recipient can still read after reseal")
	}
	if p, err := newStub(fpC).Decrypt(env.Armor); err != nil || string(p) != "x" {
		t.Errorf("new recipient: %q %v", p, err)
	}
}
