package seal_test

import (
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"github.com/BuddhiLW/keg/pkg/seal"
)

var propConfig = &quick.Config{MaxCount: 500}

// randFP returns a v4 or v5 fingerprint; some are all digits, which
// YAML would read as a number.
func randFP(r *rand.Rand) seal.Fingerprint {
	n, alphabet := 40, "0123456789ABCDEF"
	if r.Intn(4) == 0 {
		n = 64
	}
	if r.Intn(5) == 0 {
		alphabet = "0123456789"
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return seal.Fingerprint(b)
}

// recipientList is one to five fingerprints, some repeated.
type recipientList seal.Recipients

func (recipientList) Generate(r *rand.Rand, _ int) reflect.Value {
	var rs recipientList
	for i := 0; i < 1+r.Intn(5); i++ {
		fp := randFP(r)
		rs = append(rs, fp)
		if r.Intn(3) == 0 {
			rs = append(rs, fp)
		}
	}
	return reflect.ValueOf(rs)
}

func TestPropDirectiveRoundTrip(t *testing.T) {
	prop := func(l recipientList) bool {
		rs := seal.Recipients(l)
		d, err := seal.ParseDirective([]byte(seal.RenderDirective(rs) + "# Body\n"))
		return err == nil && d.Seal && reflect.DeepEqual(d.To, rs.Normal())
	}
	if err := quick.Check(prop, propConfig); err != nil {
		t.Fatal(err)
	}
}

// argvCase is a recipient set, some of whose keys live in files.
type argvCase struct {
	To    seal.Recipients
	Files map[seal.Fingerprint]string
	Show  bool
}

func (argvCase) Generate(r *rand.Rand, _ int) reflect.Value {
	c := argvCase{Files: map[seal.Fingerprint]string{}, Show: r.Intn(2) == 0}
	for i := 0; i < r.Intn(5); i++ {
		fp := randFP(r)
		c.To = append(c.To, fp)
		if r.Intn(2) == 0 {
			c.Files[fp] = "/keys/" + string(fp[:8]) + ".pub"
		}
	}
	c.To = c.To.Normal()
	return reflect.ValueOf(c)
}

func TestPropEncryptArgvNamesEachRecipientOnce(t *testing.T) {
	prop := func(c argvCase) bool {
		argv := seal.EncryptArgv(seal.GPGOptions{Bin: "gpg", ShowRecipients: c.Show, KeyFiles: c.Files}, c.To)
		if contains(argv, "--throw-keyids") == c.Show {
			return false
		}
		tail := argv[indexOf(argv, "--encrypt")+1:]
		if len(c.To) == 0 {
			return reflect.DeepEqual(tail, []string{"--default-recipient-self"})
		}
		if len(tail) != 2*len(c.To) {
			return false
		}
		for i, fp := range c.To {
			want := []string{"--recipient", string(fp)}
			if f, ok := c.Files[fp]; ok {
				want = []string{"--recipient-file", f}
			}
			if !reflect.DeepEqual(tail[2*i:2*i+2], want) {
				return false
			}
		}
		return true
	}
	if err := quick.Check(prop, propConfig); err != nil {
		t.Fatal(err)
	}
}

// keyListing is the colon output of gpg --show-keys for a few keys,
// each public or secret, with subkeys.
type keyListing struct {
	Out     string
	Secret  bool
	Primary []seal.Fingerprint
}

func (keyListing) Generate(r *rand.Rand, _ int) reflect.Value {
	var l keyListing
	var b strings.Builder
	for i := 0; i < r.Intn(4); i++ {
		head, sub := "pub", "sub"
		if r.Intn(4) == 0 {
			head, sub, l.Secret = "sec", "ssb", true
		}
		fp := randFP(r)
		l.Primary = append(l.Primary, fp)
		b.WriteString(head + ":-:255:22:X:1::::::scESC::::::23::0:\nfpr:::::::::" + string(fp) + ":\n")
		b.WriteString("uid:-::::1::H::Some One <one@keg.test>::::::::::0:\n")
		for j := 0; j < r.Intn(3); j++ {
			b.WriteString(sub + ":-:255:18:Y:1::::::e::::::23:\nfpr:::::::::" + string(randFP(r)) + ":\n")
		}
	}
	l.Out = b.String()
	return reflect.ValueOf(l)
}

func TestPropKeyFileResultReturnsTheOnePublicPrimary(t *testing.T) {
	prop := func(l keyListing) bool {
		fp, err := seal.KeyFileResult(seal.ExecResult{Stdout: []byte(l.Out)})
		switch {
		case l.Secret:
			return errors.Is(err, seal.ErrSecretKeyFile)
		case len(l.Primary) == 1:
			return err == nil && fp == l.Primary[0]
		default:
			return err != nil && fp == ""
		}
	}
	if err := quick.Check(prop, propConfig); err != nil {
		t.Fatal(err)
	}
}

func indexOf(ss []string, s string) int {
	for i, x := range ss {
		if x == s {
			return i
		}
	}
	return -1
}
