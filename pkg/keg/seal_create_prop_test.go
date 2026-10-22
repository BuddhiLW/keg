package keg_test

import (
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"github.com/BuddhiLW/keg/pkg/keg"
	"github.com/BuddhiLW/keg/pkg/seal"
)

var propConfig = &quick.Config{MaxCount: 500}

var paramWords = []string{"to", "key", "homedir", "show-recipients"}

// randWord is a non-empty word without spaces; sometimes a parameter
// name, which is legal as a value or inside the hint.
func randWord(r *rand.Rand) string {
	if r.Intn(4) == 0 {
		return paramWords[r.Intn(len(paramWords))]
	}
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789~/.-"
	b := make([]byte, 1+r.Intn(10))
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

// encryptCall is options and a command line that spells them, with the
// parameters in random order.
type encryptCall struct {
	Want keg.EncryptOptions
	Args []string
}

func (encryptCall) Generate(r *rand.Rand, _ int) reflect.Value {
	var o keg.EncryptOptions
	var params [][]string
	for i := 0; i < r.Intn(3); i++ {
		v := randWord(r)
		o.To = append(o.To, v)
		params = append(params, []string{"to", v})
	}
	for i := 0; i < r.Intn(3); i++ {
		v := randWord(r)
		o.Keys = append(o.Keys, v)
		params = append(params, []string{"key", v})
	}
	if r.Intn(2) == 0 {
		o.Homedir = randWord(r)
		params = append(params, []string{"homedir", o.Homedir})
	}
	if r.Intn(2) == 0 {
		o.ShowRecipients = true
		params = append(params, []string{"show-recipients"})
	}
	r.Shuffle(len(params), func(i, j int) { params[i], params[j] = params[j], params[i] })
	// a to or key may only be reordered among its own kind
	o.To, o.Keys = nil, nil
	var args []string
	for _, p := range params {
		args = append(args, p...)
		switch p[0] {
		case "to":
			o.To = append(o.To, p[1])
		case "key":
			o.Keys = append(o.Keys, p[1])
		}
	}
	if n := r.Intn(4); n > 0 {
		hint := []string{"hint" + randWord(r)}
		for i := 1; i < n; i++ {
			hint = append(hint, randWord(r))
		}
		o.Hint = strings.Join(hint, " ")
		args = append(args, hint...)
	}
	return reflect.ValueOf(encryptCall{Want: o, Args: args})
}

func TestPropParseEncryptArgsReadsWhatWasWritten(t *testing.T) {
	prop := func(c encryptCall) bool {
		got, err := keg.ParseEncryptArgs(c.Args)
		return err == nil && reflect.DeepEqual(got, c.Want)
	}
	if err := quick.Check(prop, propConfig); err != nil {
		t.Fatal(err)
	}
}

// planCase is recipients named by fingerprint and by key file, plus key
// files the keg settings list only so gpg can find them.
type planCase struct {
	To       []string // fingerprints as typed: any case, maybe spaced
	Keys     map[string]seal.Fingerprint
	Settings map[string]seal.Fingerprint
}

func randFP(r *rand.Rand) seal.Fingerprint {
	const hex = "0123456789ABCDEF"
	b := make([]byte, 40)
	for i := range b {
		b[i] = hex[r.Intn(len(hex))]
	}
	return seal.Fingerprint(b)
}

func (planCase) Generate(r *rand.Rand, _ int) reflect.Value {
	c := planCase{Keys: map[string]seal.Fingerprint{}, Settings: map[string]seal.Fingerprint{}}
	for i := 0; i < r.Intn(4); i++ {
		typed := string(randFP(r))
		if r.Intn(2) == 0 {
			typed = strings.ToLower(typed)
		}
		if r.Intn(3) == 0 {
			typed = typed[:20] + " " + typed[20:]
		}
		c.To = append(c.To, typed)
	}
	for i := 0; i < r.Intn(3); i++ {
		c.Keys["/keys/k"+string(rune('a'+i))+".pub"] = randFP(r)
	}
	for i := 0; i < r.Intn(3); i++ {
		c.Settings["/keg/s"+string(rune('a'+i))+".pub"] = randFP(r)
	}
	return reflect.ValueOf(c)
}

func TestPropPlanEncryptNamesOnlyAskedRecipients(t *testing.T) {
	prop := func(c planCase) bool {
		files := map[string]seal.Fingerprint{}
		o := keg.EncryptOptions{To: c.To}
		st := seal.Settings{}
		var want seal.Recipients
		for p, fp := range c.Keys {
			files[p] = fp
			o.Keys = append(o.Keys, p)
			want = append(want, fp)
		}
		for p, fp := range c.Settings {
			files[p] = fp
			st.KeyFiles = append(st.KeyFiles, p)
		}
		for _, typed := range c.To {
			fp, _ := seal.ParseFingerprint(typed)
			want = append(want, fp)
		}
		keyFile := func(_ seal.GPGOptions, p string) (seal.Fingerprint, error) { return files[p], nil }
		noFiles := func(string) ([]byte, error) { return nil, os.ErrNotExist }
		plan, err := keg.PlanEncrypt(st, o, noFiles, keyFile)
		if err != nil || !reflect.DeepEqual(plan.To, want.Normal()) {
			return false
		}
		for p, fp := range files {
			if plan.GPG.KeyFiles[fp] != p {
				return false
			}
		}
		return len(plan.GPG.KeyFiles) == len(files) && (plan.Prefill() == nil) == (len(want) == 0)
	}
	if err := quick.Check(prop, propConfig); err != nil {
		t.Fatal(err)
	}
}
