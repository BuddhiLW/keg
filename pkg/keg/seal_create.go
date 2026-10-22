// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package keg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BuddhiLW/keg/pkg/seal"
)

// EncryptOptions is what `keg create encrypt` was asked on the command
// line.
type EncryptOptions struct {
	To             []string // fingerprints, or files holding one
	Keys           []string // public key files
	Homedir        string
	ShowRecipients bool
	Hint           string
}

// ParseEncryptArgs reads the leading parameters of `keg create encrypt`:
// `to`, `key` and `homedir` take the next word as their value,
// `show-recipients` takes none. The first other word starts the hint.
func ParseEncryptArgs(args []string) (EncryptOptions, error) {
	var o EncryptOptions
	for i := 0; i < len(args); i++ {
		word := args[i]
		if word == `show-recipients` {
			o.ShowRecipients = true
			continue
		}
		if word != `to` && word != `key` && word != `homedir` {
			o.Hint = strings.Join(args[i:], ` `)
			break
		}
		i++
		if i >= len(args) || strings.TrimSpace(args[i]) == "" {
			return o, fmt.Errorf("keg: %v needs a value", word)
		}
		switch word {
		case `to`:
			o.To = append(o.To, args[i])
		case `key`:
			o.Keys = append(o.Keys, args[i])
		case `homedir`:
			o.Homedir = args[i]
		}
	}
	return o, nil
}

// Prompter asks the human one question and returns the answer.
type Prompter interface {
	Ask(question string) (string, error)
}

// AskEncryptOptions fills a bare `keg create encrypt` through p: the
// public hint, then the recipients. A blank answer keeps the default.
func AskEncryptOptions(p Prompter) (EncryptOptions, error) {
	var answers [3]string
	for i, q := range []string{
		`public hint, shown in the index (blank: ` + SealedTitle + `)`,
		`encrypt to fingerprints or fingerprint files (blank: keg policy)`,
		`public key files to encrypt to (blank: none)`,
	} {
		a, err := p.Ask(q)
		if err != nil {
			return EncryptOptions{}, err
		}
		answers[i] = a
	}
	return EncryptOptions{
		Hint: strings.TrimSpace(answers[0]),
		To:   words(answers[1]),
		Keys: words(answers[2]),
	}, nil
}

// words splits s on spaces; a blank s has no words.
func words(s string) []string {
	if f := strings.Fields(s); len(f) > 0 {
		return f
	}
	return nil
}

// KeyFileReader returns the fingerprint of the public key in a file.
type KeyFileReader func(o seal.GPGOptions, path string) (seal.Fingerprint, error)

// EncryptPlan is how nodes are sealed: the gpg options, and the
// recipients a new node's directive names (none means the keg policy).
type EncryptPlan struct {
	GPG seal.GPGOptions
	To  seal.Recipients
}

// PlanEncrypt combines the keg settings with the command line options.
// Every key file, from the keg settings or --key, becomes a place gpg
// finds that recipient; only --to and --key name recipients.
func PlanEncrypt(st seal.Settings, o EncryptOptions, readFile func(string) ([]byte, error), keyFile KeyFileReader) (EncryptPlan, error) {
	g := st.GPG
	if o.Homedir != "" {
		g.Homedir = o.Homedir
	}
	g.Homedir = expandHome(g.Homedir)
	if o.ShowRecipients {
		g.ShowRecipients = true
	}
	files := map[seal.Fingerprint]string{}
	for fp, f := range g.KeyFiles {
		files[fp] = f
	}
	locate := func(path string) (seal.Fingerprint, error) {
		path = expandHome(path)
		fp, err := keyFile(g, path)
		if err != nil {
			return "", fmt.Errorf("key file %v: %w", path, err)
		}
		files[fp] = path
		return fp, nil
	}
	for _, f := range st.KeyFiles {
		if _, err := locate(f); err != nil {
			return EncryptPlan{}, err
		}
	}
	var to seal.Recipients
	for _, k := range o.Keys {
		fp, err := locate(k)
		if err != nil {
			return EncryptPlan{}, err
		}
		to = append(to, fp)
	}
	for _, t := range o.To {
		fp, err := recipientArg(t, readFile)
		if err != nil {
			return EncryptPlan{}, err
		}
		to = append(to, fp)
	}
	g.KeyFiles = files
	return EncryptPlan{GPG: g, To: to.Normal()}, nil
}

// recipientArg reads a --to value: a fingerprint, or a file holding one.
func recipientArg(s string, readFile func(string) ([]byte, error)) (seal.Fingerprint, error) {
	fp, err := seal.ParseFingerprint(s)
	if err == nil {
		return fp, nil
	}
	buf, rerr := readFile(expandHome(s))
	if rerr != nil {
		return "", err
	}
	return seal.ParseFingerprint(strings.TrimSpace(string(buf)))
}

// Prefill is the plaintext a new encrypted node opens with: a directive
// naming its recipients, so later edits and rekeys keep them.
func (p EncryptPlan) Prefill() []byte {
	if len(p.To) == 0 {
		return nil
	}
	return []byte(seal.RenderDirective(p.To))
}

func expandHome(p string) string {
	if p == `~` || strings.HasPrefix(p, `~/`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

func gpgKeyFile(o seal.GPGOptions, path string) (seal.Fingerprint, error) {
	return seal.NewGPG(o).KeyFile(path)
}

// planSealer returns the gpg-backed Sealer for the keg under o, and the
// plan it was built from.
func planSealer(kegpath string, o EncryptOptions) (seal.Sealer, EncryptPlan, error) {
	st, err := SealSettings(kegpath)
	if err != nil {
		return seal.Sealer{}, EncryptPlan{}, err
	}
	plan, err := PlanEncrypt(st, o, os.ReadFile, gpgKeyFile)
	if err != nil {
		return seal.Sealer{}, EncryptPlan{}, err
	}
	return seal.Sealer{Cipher: seal.NewGPG(plan.GPG), Policy: st.Policy}, plan, nil
}
