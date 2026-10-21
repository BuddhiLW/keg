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

// ParseEncryptArgs reads the options of `keg create encrypt`. Words that
// are not options form the hint; `--` ends the options.
func ParseEncryptArgs(args []string) (EncryptOptions, error) {
	var o EncryptOptions
	var hint []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == `--` {
			hint = append(hint, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, `--`) {
			hint = append(hint, a)
			continue
		}
		name, val, inline := strings.Cut(a[2:], `=`)
		if name == `show-recipients` {
			if inline {
				return o, fmt.Errorf("keg: --show-recipients takes no value")
			}
			o.ShowRecipients = true
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				return o, fmt.Errorf("keg: --%v needs a value", name)
			}
			i++
			val = args[i]
		}
		if strings.TrimSpace(val) == "" {
			return o, fmt.Errorf("keg: --%v needs a value", name)
		}
		switch name {
		case `to`:
			o.To = append(o.To, val)
		case `key`:
			o.Keys = append(o.Keys, val)
		case `homedir`:
			o.Homedir = val
		default:
			return o, fmt.Errorf("keg: unknown option --%v (want --to, --key, --homedir or --show-recipients)", name)
		}
	}
	o.Hint = strings.Join(hint, ` `)
	return o, nil
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
	if len(files) > 0 {
		g.KeyFiles = files
	}
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
