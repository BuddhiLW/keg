// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNoKeyring      = errors.New("seal: no keyring configured")
	ErrKeyringMissing = errors.New("keyring not found (not mounted?)")
	ErrNoSecretKey    = errors.New("no secret key here opened it (not a recipient, or its passphrase was not given)")
)

// Keyring is a Cipher under the name a human knows it by.
type Keyring struct {
	Name   string
	Cipher Cipher
}

// Keyrings is the Cipher over several keyrings: it encrypts with the
// first and decrypts with whichever opens the message.
type Keyrings []Keyring

// Encrypt encrypts with the first keyring only. Falling back to a later
// one would seal to keys other than those asked for.
func (ks Keyrings) Encrypt(plain []byte, to Recipients) (string, error) {
	if len(ks) == 0 {
		return "", ErrNoKeyring
	}
	armor, err := ks[0].Cipher.Encrypt(plain, to)
	if err != nil {
		return "", fmt.Errorf("keyring %v: %w", ks[0].Name, err)
	}
	return armor, nil
}

// CanEncrypt reports why Encrypt would fail before any work is done:
// no keyring, or a first keyring that is not there.
func (ks Keyrings) CanEncrypt() error {
	if len(ks) == 0 {
		return ErrNoKeyring
	}
	if _, absent := ks[0].Cipher.(missing); absent {
		return fmt.Errorf("keyring %v: %w", ks[0].Name, ErrKeyringMissing)
	}
	return nil
}

// Decrypt tries each keyring in order and returns the first plaintext.
// When none opens armor the error names every keyring and why.
func (ks Keyrings) Decrypt(armor string) ([]byte, error) {
	if len(ks) == 0 {
		return nil, ErrNoKeyring
	}
	var why []string
	var errs []error
	for _, k := range ks {
		plain, err := k.Cipher.Decrypt(armor)
		if err == nil {
			return plain, nil
		}
		why = append(why, k.Name+": "+err.Error())
		errs = append(errs, err)
	}
	return nil, &NoKeyringOpened{Tried: why, errs: errs}
}

// NoKeyringOpened is the error of a Decrypt no keyring could do.
type NoKeyringOpened struct {
	Tried []string
	errs  []error
}

func (e *NoKeyringOpened) Error() string {
	return "seal: no keyring opened this node (tried " + strings.Join(e.Tried, "; ") + ")"
}

func (e *NoKeyringOpened) Unwrap() []error { return e.errs }

// missing is the Cipher of a keyring directory that does not exist.
type missing struct{}

func (missing) Encrypt([]byte, Recipients) (string, error) { return "", ErrKeyringMissing }
func (missing) Decrypt(string) ([]byte, error)             { return nil, ErrKeyringMissing }

// GPGKeyrings returns one gpg Keyring per homedir, "" meaning gpg's
// default. A homedir that exists reports false is a missing keyring.
func GPGKeyrings(o GPGOptions, homedirs []string, exists func(string) bool) Keyrings {
	if len(homedirs) == 0 {
		homedirs = []string{o.Homedir}
	}
	var ks Keyrings
	for _, h := range homedirs {
		g := o
		g.Homedir = h
		name := h
		if name == "" {
			name = "gpg default keyring"
		}
		var c Cipher = NewGPG(g)
		if h != "" && !exists(h) {
			c = missing{}
		}
		ks = append(ks, Keyring{Name: name, Cipher: c})
	}
	return ks
}
