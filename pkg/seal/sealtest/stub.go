// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

// Package sealtest provides an in-memory seal.Cipher for tests. It is
// held to the same conformance suite as the gpg adapter.
package sealtest

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/BuddhiLW/keg/pkg/seal"
)

// Stub is an in-memory Cipher. Each "key" is a fingerprint; a message
// is readable only by a Stub holding one of its recipients.
type Stub struct {
	Self  seal.Fingerprint
	Holds map[seal.Fingerprint]bool
}

// New returns a Stub whose own key is self and which also holds the
// secret keys in holds.
func New(self seal.Fingerprint, holds ...seal.Fingerprint) *Stub {
	s := &Stub{Self: self, Holds: map[seal.Fingerprint]bool{self: true}}
	for _, h := range holds {
		s.Holds[h] = true
	}
	return s
}

func (s *Stub) Encrypt(plain []byte, to seal.Recipients) (string, error) {
	if len(to) == 0 {
		to = seal.Recipients{s.Self}
	}
	body := strings.Join(to.Strings(), ",") + "|" + base64.StdEncoding.EncodeToString(plain)
	return "-----BEGIN PGP MESSAGE-----\n\n" + body + "\n-----END PGP MESSAGE-----\n", nil
}

func (s *Stub) Decrypt(armor string) ([]byte, error) {
	t := strings.TrimSpace(armor)
	t = strings.TrimPrefix(t, "-----BEGIN PGP MESSAGE-----")
	t = strings.TrimSuffix(t, "-----END PGP MESSAGE-----")
	rcpts, b64, ok := strings.Cut(strings.TrimSpace(t), "|")
	if !ok {
		return nil, errors.New("sealtest: malformed message")
	}
	for _, r := range strings.Split(rcpts, ",") {
		if s.Holds[seal.Fingerprint(r)] {
			return base64.StdEncoding.DecodeString(b64)
		}
	}
	return nil, errors.New("sealtest: no secret key")
}

// Recording decorates a Cipher and records every recipient set it was
// asked to encrypt to.
type Recording struct {
	seal.Cipher
	Calls []seal.Recipients
}

func (r *Recording) Encrypt(plain []byte, to seal.Recipients) (string, error) {
	r.Calls = append(r.Calls, to)
	return r.Cipher.Encrypt(plain, to)
}
