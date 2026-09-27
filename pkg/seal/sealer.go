// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"errors"
	"fmt"
)

var (
	ErrAlreadySealed = errors.New("seal: content is already sealed")
	ErrNotSealed     = errors.New("seal: content is not sealed")
	ErrBadHint       = errors.New("seal: hint must be a single line")
)

// Sealer seals and opens node content under a Policy through a Cipher.
type Sealer struct {
	Cipher Cipher
	Policy Policy
}

// Seal encrypts plain for the recipients tags select and returns the
// stored envelope. The hint is public: it becomes the node's title in
// the index, so it must not carry the secret.
func (s Sealer) Seal(plain []byte, hint string, tags []string) (string, error) {
	if IsSealed(plain) {
		return "", ErrAlreadySealed
	}
	if !ValidHint(hint) {
		return "", ErrBadHint
	}
	armor, err := s.Cipher.Encrypt(plain, s.Policy.RecipientsFor(tags))
	if err != nil {
		return "", err
	}
	if !IsArmor(armor) {
		return "", fmt.Errorf("seal: cipher returned something other than armor")
	}
	return Envelope{Hint: hint, Armor: armor}.Render(), nil
}

// Open returns the plaintext of a sealed envelope and the envelope.
func (s Sealer) Open(content []byte) ([]byte, Envelope, error) {
	env, ok := Parse(string(content))
	if !ok {
		return nil, Envelope{}, ErrNotSealed
	}
	plain, err := s.Cipher.Decrypt(env.Armor)
	if err != nil {
		return nil, env, err
	}
	return plain, env, nil
}

// Reseal re-encrypts sealed content to the recipients tags select now,
// keeping its hint. It is how a key is added to or removed from a node.
func (s Sealer) Reseal(content []byte, tags []string) (string, error) {
	plain, env, err := s.Open(content)
	if err != nil {
		return "", err
	}
	return s.Seal(plain, env.Hint, tags)
}
