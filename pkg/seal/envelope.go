// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

// Package seal encrypts KEG node content to one or more OpenPGP
// recipients so that private nodes can live in a public git history.
//
// The package is stratified: envelope, recipient and policy are pure
// domain values; Cipher is the port; GPG is the boundary adapter;
// Sealer is the pipeline that composes them.
package seal

import "strings"

// Header opens every sealed node. It is byte-identical to the hive
// memory envelope so hive can store a sealed node without opening it.
const Header = "#hive/sealed 1\n"

const hintPrefix = "hint: "

const (
	armorBegin = "-----BEGIN PGP MESSAGE-----"
	armorEnd   = "-----END PGP MESSAGE-----"
)

// Envelope is sealed node content: an optional public one-line hint and
// the ASCII-armored ciphertext.
type Envelope struct {
	Hint  string
	Armor string
}

// Render returns the stored form of the envelope.
func (e Envelope) Render() string {
	var b strings.Builder
	b.WriteString(Header)
	if e.Hint != "" {
		b.WriteString(hintPrefix + e.Hint + "\n")
	}
	b.WriteString(e.Armor)
	if !strings.HasSuffix(e.Armor, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

// Parse returns the envelope held in content, and false when content is
// not a whole, well-formed envelope.
func Parse(content string) (Envelope, bool) {
	body, ok := strings.CutPrefix(content, Header)
	if !ok {
		return Envelope{}, false
	}
	var env Envelope
	if rest, ok := strings.CutPrefix(body, hintPrefix); ok {
		line, after, found := strings.Cut(rest, "\n")
		if !found {
			return Envelope{}, false
		}
		env.Hint, body = line, after
	}
	if !IsArmor(body) {
		return Envelope{}, false
	}
	env.Armor = body
	return env, true
}

// IsSealed reports whether content is a well-formed envelope.
func IsSealed(content []byte) bool {
	_, ok := Parse(string(content))
	return ok
}

// IsArmor reports whether s is exactly one ASCII-armored PGP message.
func IsArmor(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, armorBegin) && strings.HasSuffix(t, armorEnd)
}

// ValidHint reports whether h can be stored as a hint: a single line.
func ValidHint(h string) bool {
	return !strings.ContainsAny(h, "\r\n")
}
