// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Fingerprint is an OpenPGP v4 (40 hex) or v5/v6 (64 hex) key
// fingerprint, upper case and without spaces.
type Fingerprint string

var fingerprintExp = regexp.MustCompile(`^(?:[0-9A-F]{40}|[0-9A-F]{64})$`)

// ParseFingerprint normalises s and fails when it is not a full
// fingerprint. Short key ids and user ids are refused: they can match
// a key other than the one intended.
func ParseFingerprint(s string) (Fingerprint, error) {
	n := strings.ToUpper(strings.Join(strings.Fields(s), ""))
	n = strings.TrimPrefix(n, "0X")
	if !fingerprintExp.MatchString(n) {
		return "", fmt.Errorf("seal: %q is not a full OpenPGP fingerprint", s)
	}
	return Fingerprint(n), nil
}

// Recipients is a set of fingerprints kept sorted and free of
// duplicates, so equal sets render identically.
type Recipients []Fingerprint

// ParseRecipients parses every entry and fails on the first bad one.
func ParseRecipients(ss []string) (Recipients, error) {
	var rs Recipients
	for _, s := range ss {
		if strings.TrimSpace(s) == "" {
			continue
		}
		fp, err := ParseFingerprint(s)
		if err != nil {
			return nil, err
		}
		rs = append(rs, fp)
	}
	return rs.Normal(), nil
}

// Normal returns the set sorted and deduplicated.
func (rs Recipients) Normal() Recipients {
	seen := map[Fingerprint]bool{}
	out := Recipients{}
	for _, r := range rs {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Union returns every fingerprint in rs or other.
func (rs Recipients) Union(other Recipients) Recipients {
	return append(append(Recipients{}, rs...), other...).Normal()
}

// Strings returns the fingerprints as plain strings.
func (rs Recipients) Strings() []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}
