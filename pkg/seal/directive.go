// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Directive is what a note asks of the sealer in its own front matter:
//
//	---
//	seal: true              # or: seal: [FPR, FPR]  /  seal: FPR,FPR
//	seal-hint: public title # optional
//	---
//
// Seal marks a plaintext note to be sealed before it is published. To,
// when set, names the only recipients, overriding the keg policy.
type Directive struct {
	Seal bool
	To   Recipients
	Hint string
}

var sealKeyExp = regexp.MustCompile(`(?m)^seal(-hint)?\s*:`)

// ParseDirective reads the directive from the front matter at the top
// of content. Content without front matter, or without a seal key, has
// the zero Directive. A seal key that cannot be understood is an error:
// guessing would seal to the wrong people or leave the note in the clear.
func ParseDirective(content []byte) (Directive, error) {
	block, ok := frontMatter(string(content))
	if !ok || !sealKeyExp.MatchString(block) {
		return Directive{}, nil
	}
	var fm struct {
		Seal yaml.Node `yaml:"seal"`
		Hint string    `yaml:"seal-hint"`
	}
	if err := yaml.Unmarshal([]byte(block), &fm); err != nil {
		return Directive{}, fmt.Errorf("seal: front matter: %w", err)
	}
	if !ValidHint(fm.Hint) {
		return Directive{}, ErrBadHint
	}
	d := Directive{Hint: strings.TrimSpace(fm.Hint)}
	var err error
	d.Seal, d.To, err = sealValue(&fm.Seal)
	if err != nil {
		return Directive{}, err
	}
	return d, nil
}

// yamlWords are the YAML 1.1 booleans that YAML 1.2 reads as strings.
var yamlWords = map[string]bool{
	"yes": true, "y": true, "on": true,
	"no": false, "n": false, "off": false,
}

// sealValue interprets the `seal:` node: a boolean, a comma list of
// fingerprints, or a YAML list of fingerprints.
func sealValue(n *yaml.Node) (bool, Recipients, error) {
	switch n.Kind {
	case 0:
		return false, nil, nil
	case yaml.ScalarNode:
		if n.Tag == "!!bool" {
			var b bool
			if err := n.Decode(&b); err != nil {
				return false, nil, fmt.Errorf("seal: %w", err)
			}
			return b, nil, nil
		}
		if b, ok := yamlWords[strings.ToLower(strings.TrimSpace(n.Value))]; ok {
			return b, nil, nil
		}
		fps := SplitCSV(n.Value)
		if len(fps) == 0 {
			return false, nil, fmt.Errorf("seal: empty seal value; use true, false or fingerprints")
		}
		rs, err := ParseRecipients(fps)
		return err == nil, rs, err
	case yaml.SequenceNode:
		var fps []string
		if err := n.Decode(&fps); err != nil {
			return false, nil, fmt.Errorf("seal: %w", err)
		}
		if len(fps) == 0 {
			return false, nil, fmt.Errorf("seal: empty recipient list")
		}
		rs, err := ParseRecipients(fps)
		return err == nil, rs, err
	default:
		return false, nil, fmt.Errorf("seal: seal must be true, false or fingerprints")
	}
}

// frontMatter returns the YAML between a leading `---` line and the
// next `---` or `...` line.
func frontMatter(s string) (string, bool) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	rest, ok := strings.CutPrefix(s, "---\n")
	if !ok {
		return "", false
	}
	var b strings.Builder
	for _, line := range strings.SplitAfter(rest, "\n") {
		if t := strings.TrimRight(line, "\n"); t == "---" || t == "..." {
			return b.String(), true
		}
		b.WriteString(line)
	}
	return "", false
}

// FirstHint returns the first non-empty hint.
func FirstHint(hints ...string) string {
	for _, h := range hints {
		if h != "" {
			return h
		}
	}
	return ""
}
