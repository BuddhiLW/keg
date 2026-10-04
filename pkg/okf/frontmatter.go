// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

// Package okf reads and writes the Open Knowledge Format (OKF) v0.2:
// markdown concepts with YAML front matter carrying a required type.
//
// https://github.com/GoogleCloudPlatform/open-knowledge-format/blob/main/SPEC.md
package okf

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Version is the OKF specification version this package produces.
const Version = "0.2"

const delim = "---"

// Split separates a leading front matter block from the body. block is
// the YAML between the delimiters, ending in a newline when non-empty.
// ok is false when content does not open with a closed block.
func Split(content string) (block, body string, ok bool) {
	s := strings.ReplaceAll(content, "\r\n", "\n")
	rest, found := strings.CutPrefix(s, delim+"\n")
	if !found {
		return "", s, false
	}
	var b strings.Builder
	for len(rest) > 0 {
		line, after, _ := strings.Cut(rest, "\n")
		if line == delim {
			return b.String(), after, true
		}
		b.WriteString(line + "\n")
		rest = after
	}
	return "", s, false
}

// Fields decodes a front matter block into its top-level keys.
func Fields(block string) (map[string]any, error) {
	m := map[string]any{}
	if strings.TrimSpace(block) == "" {
		return m, nil
	}
	if err := yaml.Unmarshal([]byte(block), &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Join renders a front matter block followed by body.
func Join(block, body string) string {
	if block != "" && !strings.HasSuffix(block, "\n") {
		block += "\n"
	}
	return delim + "\n" + block + delim + "\n" + body
}
