// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package okf

import (
	"errors"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TimeFmt is the ISO 8601 UTC form OKF timestamps use.
const TimeFmt = `2006-01-02T15:04:05Z`

var ErrBlankKey = errors.New("okf: key present but empty")

// Defaults are the values Complete writes for the keys a concept lacks.
type Defaults struct {
	Type  string    // type
	Title string    // title, usually the first heading
	Tags  []string  // tags
	Actor string    // generated.by, in the OKF actor convention
	At    time.Time // generated.at when no published date is known
}

// Complete returns content with the OKF keys it lacks appended to its
// front matter, and the names of the keys added. Keys already present
// are left as written. Content without front matter gains a block.
func Complete(content string, d Defaults) (string, []string, error) {
	block, body, ok := Split(content)
	if !ok {
		block, body = "", content
	}
	have, err := Fields(block)
	if err != nil {
		return content, nil, err
	}

	add := &yaml.Node{Kind: yaml.MappingNode}
	var added []string
	put := func(k string, v *yaml.Node) {
		add.Content = append(add.Content, scalar(k), v)
		added = append(added, k)
	}

	if v, has := have["type"]; has && blank(v) {
		return content, nil, ErrBlankKey
	} else if !has && d.Type != "" {
		put("type", scalar(d.Type))
	}
	if _, has := have["title"]; !has && d.Title != "" {
		put("title", scalar(d.Title))
	}
	if _, has := have["tags"]; !has && len(d.Tags) > 0 {
		put("tags", flowSeq(d.Tags))
	}
	if _, has := have["generated"]; !has && d.Actor != "" {
		at := d.At
		if p, ok := published(have["published"]); ok {
			at = p
		}
		gen := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
		gen.Content = append(gen.Content, scalar("by"), scalar(d.Actor))
		if !at.IsZero() {
			gen.Content = append(gen.Content, scalar("at"), scalar(at.UTC().Format(TimeFmt)))
		}
		put("generated", gen)
	}
	if _, has := have["status"]; !has && have["draft"] == true {
		put("status", scalar("draft"))
	}

	if len(added) == 0 {
		return content, nil, nil
	}
	out, err := yaml.Marshal(add)
	if err != nil {
		return content, nil, err
	}
	return Join(block+string(out), body), added, nil
}

// Problem kinds a concept document can have.
const (
	NoFrontMatter = "no front matter"
	BadYAML       = "front matter is not YAML"
	NoType        = "no type"
)

// CheckConcept returns the conformance problem of a concept document,
// or "" when it conforms.
func CheckConcept(content string) string {
	block, _, ok := Split(content)
	if !ok {
		return NoFrontMatter
	}
	m, err := Fields(block)
	if err != nil {
		return BadYAML
	}
	if blank(m["type"]) {
		return NoType
	}
	return ""
}

func blank(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// published reads a `published` date as written by static site
// generators: a YAML timestamp or a YYYY-MM-DD string.
func published(v any) (time.Time, bool) {
	switch p := v.(type) {
	case time.Time:
		return p, true
	case string:
		for _, f := range []string{time.RFC3339, `2006-01-02`} {
			if t, err := time.Parse(f, strings.TrimSpace(p)); err == nil {
				return t, true
			}
		}
	}
	return time.Time{}, false
}

func scalar(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}

func flowSeq(items []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, s := range items {
		n.Content = append(n.Content, scalar(s))
	}
	return n
}
