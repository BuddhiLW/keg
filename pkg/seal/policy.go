// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

import "sort"

// Policy decides which nodes must be sealed and to whom.
//
// Default recipients apply to every sealed node. A tag listed in
// TopicRecipients is its own compartment: a node carrying it is sealed
// to that tag's keys INSTEAD of the default, and a node carrying several
// mapped tags is sealed to the union of them. Topics lists the tags
// whose nodes may never be stored in the clear.
type Policy struct {
	Default         Recipients
	TopicRecipients map[string]Recipients
	Topics          map[string]bool
}

// RecipientsFor returns the recipients a node with tags is sealed to.
// An empty result means gpg's default recipient (the user's own key).
func (p Policy) RecipientsFor(tags []string) Recipients {
	var mapped Recipients
	hit := false
	for _, t := range tags {
		if rs, ok := p.TopicRecipients[t]; ok {
			hit = true
			mapped = mapped.Union(rs)
		}
	}
	if hit {
		return mapped
	}
	return p.Default.Normal()
}

// MustSeal reports whether any tag names a sealed topic or a mapped
// compartment; such a node may not be published in the clear.
func (p Policy) MustSeal(tags []string) bool {
	for _, t := range tags {
		if p.Topics[t] {
			return true
		}
		if _, ok := p.TopicRecipients[t]; ok {
			return true
		}
	}
	return false
}

// SealedTopics returns every tag MustSeal answers true for, sorted.
func (p Policy) SealedTopics() []string {
	set := map[string]bool{}
	for t, on := range p.Topics {
		if on {
			set[t] = true
		}
	}
	for t := range p.TopicRecipients {
		set[t] = true
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
