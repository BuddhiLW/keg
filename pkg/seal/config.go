// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// GPGOptions configures the gpg boundary.
type GPGOptions struct {
	Bin     string
	Homedir string
	// ShowRecipients writes recipient key ids into the ciphertext. Off
	// by default: a public repo then does not reveal who can read a node.
	ShowRecipients bool
}

// Settings is everything a keg says about sealing.
type Settings struct {
	Policy Policy
	GPG    GPGOptions
}

// Environment variables that override the keg file.
const (
	EnvRecipients      = `KEG_SEAL_RECIPIENTS`
	EnvTopicRecipients = `KEG_SEAL_TOPIC_RECIPIENTS`
	EnvTopics          = `KEG_SEALED_TOPICS`
	EnvGPGBin          = `KEG_SEAL_GPG_BIN`
	EnvGPGHomedir      = `KEG_SEAL_GPG_HOMEDIR`
)

type sealBlock struct {
	Recipients      []string            `yaml:"recipients"`
	Topics          []string            `yaml:"topics"`
	TopicRecipients map[string][]string `yaml:"topic-recipients"`
	ShowRecipients  bool                `yaml:"show-recipients"`
	GPG             struct {
		Bin     string `yaml:"bin"`
		Homedir string `yaml:"homedir"`
	} `yaml:"gpg"`
}

// ParseSettings reads the `seal:` section of a keg info file and applies
// the KEG_SEAL_* environment overrides read through getenv. A malformed
// entry is an error, never dropped: dropping one would seal a node to
// fewer people, or leave it in the clear.
func ParseSettings(kegfile string, getenv func(string) string) (Settings, error) {
	var blk sealBlock
	if src := SealSection(kegfile); src != "" {
		var doc struct {
			Seal sealBlock `yaml:"seal"`
		}
		if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
			return Settings{}, fmt.Errorf("seal: keg file seal section: %w", err)
		}
		blk = doc.Seal
	}

	if v := getenv(EnvRecipients); v != "" {
		blk.Recipients = SplitCSV(v)
	}
	if v := getenv(EnvTopics); v != "" {
		blk.Topics = append(blk.Topics, SplitCSV(v)...)
	}
	if v := getenv(EnvTopicRecipients); v != "" {
		pairs, err := ParseTopicPairs(v)
		if err != nil {
			return Settings{}, err
		}
		blk.TopicRecipients = pairs
	}
	if v := getenv(EnvGPGBin); v != "" {
		blk.GPG.Bin = v
	}
	if v := getenv(EnvGPGHomedir); v != "" {
		blk.GPG.Homedir = v
	}

	return blk.settings()
}

func (b sealBlock) settings() (Settings, error) {
	def, err := ParseRecipients(b.Recipients)
	if err != nil {
		return Settings{}, err
	}
	topicRs := map[string]Recipients{}
	for topic, fps := range b.TopicRecipients {
		topic = strings.TrimSpace(topic)
		if topic == "" {
			return Settings{}, fmt.Errorf("seal: topic-recipients has a blank topic")
		}
		rs, err := ParseRecipients(fps)
		if err != nil {
			return Settings{}, fmt.Errorf("seal: topic %q: %w", topic, err)
		}
		if len(rs) == 0 {
			return Settings{}, fmt.Errorf("seal: topic %q maps to no recipients", topic)
		}
		topicRs[topic] = rs
	}
	topics := map[string]bool{}
	for _, t := range b.Topics {
		if t = strings.TrimSpace(t); t != "" {
			topics[t] = true
		}
	}
	bin := b.GPG.Bin
	if bin == "" {
		bin = "gpg"
	}
	return Settings{
		Policy: Policy{Default: def, TopicRecipients: topicRs, Topics: topics},
		GPG:    GPGOptions{Bin: bin, Homedir: b.GPG.Homedir, ShowRecipients: b.ShowRecipients},
	}, nil
}

// SealSection returns the top-level `seal:` block of a keg info file,
// or "" when there is none. Only that block is handed to the YAML
// parser, so the rest of the (simplified YAML) file cannot break it.
func SealSection(kegfile string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(kegfile, "\n") {
		top := line != "" && line[0] != ' ' && line[0] != '\t' && line[0] != '#'
		switch {
		case top && strings.HasPrefix(line, "seal:"):
			in = true
		case top:
			in = false
		}
		if in {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

// SplitCSV splits on commas and drops blank fields.
func SplitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ParseTopicPairs parses "topic=FPR,topic=FPR"; a topic may repeat to
// add recipients.
func ParseTopicPairs(s string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, pair := range SplitCSV(s) {
		t, fp, ok := strings.Cut(pair, "=")
		t, fp = strings.TrimSpace(t), strings.TrimSpace(fp)
		if !ok || t == "" || fp == "" {
			return nil, fmt.Errorf("seal: %s entries must be topic=<fingerprint>: %q", EnvTopicRecipients, pair)
		}
		out[t] = append(out[t], fp)
	}
	return out, nil
}
