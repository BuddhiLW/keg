// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package keg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BuddhiLW/keg/pkg/kegml"
	"github.com/BuddhiLW/keg/pkg/seal"
	_fs "github.com/rwxrob/fs"
)

// SealedTitle is the index title of a sealed node that has no hint.
const SealedTitle = `🔒 sealed`

var ErrMustStaySealed = errors.New("keg: node carries a sealed tag and may not be stored in the clear")

// Editor opens path for the human to edit. file.Edit in production.
type Editor func(path string) error

// EditResult says what an edit of a sealed node did.
type EditResult int

const (
	Unchanged EditResult = iota
	Changed
	Emptied
)

// ------------------------------ collect -----------------------------

func readmePath(kegpath, id string) string {
	return filepath.Join(kegpath, id, `README.md`)
}

// SealSettings reads the seal section of the keg info file, then the
// KEG_SEAL_* environment.
func SealSettings(kegpath string) (seal.Settings, error) {
	buf, err := os.ReadFile(filepath.Join(kegpath, `keg`))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return seal.Settings{}, err
	}
	return seal.ParseSettings(string(buf), os.Getenv)
}

// NewSealer returns the gpg-backed Sealer configured for the keg.
func NewSealer(kegpath string) (seal.Sealer, error) {
	s, err := SealSettings(kegpath)
	if err != nil {
		return seal.Sealer{}, err
	}
	return seal.Sealer{Cipher: seal.NewGPG(s.GPG), Policy: s.Policy}, nil
}

func readTagsOrEmpty(kegpath string) (TagsMap, error) {
	tmap, err := ReadTags(kegpath)
	if errors.Is(err, os.ErrNotExist) {
		return TagsMap{}, nil
	}
	return tmap, err
}

// NodeTags returns the tags dex/tags assigns to node id.
func NodeTags(kegpath, id string) ([]string, error) {
	tmap, err := readTagsOrEmpty(kegpath)
	if err != nil {
		return nil, err
	}
	return tagsOf(tmap, id), nil
}

// ------------------------------ promote -----------------------------

func tagsOf(tmap TagsMap, id string) []string {
	var tags []string
	for tag, ids := range tmap {
		for _, i := range ids {
			if i == id {
				tags = append(tags, tag)
				break
			}
		}
	}
	sort.Strings(tags)
	return tags
}

// sealedTitle is the public title of sealed content: its hint, never
// its plaintext. ok is false for content that is not sealed.
func sealedTitle(content []byte) (title string, ok bool) {
	env, ok := seal.Parse(string(content))
	if !ok {
		return "", false
	}
	if env.Hint != "" {
		return env.Hint, true
	}
	return SealedTitle, true
}

// violations returns the ids the policy requires sealed that are not.
func violations(p seal.Policy, tmap TagsMap, exists, sealed func(id string) bool) []string {
	seen := map[string]bool{}
	var ids []string
	for _, nodes := range tmap {
		for _, id := range nodes {
			if seen[id] {
				continue
			}
			seen[id] = true
			if exists(id) && p.MustSeal(tagsOf(tmap, id)) && !sealed(id) {
				ids = append(ids, id)
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, _ := strconv.Atoi(ids[i])
		b, _ := strconv.Atoi(ids[j])
		return a < b
	})
	return ids
}

// describeRecipients renders a recipient set, one fingerprint a line.
func describeRecipients(rs seal.Recipients) string {
	if len(rs) == 0 {
		return "  recipients: gpg default (your own key)\n"
	}
	var b strings.Builder
	b.WriteString("  recipients:\n")
	for _, r := range rs {
		b.WriteString("    " + string(r) + "\n")
	}
	return b.String()
}

// describePolicy renders the keg's sealing policy for humans.
func describePolicy(st seal.Settings) string {
	var b strings.Builder
	b.WriteString("default\n")
	b.WriteString(describeRecipients(st.Policy.Default))
	topics := make([]string, 0, len(st.Policy.TopicRecipients))
	for t := range st.Policy.TopicRecipients {
		topics = append(topics, t)
	}
	sort.Strings(topics)
	for _, t := range topics {
		b.WriteString("tag " + t + " (own compartment)\n")
		b.WriteString(describeRecipients(st.Policy.TopicRecipients[t]))
	}
	if sealed := st.Policy.SealedTopics(); len(sealed) > 0 {
		b.WriteString("must stay sealed: " + strings.Join(sealed, " ") + "\n")
	}
	return b.String()
}

// ------------------------------ boundary ----------------------------

// NodeTitle reads the index title of a node README.md (or its
// directory). A sealed node answers with its hint and is never opened.
func NodeTitle(path string) (string, error) {
	if !strings.HasSuffix(path, `README.md`) {
		path = filepath.Join(path, `README.md`)
	}
	if buf, err := os.ReadFile(path); err == nil {
		if t, ok := sealedTitle(buf); ok {
			return t, nil
		}
	}
	return kegml.ReadTitle(path)
}

// IsSealedNode reports whether node id is stored sealed.
func IsSealedNode(kegpath, id string) bool {
	buf, err := os.ReadFile(readmePath(kegpath, id))
	return err == nil && seal.IsSealed(buf)
}

// SealNode encrypts node id in place to the recipients its tags select.
func SealNode(s seal.Sealer, kegpath, id, hint string) error {
	path := readmePath(kegpath, id)
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tags, err := NodeTags(kegpath, id)
	if err != nil {
		return err
	}
	out, err := s.Seal(buf, hint, tags)
	if err != nil {
		return err
	}
	return writeAtomic(path, []byte(out))
}

// UnsealNode stores node id in the clear again. A node whose tags the
// policy seals is refused.
func UnsealNode(s seal.Sealer, kegpath, id string) error {
	tags, err := NodeTags(kegpath, id)
	if err != nil {
		return err
	}
	if s.Policy.MustSeal(tags) {
		return ErrMustStaySealed
	}
	plain, err := OpenNode(s, kegpath, id)
	if err != nil {
		return err
	}
	return writeAtomic(readmePath(kegpath, id), plain)
}

// RekeyNode re-encrypts a sealed node to the recipients its tags select
// now: how a key is added to, or removed from, a node.
func RekeyNode(s seal.Sealer, kegpath, id string) error {
	path := readmePath(kegpath, id)
	buf, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tags, err := NodeTags(kegpath, id)
	if err != nil {
		return err
	}
	out, err := s.Reseal(buf, tags)
	if err != nil {
		return err
	}
	return writeAtomic(path, []byte(out))
}

// OpenNode returns the plaintext of sealed node id, in memory only.
func OpenNode(s seal.Sealer, kegpath, id string) ([]byte, error) {
	buf, err := os.ReadFile(readmePath(kegpath, id))
	if err != nil {
		return nil, err
	}
	plain, _, err := s.Open(buf)
	return plain, err
}

// EditSealedNode opens sealed node id in edit through a private
// plaintext copy outside the keg, then seals the result back. The copy
// is wiped whatever happens.
func EditSealedNode(s seal.Sealer, kegpath, id string, edit Editor) (EditResult, error) {
	path := readmePath(kegpath, id)
	buf, err := os.ReadFile(path)
	if err != nil {
		return Unchanged, err
	}
	plain, env, err := s.Open(buf)
	if err != nil {
		return Unchanged, err
	}
	after, err := editPrivately(id, plain, edit)
	if err != nil {
		return Unchanged, err
	}
	switch {
	case bytes.Equal(after, plain):
		return Unchanged, nil
	case len(bytes.TrimSpace(after)) == 0:
		return Emptied, nil
	}
	tags, err := NodeTags(kegpath, id)
	if err != nil {
		return Unchanged, err
	}
	out, err := s.Seal(after, env.Hint, tags)
	if err != nil {
		return Unchanged, err
	}
	return Changed, writeAtomic(path, []byte(out))
}

// CreateSealedNode fills the new node entry through a private
// plaintext copy and stores only the sealed result. An empty edit
// removes the node directory and reports false.
func CreateSealedNode(s seal.Sealer, kegpath string, entry *DexEntry, hint string, edit Editor) (bool, error) {
	after, err := editPrivately(entry.ID(), nil, edit)
	if err != nil {
		return false, err
	}
	if len(bytes.TrimSpace(after)) == 0 {
		return false, os.RemoveAll(filepath.Join(kegpath, entry.ID()))
	}
	tags, err := NodeTags(kegpath, entry.ID())
	if err != nil {
		return false, err
	}
	out, err := s.Seal(after, hint, tags)
	if err != nil {
		return false, err
	}
	return true, writeAtomic(readmePath(kegpath, entry.ID()), []byte(out))
}

// CheckSealed returns the ids of nodes the policy requires sealed that
// are stored in the clear.
func CheckSealed(kegpath string, p seal.Policy) ([]string, error) {
	if len(p.SealedTopics()) == 0 {
		return nil, nil
	}
	tmap, err := readTagsOrEmpty(kegpath)
	if err != nil {
		return nil, err
	}
	exists := func(id string) bool { return _fs.Exists(readmePath(kegpath, id)) }
	sealed := func(id string) bool { return IsSealedNode(kegpath, id) }
	return violations(p, tmap, exists, sealed), nil
}

// GuardSealed fails when publishing would put a must-seal node in git
// in the clear.
func GuardSealed(kegpath string) error {
	st, err := SealSettings(kegpath)
	if err != nil {
		return err
	}
	ids, err := CheckSealed(kegpath, st.Policy)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		return fmt.Errorf(_MustBeSealed, strings.Join(ids, " "))
	}
	return nil
}

const _MustBeSealed = "refusing to publish: node(s) %v carry a sealed tag but are stored in the clear (run `keg seal ID`)"

// editPrivately writes plain to a 0600 file in a fresh 0700 directory
// under $XDG_RUNTIME_DIR (else the temp dir), lets edit change it, and
// returns the result after zeroing and removing the copy.
func editPrivately(id string, plain []byte, edit Editor) ([]byte, error) {
	base := os.Getenv(`XDG_RUNTIME_DIR`)
	if base == "" {
		base = os.TempDir()
	}
	dir, err := os.MkdirTemp(base, `keg-sealed-`)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, id+`.md`)
	defer wipe(dir, path)
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, plain, 0o600); err != nil {
		return nil, err
	}
	if err := edit(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func wipe(dir, path string) {
	if fi, err := os.Stat(path); err == nil {
		os.WriteFile(path, make([]byte, fi.Size()), 0o600)
	}
	os.RemoveAll(dir)
}

// writeAtomic replaces path through a sibling temp file and a rename,
// so a failure never leaves a half-written node.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), `.keg-seal-*`)
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
