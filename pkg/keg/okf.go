// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package keg

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/BuddhiLW/keg/pkg/okf"
	"github.com/BuddhiLW/keg/pkg/seal"
	"github.com/rwxrob/fs/file"
)

// OKF concept types a keg writes by default.
const (
	OKFNodeType = `Note`
	OKFDexType  = `KEG Index`
)

// EnvOKFActor overrides the generated.by actor of completed nodes.
const EnvOKFActor = `KEG_OKF_ACTOR`

var nodeReadmeExp = regexp.MustCompile(`^(\d+)/README\.md$`)

// OKFSettings are the values a keg writes for the OKF keys a document
// lacks.
type OKFSettings struct {
	NodeType string
	DexType  string
	Actor    string
}

// OKFSnapshot is a keg as OKF sees it: every markdown file, the dex,
// and the tags each node carries.
type OKFSnapshot struct {
	Files []okf.File
	Dex   Dex
	Tags  TagsMap
}

// OKFWrite is one file a plan replaces, and the keys it adds.
type OKFWrite struct {
	Path    string
	Content string
	Added   []string
}

// OKFSkip is one file a plan leaves alone, and why.
type OKFSkip struct {
	Path   string
	Reason string
}

// OKFPlan is the work that makes a keg an OKF bundle.
type OKFPlan struct {
	Writes []OKFWrite
	Skips  []OKFSkip
}

// FileWriter replaces whole files by keg-relative path.
type FileWriter interface {
	WriteFile(name string, data []byte) error
}

// DirWriter writes files below a keg directory.
type DirWriter string

func (d DirWriter) WriteFile(name string, data []byte) error {
	return file.Overwrite(filepath.Join(string(d), filepath.FromSlash(name)), string(data))
}

// ------------------------------ collect -----------------------------

// CollectOKF reads the markdown, the dex and the tags of the keg kegfs.
// A keg without a dex or tags yields an empty one.
func CollectOKF(kegfs fs.FS) (OKFSnapshot, error) {
	var snap OKFSnapshot
	files, err := okf.Survey(kegfs)
	if err != nil {
		return snap, err
	}
	snap.Files = files
	if buf, err := fs.ReadFile(kegfs, `dex/changes.md`); err == nil {
		if d, err := ParseDex(buf); err == nil {
			snap.Dex = *d
		}
	}
	snap.Tags = TagsMap{}
	if buf, err := fs.ReadFile(kegfs, `dex/tags`); err == nil {
		if err := snap.Tags.UnmarshalText(buf); err != nil {
			return snap, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return snap, err
	}
	return snap, nil
}

// OKFSettingsFor returns the default settings, the actor taken from
// KEG_OKF_ACTOR or else the login name as a human actor.
func OKFSettingsFor(getenv func(string) string, login string) OKFSettings {
	actor := getenv(EnvOKFActor)
	if actor == "" && login != "" {
		actor = `human:` + login
	}
	return OKFSettings{NodeType: OKFNodeType, DexType: OKFDexType, Actor: actor}
}

func loginName() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// ------------------------------ promote -----------------------------

// nodeID returns the node a keg-relative path is the README.md of.
func nodeID(p string) (int, bool) {
	m := nodeReadmeExp.FindStringSubmatch(p)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func isDexDoc(p string) bool { return path.Dir(p) == `dex` }

func reserved(p string) bool {
	b := path.Base(p)
	return b == okf.IndexFile || b == okf.LogFile
}

// firstHeading is the text of the first level-one heading of a body.
func firstHeading(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if t, ok := strings.CutPrefix(line, `# `); ok {
			return strings.TrimSpace(t)
		}
	}
	return ""
}

// defaultsFor returns what Complete writes into the document at p.
func defaultsFor(f okf.File, snap OKFSnapshot, set OKFSettings) okf.Defaults {
	if isDexDoc(f.Path) {
		return okf.Defaults{Type: set.DexType}
	}
	_, body, _ := okf.Split(f.Content)
	d := okf.Defaults{Type: set.NodeType, Title: firstHeading(body), Actor: set.Actor}
	if id, ok := nodeID(f.Path); ok {
		d.Tags = tagsOf(snap.Tags, strconv.Itoa(id))
		if e := snap.Dex.Lookup(id); e != nil {
			d.At = e.U
		}
	}
	return d
}

// PlanOKFFix returns the writes that give every document of the keg the
// OKF keys it lacks. Sealed nodes and unreadable front matter are
// skipped, never guessed at.
func PlanOKFFix(snap OKFSnapshot, set OKFSettings) OKFPlan {
	var plan OKFPlan
	for _, f := range snap.Files {
		if reserved(f.Path) {
			continue
		}
		if seal.IsSealed([]byte(f.Content)) {
			plan.Skips = append(plan.Skips, OKFSkip{f.Path, `sealed`})
			continue
		}
		out, added, err := okf.Complete(f.Content, defaultsFor(f, snap, set))
		if err != nil {
			plan.Skips = append(plan.Skips, OKFSkip{f.Path, err.Error()})
			continue
		}
		if len(added) > 0 {
			plan.Writes = append(plan.Writes, OKFWrite{f.Path, out, added})
		}
	}
	return plan
}

// description is the front matter description of a document, or "".
func description(content string) string {
	block, _, ok := okf.Split(content)
	if !ok {
		return ""
	}
	m, err := okf.Fields(block)
	if err != nil {
		return ""
	}
	s, _ := m[`description`].(string)
	return s
}

// PlanOKFIndex returns the bundle-root index.md listing every node and
// the log.md of its changes, both from the dex. Titles come from the
// dex, so a sealed node shows its hint and nothing more.
func PlanOKFIndex(snap OKFSnapshot, title string) []OKFWrite {
	content := map[int]string{}
	for _, f := range snap.Files {
		if id, ok := nodeID(f.Path); ok && !seal.IsSealed([]byte(f.Content)) {
			content[id] = f.Content
		}
	}
	byID := append(Dex(nil), snap.Dex...).ByID()
	items := make([]okf.Item, 0, len(byID))
	changes := make([]okf.Change, 0, len(byID))
	for _, e := range byID {
		link := e.ID() + `/README.md`
		items = append(items, okf.Item{Title: e.T, Link: link, Description: description(content[e.N])})
		changes = append(changes, okf.Change{At: e.U, Kind: `Update`, Title: e.T, Link: `/` + link})
	}
	return []OKFWrite{
		{Path: okf.IndexFile, Content: okf.RenderIndex(okf.Version, title, items)},
		{Path: okf.LogFile, Content: okf.RenderLog(title+` update log`, changes)},
	}
}

// OKFProblems returns the conformance problems of the keg, sealed nodes
// named as such.
func OKFProblems(snap OKFSnapshot) []okf.Problem {
	ps := okf.Check(snap.Files)
	sealed := map[string]bool{}
	for _, f := range snap.Files {
		sealed[f.Path] = seal.IsSealed([]byte(f.Content))
	}
	for i, p := range ps {
		if sealed[p.Path] {
			ps[i].Kind = `sealed node: ` + p.Kind
		}
	}
	return ps
}

// OKFEnabled reports whether the keg is an OKF bundle: its root
// index.md declares an okf_version.
func OKFEnabled(snap OKFSnapshot) bool {
	for _, f := range snap.Files {
		if f.Path == okf.IndexFile {
			block, _, ok := okf.Split(f.Content)
			if !ok {
				return false
			}
			m, err := okf.Fields(block)
			return err == nil && m[`okf_version`] != nil
		}
	}
	return false
}

// PlanOKFSync is the upkeep of an OKF keg after a change to the nodes
// ids: those nodes completed, the index and log rewritten.
func PlanOKFSync(snap OKFSnapshot, set OKFSettings, title string, ids ...int) []OKFWrite {
	want := map[int]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var ws []OKFWrite
	for _, w := range PlanOKFFix(snap, set).Writes {
		if id, ok := nodeID(w.Path); (ok && want[id]) || isDexDoc(w.Path) {
			ws = append(ws, w)
		}
	}
	return append(ws, PlanOKFIndex(snap, title)...)
}

// ------------------------------ boundary ----------------------------

// ApplyOKF performs the writes in order.
func ApplyOKF(w FileWriter, ws []OKFWrite) error {
	for _, x := range ws {
		if err := w.WriteFile(x.Path, []byte(x.Content)); err != nil {
			return fmt.Errorf("okf: %s: %w", x.Path, err)
		}
	}
	return nil
}

// frontMatterOf returns the front matter block heading the file at
// path, delimiters included, or "" when it has none.
func frontMatterOf(path string) string {
	buf, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _, ok := okf.Split(string(buf))
	if !ok {
		return ""
	}
	return okf.Join(block, "")
}

// kegTitle is the title of the keg info file, or the keg directory name.
func kegTitle(kegpath string) string {
	if buf, err := os.ReadFile(filepath.Join(kegpath, `keg`)); err == nil {
		for _, line := range strings.Split(string(buf), "\n") {
			if t, ok := strings.CutPrefix(line, `title:`); ok && strings.TrimSpace(t) != "" {
				return strings.TrimSpace(t)
			}
		}
	}
	return filepath.Base(kegpath)
}

// SyncOKF keeps an OKF keg conformant after a change to the nodes ids.
// A keg that has not opted in (no okf_version index) is left alone.
func SyncOKF(kegpath string, ids ...int) error {
	snap, err := CollectOKF(os.DirFS(kegpath))
	if err != nil || !OKFEnabled(snap) {
		return err
	}
	set := OKFSettingsFor(os.Getenv, loginName())
	return ApplyOKF(DirWriter(kegpath), PlanOKFSync(snap, set, kegTitle(kegpath), ids...))
}
