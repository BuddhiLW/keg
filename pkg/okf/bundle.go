// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package okf

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Reserved file names, never concepts (SPEC §3.1).
const (
	IndexFile = "index.md"
	LogFile   = "log.md"
)

// Item is one entry of an index.md listing.
type Item struct {
	Title       string
	Link        string
	Description string
}

// RenderIndex renders an index.md with one section. A non-empty version
// adds the okf_version front matter only a bundle-root index may carry.
func RenderIndex(version, heading string, items []Item) string {
	var b strings.Builder
	if version != "" {
		b.WriteString(Join(fmt.Sprintf("okf_version: %q\n", version), "\n"))
	}
	b.WriteString("# " + heading + "\n\n")
	for _, it := range items {
		b.WriteString("* [" + it.Title + "](" + it.Link + ")")
		if d := oneLine(it.Description); d != "" {
			b.WriteString(" - " + d)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// Change is one log.md entry.
type Change struct {
	At    time.Time
	Kind  string // leading bold word, e.g. Update
	Title string
	Link  string
}

// RenderLog renders a log.md: entries grouped under YYYY-MM-DD
// headings, newest first.
func RenderLog(heading string, changes []Change) string {
	cs := append([]Change(nil), changes...)
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].At.After(cs[j].At) })
	var b strings.Builder
	b.WriteString("# " + heading + "\n")
	day := ""
	for _, c := range cs {
		if d := c.At.UTC().Format(time.DateOnly); d != day {
			day = d
			b.WriteString("\n## " + d + "\n")
		}
		b.WriteString("* **" + c.Kind + "**: [" + c.Title + "](" + c.Link + ")\n")
	}
	return b.String()
}

// Problem is one conformance failure of a bundle file.
type Problem struct {
	Path string
	Kind string
}

func (p Problem) String() string { return p.Path + ": " + p.Kind }

var logDateExp = regexp.MustCompile(`^## \d{4}-\d{2}-\d{2}\s*$`)

// Problem kinds for reserved files.
const (
	IndexFrontMatter = "index front matter other than okf_version at the bundle root"
	LogBadDate       = "log heading is not a YYYY-MM-DD date"
)

// CheckIndex returns the problem of an index.md, or "" when it conforms.
func CheckIndex(content string, root bool) string {
	block, _, ok := Split(content)
	if !ok {
		return ""
	}
	m, err := Fields(block)
	if err != nil {
		return BadYAML
	}
	_, versioned := m["okf_version"]
	if !root || len(m) != 1 || !versioned {
		return IndexFrontMatter
	}
	return ""
}

// CheckLog returns the problem of a log.md, or "" when it conforms.
func CheckLog(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "## ") && !logDateExp.MatchString(line) {
			return LogBadDate
		}
	}
	return ""
}

// Skip reports whether a bundle walk passes over a path: hidden files
// and directories are not part of a bundle.
func Skip(name string) bool {
	return strings.HasPrefix(name, ".") && name != "."
}

// File is one markdown file of a bundle, by bundle-relative path.
type File struct {
	Path    string
	Content string
}

// Survey collects every markdown file of a bundle, hidden paths aside.
func Survey(bundle fs.FS) ([]File, error) {
	var files []File
	err := fs.WalkDir(bundle, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if Skip(d.Name()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || path.Ext(p) != ".md" {
			return nil
		}
		buf, err := fs.ReadFile(bundle, p)
		if err != nil {
			return err
		}
		files = append(files, File{Path: p, Content: string(buf)})
		return nil
	})
	return files, err
}

// CheckFile returns the conformance problem of one bundle file, by the
// role its name gives it, or "" when it conforms.
func CheckFile(f File) string {
	switch path.Base(f.Path) {
	case IndexFile:
		return CheckIndex(f.Content, path.Dir(f.Path) == ".")
	case LogFile:
		return CheckLog(f.Content)
	default:
		return CheckConcept(f.Content)
	}
}

// Check returns every conformance problem of a bundle (SPEC §11).
func Check(files []File) []Problem {
	var ps []Problem
	for _, f := range files {
		if kind := CheckFile(f); kind != "" {
			ps = append(ps, Problem{Path: f.Path, Kind: kind})
		}
	}
	return ps
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
