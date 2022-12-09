// Copyright 2022 Robert Muhlestein.
// SPDX-License-Identifier: Apache-2.0

package keg

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/charmbracelet/glamour"
	Z "github.com/rwxrob/bonzai/z"
	"github.com/rwxrob/choose"
	"github.com/rwxrob/conf"
	"github.com/rwxrob/fs"
	"github.com/rwxrob/fs/dir"
	"github.com/rwxrob/fs/file"
	"github.com/rwxrob/grep"
	"github.com/rwxrob/help"
	"github.com/rwxrob/term"
	"github.com/rwxrob/to"
	"github.com/rwxrob/vars"
)

func init() {
	Z.Conf.SoftInit()
	Z.Vars.SoftInit()
}

var DefColumns = 100

// has to stay here because needs vars package from x
func current(x *Z.Cmd) (*Local, error) {
	var name, dir string

	// if we have an env it beats config settings
	name = os.Getenv(`KEG_CURRENT`)
	if name != "" {
		dir, _ = x.C(`map.` + name)
		if !(dir == "" || dir == "null") {

			dir = fs.Tilde2Home(dir)
			if fs.NotExists(dir) {
				return nil, fs.ErrNotExist{dir}
			}
			docsdir := filepath.Join(dir, `docs`)
			if fs.Exists(docsdir) {
				dir = docsdir
			}
			return &Local{Path: dir, Name: name}, nil
		}
	}

	// check if current working directory has a keg
	dir, _ = os.Getwd()
	if fs.Exists(filepath.Join(dir, `keg`)) {
		name = filepath.Base(dir)
		if name == `docs` {
			name = filepath.Base(filepath.Dir(dir))
		}
		return &Local{Path: dir, Name: name}, nil
	}

	// check if current working directory has a docs/keg
	dir, _ = os.Getwd()
	if fs.Exists(filepath.Join(dir, `docs`, `keg`)) {
		name = filepath.Base(dir)
		dir = filepath.Join(dir, `docs`)
		return &Local{Path: dir, Name: name}, nil
	}

	// check vars and conf
	name, _ = x.Get(`current`)
	if name != "" {
		dir, _ = x.C(`map.` + name)
		if !(dir == "" || dir == "null") {
			dir = fs.Tilde2Home(dir)
			return &Local{Path: dir, Name: name}, nil
		}
	}

	return nil, fmt.Errorf("no kegs found") // FIXME with better error
}

//go:embed desc/help.md
var helpDoc string

var Cmd = &Z.Cmd{
	Name:        `keg`,
	Aliases:     []string{`kn`},
	Summary:     `create and manage knowledge exchange graphs`,
	Version:     `v0.8.1`,
	UseVars:     true,
	Copyright:   `Copyright 2022 Robert S Muhlestein`,
	License:     `Apache-2.0`,
	Site:        `rwxrob.tv`,
	Source:      `git@github.com:rwxrob/keg.git`,
	Issues:      `github.com/rwxrob/keg/issues`,
	ConfVars:    true,
	Description: helpDoc,

	Commands: []*Z.Cmd{
		editCmd, help.Cmd, conf.Cmd, vars.Cmd,
		indexCmd, createCmd, currentCmd, directoryCmd, deleteCmd,
		lastCmd, changesCmd, titlesCmd, initCmd, randomCmd,
		importCmd, grepCmd, viewCmd, columnsCmd,
	},

	Shortcuts: Z.ArgMap{
		`set`:    {`var`, `set`},
		`get`:    {`var`, `get`},
		`sample`: {`create`, `sample`},
	},
}

//go:embed desc/current.md
var currentDoc string

var currentCmd = &Z.Cmd{
	Name:        `current`,
	Summary:     `show the current keg`,
	Commands:    []*Z.Cmd{help.Cmd},
	Description: currentDoc,

	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		term.Print(keg.Name)

		return nil
	},
}

//go:embed desc/titles.md
var titlesDoc string

var titlesCmd = &Z.Cmd{
	Name:        `titles`,
	Aliases:     []string{`title`},
	Usage:       `(help|REGEXP)`,
	Summary:     `find titles containing regular expression`,
	UseVars:     true,
	Description: titlesDoc,
	Commands:    []*Z.Cmd{help.Cmd, vars.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		if len(args) == 0 {
			args = append(args, "")
		}

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		var dex *Dex
		dex, err = ReadDex(keg.Path)
		if err != nil {
			return err
		}

		pre, err := x.Caller.Get(`regxpre`)
		if err != nil {
			return err
		}
		if pre == "" {
			pre = `(?i)`
		}

		re, err := regexp.Compile(pre + args[0])
		if err != nil {
			return err
		}

		if term.IsInteractive() {
			Z.Page(dex.WithTitleTextExp(re).Pretty())
			return nil
		}

		fmt.Print(dex.WithTitleTextExp(re).AsIncludes())
		return nil
	},
}

var directoryCmd = &Z.Cmd{
	Name:     `directory`,
	Aliases:  []string{`d`, `dir`},
	MaxArgs:  1,
	Summary:  `print path to directory of current keg or node`,
	Commands: []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		if len(args) > 0 {
			dex, _ := ReadDex(keg.Path)
			choice := dex.ChooseWithTitleText(strings.Join(args, " "))
			term.Print(filepath.Join(keg.Path, strconv.Itoa(choice.N)))
			return nil
		}

		term.Print(keg.Path)

		return nil
	},
}

//go:embed desc/delete.md
var deleteDoc string

var deleteCmd = &Z.Cmd{
	Name:        `delete`,
	Summary:     `delete node from current keg`,
	MinArgs:     1,
	Aliases:     []string{`del`, `rm`},
	Usage:       `(help|INTEGER_NODE_ID|last|same)`,
	Description: deleteDoc,
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		id := args[0]
		var entry *DexEntry

		switch {

		case id == "same":

			if entry = LastChanged(keg.Path); entry != nil {
				id = entry.ID()
			}

		case id == "last":

			if entry = Last(keg.Path); entry != nil {
				id = entry.ID()
			}

		default:

			var idn int
			if idn, err = strconv.Atoi(id); err != nil {
				return x.UsageError()
			}

			dex, err := ReadDex(keg.Path)
			if err != nil {
				return err
			}

			entry = dex.Lookup(idn)
			if entry == nil {
				return fmt.Errorf("node not found: %v", idn)
			}
			id = entry.ID()
		}

		dir := filepath.Join(keg.Path, id)
		log.Println("deleting", dir)

		if err := os.RemoveAll(dir); err != nil {
			return err
		}

		if err := DexRemove(keg.Path, entry); err != nil {
			return err
		}
		return Publish(keg.Path)

	},
}

//go:embed desc/indexdoc.md
var indexDoc string

var indexCmd = &Z.Cmd{
	Name:        `index`,
	Aliases:     []string{`dex`},
	Commands:    []*Z.Cmd{help.Cmd, dexUpdateCmd},
	Summary:     `work with indexes`,
	Description: indexDoc,
}

//go:embed desc/dexupdate.md
var dexUpdateDoc string

var dexUpdateCmd = &Z.Cmd{
	Name:        `update`,
	Commands:    []*Z.Cmd{help.Cmd},
	Summary:     `update dex/changes.md and dex/nodes.tsv`,
	Description: dexUpdateDoc,
	Call: func(x *Z.Cmd, args ...string) error {
		keg, err := current(x.Caller.Caller) // keg dex update
		if err != nil {
			return err
		}
		return MakeDex(keg.Path)
	},
}

//go:embed desc/last.md
var lastDoc string

var lastCmd = &Z.Cmd{
	Name:        `last`,
	Usage:       `[help|dir|id|title|time]`,
	Params:      []string{`dir`, `id`, `title`, `time`},
	MaxArgs:     1,
	Summary:     `show last created node`,
	Description: lastDoc,
	Commands:    []*Z.Cmd{help.Cmd},
	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		last := Last(keg.Path)

		if len(args) == 0 {
			if term.IsInteractive() {
				fmt.Print(last.Pretty())
			} else {
				fmt.Print(last.MD())
			}
			return nil
		}

		switch args[0] {
		case `dir`:
			term.Print(filepath.Join(keg.Path, last.ID()))
		case `time`:
			term.Print(last.U.Format(IsoDateFmt))
		case `title`:
			term.Print(last.T)
		case `id`:
			term.Print(last.ID())
		}

		return nil
	},
}

//go:embed desc/changescmd.md
var changesDoc string

var ChangesDefault = 5

var changesCmd = &Z.Cmd{
	Name:        `changes`,
	Aliases:     []string{`changed`},
	Usage:       `[help|COUNT|default|set default COUNT]`,
	Summary:     `show most recent n nodes changed`,
	UseVars:     true,
	Description: changesDoc,
	Commands:    []*Z.Cmd{help.Cmd, vars.Cmd},
	Dynamic: template.FuncMap{
		`changesdef`: func() int { return ChangesDefault },
	},

	Shortcuts: Z.ArgMap{
		`default`: {`var`, `get`, `default`},
		`set`:     {`var`, `set`},
	},

	Call: func(x *Z.Cmd, args ...string) error {
		var err error
		var n int

		if len(args) > 0 {
			n, _ = strconv.Atoi(args[0])
		}

		if n <= 0 {
			def, err := x.Get(`default`)
			if err == nil && def != "" {
				n, err = strconv.Atoi(def)
				if err != nil {
					return err
				}
			}
		}

		if n <= 0 {
			n = ChangesDefault
		}

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		path := filepath.Join(keg.Path, `dex/changes.md`)
		if !fs.Exists(path) {
			return fmt.Errorf("dex/changes.md file does not exist")
		}

		lines, err := file.Head(path, n)
		if err != nil {
			return err
		}

		dex, err := ParseDex(strings.Join(lines, "\n"))
		if err != nil {
			return nil
		}

		if term.IsInteractive() {
			fmt.Print(dex.Pretty())
			return nil
		}

		fmt.Print(dex.AsIncludes())
		return nil
	},
}

//go:embed testdata/samplekeg/keg
var DefaultInfoFile string

//go:embed testdata/samplekeg/0/README.md
var DefaultZeroNode string

//go:embed desc/init.md
var initDoc string

var initCmd = &Z.Cmd{
	Name:        `init`,
	Usage:       `[help]`,
	Summary:     `initialize current working dir as new keg`,
	Description: initDoc,
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(_ *Z.Cmd, _ ...string) error {

		if fs.NotExists(`keg`) {
			if err := file.Overwrite(`keg`, DefaultInfoFile); err != nil {
				return err
			}
		}

		if fs.NotExists(`0/README.md`) {
			if err := file.Overwrite(`0/README.md`, DefaultZeroNode); err != nil {
				return err
			}
		}

		if err := file.Edit(`keg`); err != nil {
			return err
		}

		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		if err := MakeDex(dir); err != nil {
			return err
		}

		return Publish(dir)
	},
}

//go:embed desc/edit.md
var editDoc string

var editCmd = &Z.Cmd{
	Name:        `edit`,
	Aliases:     []string{`e`},
	Params:      []string{`last`, `same`},
	Usage:       `(help|ID|last|same|REGEX)`,
	Summary:     `choose and edit a specific node (default)`,
	Description: editDoc,
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		if len(args) == 0 {
			return help.Cmd.Call(x, args...)
		}

		if !term.IsInteractive() {
			return titlesCmd.Call(x, args...)
		}

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		id := args[0]
		var entry *DexEntry

		switch id {

		case "same":
			if entry = LastChanged(keg.Path); entry != nil {
				id = entry.ID()
			}

		case "last":
			if entry = Last(keg.Path); entry != nil {
				id = entry.ID()
			}

		default:

			dex, err := ReadDex(keg.Path)
			if err != nil {
				return err
			}

			idn, err := strconv.Atoi(id)

			if err == nil {
				entry = dex.Lookup(idn)
			} else {

				pre, err := x.Caller.Get(`regxpre`)
				if err != nil {
					return err
				}
				if pre == "" {
					pre = `(?i)`
				}

				re, err := regexp.Compile(pre + args[0])
				if err != nil {
					return err
				}

				entry = dex.ChooseWithTitleTextExp(re)
				if entry == nil {
					return fmt.Errorf("unable to choose a title")
				}

				id = strconv.Itoa(entry.N)
			}
		}

		path := filepath.Join(keg.Path, id, `README.md`)

		if !fs.Exists(path) {
			return fmt.Errorf("content node (%s) does not exist in %q", id, keg.Name)
		}

		btime := fs.ModTime(path)

		if err := file.Edit(path); err != nil {
			return err
		}

		if file.IsEmpty(path) {
			if err = os.RemoveAll(filepath.Dir(path)); err != nil {
				return err
			}
			if err := DexRemove(keg.Path, entry); err != nil {
				return err
			}
			return Publish(keg.Path)
		} else {
			if err := DexUpdate(keg.Path, entry); err != nil {
				return err
			}
		}

		atime := fs.ModTime(path)
		if atime.After(btime) {
			return Publish(keg.Path)
		}
		return nil

	},
}

var createCmd = &Z.Cmd{
	Name:     `create`,
	Aliases:  []string{`c`},
	Params:   []string{`sample`},
	Summary:  `create and edit content node`,
	MaxArgs:  1,
	Commands: []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		entry, err := MakeNode(keg.Path)
		if err != nil {
			return err
		}

		if len(args) > 0 && args[0] == `sample` {
			if err := WriteSample(keg.Path, entry); err != nil {
				return err
			}
		}

		if err := Edit(keg.Path, entry.N); err != nil {
			return err
		}

		path := filepath.Join(keg.Path, entry.ID(), `README.md`)

		if file.IsEmpty(path) {
			if err = os.RemoveAll(filepath.Dir(path)); err != nil {
				return err
			}
			return nil
		}

		if err := DexUpdate(keg.Path, entry); err != nil {
			return err
		}

		return Publish(keg.Path)
	},
}

//go:embed desc/random.md
var randomDoc string

var randomCmd = &Z.Cmd{
	Name:        `random`,
	Aliases:     []string{`rand`},
	Usage:       `[help|title|id|dir|edit]`,
	Params:      []string{`title`, `id`, `dir`, `edit`},
	MaxArgs:     1,
	Summary:     `return random node, gamify content editing`,
	Description: randomDoc,
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {
		if len(args) == 0 {
			args = append(args, `edit`)
		}
		keg, err := current(x.Caller)
		if err != nil {
			return err
		}
		dex, err := ReadDex(keg.Path)
		r := dex.Random()
		switch args[0] {
		case `id`:
			term.Print(r.N)
		case `title`:
			term.Print(r.T)
		case `edit`:
			return editCmd.Call(x, strconv.Itoa(r.N))
		case `dir`:
			term.Print(filepath.Join(strconv.Itoa(r.N)))
		}
		return nil
	},
}

//go:embed desc/import.md
var importDoc string

var importCmd = &Z.Cmd{
	Name:        `import`,
	Usage:       `[help|(DIR|NODEDIR)...]`,
	Summary:     `import nodes into current keg`,
	Description: importDoc,
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		if len(args) == 0 {
			d := dir.Abs()
			if d == "" {
				return fmt.Errorf("unable to determine absolute path to current directory")
			}
			args = append(args, d)
		}

		if err := Import(keg.Path, args...); err != nil {
			return err
		}

		if err := MakeDex(keg.Path); err != nil {
			return err
		}

		return Publish(keg.Path)

	},
}

// columns first looks for term.WinSize.Col to have been set. If not
// found, the columns variable (from vars) is checked and used if found.
// Finally, the package global DefColumns will be used.
func columns(x *Z.Cmd) int {

	col := int(term.WinSize.Col) // only > 0 for interactive terminals
	if col > 0 {
		return col
	}

	colstr, err := x.Caller.Get(`columns`)
	if err == nil && colstr != "" {
		col, err = strconv.Atoi(colstr)
		if err == nil {
			return col
		}
	}

	return DefColumns

}

//go:embed desc/columns.md
var columnsDoc string

var columnsCmd = &Z.Cmd{
	Name:        `columns`,
	Usage:       `(help|col|cols)`,
	MaxArgs:     1,
	Summary:     `print the number of columns resolved`,
	Description: columnsDoc,
	Commands:    []*Z.Cmd{help.Cmd},
	Dynamic:     template.FuncMap{`columns`: func() int { return DefColumns }},

	Call: func(x *Z.Cmd, args ...string) error {
		term.Print(columns(x))
		return nil
	},
}

type grepChoice struct {
	hit grep.Result
	str string
}

func (c grepChoice) String() string { return c.str }

//go:embed desc/grep.md
var grepDoc string

var grepCmd = &Z.Cmd{
	Name:        `grep`,
	Usage:       `(help|REGEXP)`,
	MinArgs:     1,
	Summary:     `grep regular expression out of all nodes`,
	Description: grepDoc,
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		dirs, _, _ := fs.IntDirs(keg.Path)
		dpaths := []string{}
		for _, d := range dirs {
			dpaths = append(dpaths, filepath.Join(d.Path, `README.md`))
		}

		col := columns(x) - 14
		results, err := grep.This(args[0], col, dpaths...)
		if err != nil {
			return err
		}

		if term.IsInteractive() {

			var choices []grepChoice
			for _, hit := range results.Hits {
				id := filepath.Base(filepath.Dir(hit.File))
				match := to.CrunchSpaceVisible(hit.Text[hit.TextBeg:hit.TextEnd])
				before := to.CrunchSpaceVisible(hit.Text[0:hit.TextBeg])
				after := to.CrunchSpaceVisible(hit.Text[hit.TextEnd:])
				width := len(match) + len(before) + len(after)
				if width > col {
					chop := (width - col) / 2
					lafter := len(after)
					lbefore := len(before)
					switch {
					case lbefore > chop && lafter > chop:
						after = after[:len(after)-chop]
						before = before[chop:]
					case lbefore > chop && lafter < chop:
						before = before[chop-(chop-lafter):]
					case lafter > chop && lbefore < chop:
						after = after[:len(after)-(chop-lbefore)]
					}
				}
				out := before + term.Red + match + term.X + after
				choices = append(choices, grepChoice{
					hit: hit,
					str: fmt.Sprintf("%v%6v%v %v", term.Green, id, term.X, out),
				})
			}
			i, c, err := choose.From(choices)
			if err != nil {
				return err
			}
			if i > 0 {
				id := filepath.Base(filepath.Dir(c.hit.File))
				return editCmd.Call(x, id)
			}
			return nil
		}

		dex, err := ReadDex(keg.Path)
		if err != nil {
			return err
		}
		var lastid int
		for _, hit := range results.Hits {
			id, err := strconv.Atoi(filepath.Base(filepath.Dir(hit.File)))
			if err != nil {
				return err
			}
			if id == lastid {
				continue
			}
			lastid = id
			fmt.Println(dex.Lookup(id).AsInclude())
		}
		return nil
	},
}

//go:embed testdata/keg-dark.json
var dark []byte

//go:embed testdata/keg-notty.json
var notty []byte

//go:embed desc/view.md
var viewDoc string

var viewCmd = &Z.Cmd{
	Name:        `view`,
	Summary:     `view a specific node`,
	Usage:       `(help|ID|REGEXP)`,
	Description: viewDoc,
	Params:      []string{`last`, `same`},
	MinArgs:     1,
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {

		keg, err := current(x.Caller)
		if err != nil {
			return err
		}

		id := args[0]

		switch id {

		case "same":
			if n := LastChanged(keg.Path); n != nil {
				id = n.ID()
			}

		case "last":
			if n := Last(keg.Path); n != nil {
				id = n.ID()
			}

		default:
			_, err := strconv.Atoi(id)

			if err != nil {

				dex, err := ReadDex(keg.Path)
				if err != nil {
					return err
				}

				pre, err := x.Caller.Get(`regxpre`)
				if err != nil {
					return err
				}
				if pre == "" {
					pre = `(?i)`
				}

				re, err := regexp.Compile(pre + args[0])
				if err != nil {
					return err
				}

				choice := dex.ChooseWithTitleTextExp(re)
				if choice == nil {
					return fmt.Errorf("unable to choose a title")
				}

				id = strconv.Itoa(choice.N)
			}
		}

		path := filepath.Join(keg.Path, id, `README.md`)

		if !fs.Exists(path) {
			return fmt.Errorf("content node (%s) does not exist in %q", id, keg.Name)
		}

		buf, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var r *glamour.TermRenderer
		if !term.IsInteractive() {
			r, err = glamour.NewTermRenderer(
				glamour.WithWordWrap(-1),
				glamour.WithStylesFromJSONBytes(notty),
			)
			if err != nil {
				return err
			}
			out, err := r.Render(string(buf))
			if err != nil {
				return err
			}
			fmt.Print(out)
			return nil
		}

		glamenv := os.Getenv(`GLAMOUR_STYLE`)
		if glamenv != "" {
			r, err = glamour.NewTermRenderer(
				glamour.WithEnvironmentConfig(),
				glamour.WithWordWrap(-1),
			)
			if err != nil {
				return err
			}
		} else {
			r, err = glamour.NewTermRenderer(
				glamour.WithStylesFromJSONBytes(dark),
				glamour.WithWordWrap(-1),
			)
			if err != nil {
				return err
			}
		}

		out, err := r.Render(string(buf))
		if err != nil {
			return err
		}
		Z.Page(out)

		return nil
	},
}
