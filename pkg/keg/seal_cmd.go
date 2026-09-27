// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package keg

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	Z "github.com/rwxrob/bonzai/z"
	_fs "github.com/rwxrob/fs"
	"github.com/rwxrob/fs/file"
	"github.com/rwxrob/help"
	"github.com/rwxrob/term"
)

//go:embed text/en/seal.md
var _seal string

//go:embed text/en/seal-check.md
var _seal_check string

//go:embed text/en/seal-rekey.md
var _seal_rekey string

//go:embed text/en/seal-who.md
var _seal_who string

//go:embed text/en/unseal.md
var _unseal string

var sealCmd = &Z.Cmd{
	Name:        `seal`,
	Aliases:     []string{`lock`},
	Usage:       `(help|check|rekey|who|ID|last|same|REGEXP) [HINT...]`,
	MinArgs:     1,
	Summary:     help.S(_seal),
	Description: help.D(_seal),
	Commands:    []*Z.Cmd{help.Cmd, sealCheckCmd, sealRekeyCmd, sealWhoCmd},

	Call: func(x *Z.Cmd, args ...string) error {
		keg, id, entry, err := get(x, args[0])
		if err != nil {
			return err
		}
		s, err := NewSealer(keg.Path)
		if err != nil {
			return err
		}
		if err := SealNode(s, keg.Path, id, strings.Join(args[1:], ` `)); err != nil {
			return err
		}
		return commitNode(keg, entry)
	},
}

var unsealCmd = &Z.Cmd{
	Name:        `unseal`,
	Aliases:     []string{`unlock`},
	Usage:       `(help|ID|last|same|REGEXP)`,
	MinArgs:     1,
	Summary:     help.S(_unseal),
	Description: help.D(_unseal),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {
		keg, id, entry, err := get(x, args[0])
		if err != nil {
			return err
		}
		s, err := NewSealer(keg.Path)
		if err != nil {
			return err
		}
		if err := UnsealNode(s, keg.Path, id); err != nil {
			return err
		}
		return commitNode(keg, entry)
	},
}

var sealCheckCmd = &Z.Cmd{
	Name:        `check`,
	Usage:       `[help]`,
	Summary:     help.S(_seal_check),
	Description: help.D(_seal_check),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, _ ...string) error {
		keg, err := current(x.Caller.Caller)
		if err != nil {
			return err
		}
		if err := GuardSealed(keg.Path); err != nil {
			return err
		}
		term.Print(`every node carrying a sealed tag is sealed`)
		return nil
	},
}

var sealRekeyCmd = &Z.Cmd{
	Name:        `rekey`,
	Usage:       `(help|all|ID|last|same|REGEXP)`,
	MinArgs:     1,
	Summary:     help.S(_seal_rekey),
	Description: help.D(_seal_rekey),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {
		if args[0] == `all` {
			keg, err := current(x.Caller.Caller)
			if err != nil {
				return err
			}
			return rekeyAll(keg)
		}
		keg, id, entry, err := get(x.Caller, args[0])
		if err != nil {
			return err
		}
		s, err := NewSealer(keg.Path)
		if err != nil {
			return err
		}
		if err := RekeyNode(s, keg.Path, id); err != nil {
			return err
		}
		return commitNode(keg, entry)
	},
}

var sealWhoCmd = &Z.Cmd{
	Name:        `who`,
	Usage:       `[help|ID|last|same|REGEXP]`,
	MaxArgs:     1,
	Summary:     help.S(_seal_who),
	Description: help.D(_seal_who),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {
		if len(args) == 0 {
			keg, err := current(x.Caller.Caller)
			if err != nil {
				return err
			}
			st, err := SealSettings(keg.Path)
			if err != nil {
				return err
			}
			fmt.Print(describePolicy(st))
			return nil
		}
		keg, id, _, err := get(x.Caller, args[0])
		if err != nil {
			return err
		}
		st, err := SealSettings(keg.Path)
		if err != nil {
			return err
		}
		tags, err := NodeTags(keg.Path, id)
		if err != nil {
			return err
		}
		fmt.Printf("node %v tags [%v] sealed=%v\n", id, strings.Join(tags, ` `), IsSealedNode(keg.Path, id))
		fmt.Print(describeRecipients(st.Policy.RecipientsFor(tags)))
		return nil
	},
}

// ----------------------------- helpers ------------------------------

func commitNode(keg *Local, entry *DexEntry) error {
	if err := DexUpdate(keg.Path, entry); err != nil {
		return err
	}
	return Publish(keg.Path)
}

func editSealed(keg *Local, id string, entry *DexEntry) error {
	s, err := NewSealer(keg.Path)
	if err != nil {
		return err
	}
	res, err := EditSealedNode(s, keg.Path, id, file.Edit)
	if err != nil {
		return err
	}
	switch res {
	case Unchanged:
		return nil
	case Emptied:
		if err := os.RemoveAll(filepath.Join(keg.Path, id)); err != nil {
			return err
		}
		if err := DexRemove(keg.Path, entry); err != nil {
			return err
		}
		return Publish(keg.Path)
	}
	return commitNode(keg, entry)
}

func createSealed(keg *Local, entry *DexEntry, hint string) error {
	s, err := NewSealer(keg.Path)
	if err != nil {
		return err
	}
	created, err := CreateSealedNode(s, keg.Path, entry, hint, file.Edit)
	if err != nil || !created {
		return err
	}
	return commitNode(keg, entry)
}

func openSealed(kegpath string, buf []byte) ([]byte, error) {
	s, err := NewSealer(kegpath)
	if err != nil {
		return nil, err
	}
	plain, _, err := s.Open(buf)
	return plain, err
}

func rekeyAll(keg *Local) error {
	s, err := NewSealer(keg.Path)
	if err != nil {
		return err
	}
	dirs, _, _ := _fs.IntDirs(keg.Path)
	n := 0
	for _, d := range dirs {
		id := d.Info.Name()
		if !IsSealedNode(keg.Path, id) {
			continue
		}
		if err := RekeyNode(s, keg.Path, id); err != nil {
			return fmt.Errorf("node %v: %w", id, err)
		}
		n++
	}
	term.Print(fmt.Sprintf("rekeyed %v sealed node(s)", n))
	if n == 0 {
		return nil
	}
	return Publish(keg.Path)
}
