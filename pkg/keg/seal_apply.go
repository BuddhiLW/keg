// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package keg

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	Z "github.com/rwxrob/bonzai/z"
	"github.com/rwxrob/help"
	"github.com/rwxrob/term"
)

//go:embed text/en/seal-apply.md
var _seal_apply string

var sealApplyCmd = &Z.Cmd{
	Name:        `apply`,
	Usage:       `[help]`,
	Summary:     help.S(_seal_apply),
	Description: help.D(_seal_apply),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, _ ...string) error {
		keg, err := current(x.Caller.Caller)
		if err != nil {
			return err
		}
		ids, err := PendingSeals(keg.Path)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			term.Print(`no node asks to be sealed`)
			return nil
		}
		return SealPendingNodes(keg.Path)
	},
}

// SealPendingNodes seals every plaintext node whose front matter asks
// for it. It touches gpg only when there is something to seal.
func SealPendingNodes(kegpath string) error {
	ids, err := PendingSeals(kegpath)
	if err != nil || len(ids) == 0 {
		return err
	}
	s, err := NewSealer(kegpath)
	if err != nil {
		return err
	}
	sealed, err := AutoSeal(s, kegpath)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "🔒 sealed:", strings.Join(sealed, " "))
	return nil
}
