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

//go:embed text/en/okf.md
var _okf string

//go:embed text/en/okf-check.md
var _okf_check string

//go:embed text/en/okf-fix.md
var _okf_fix string

//go:embed text/en/okf-index.md
var _okf_index string

var okfCmd = &Z.Cmd{
	Name:        `okf`,
	Usage:       `(help|check|fix|index)`,
	Summary:     help.S(_okf),
	Description: help.D(_okf),
	Commands:    []*Z.Cmd{help.Cmd, okfCheckCmd, okfFixCmd, okfIndexCmd},
}

func okfSnapshot(x *Z.Cmd) (*Local, OKFSnapshot, error) {
	keg, err := current(x.Caller.Caller)
	if err != nil {
		return nil, OKFSnapshot{}, err
	}
	snap, err := CollectOKF(os.DirFS(keg.Path))
	return keg, snap, err
}

var okfCheckCmd = &Z.Cmd{
	Name:        `check`,
	Usage:       `[help]`,
	Summary:     help.S(_okf_check),
	Description: help.D(_okf_check),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, _ ...string) error {
		_, snap, err := okfSnapshot(x)
		if err != nil {
			return err
		}
		ps := OKFProblems(snap)
		for _, p := range ps {
			fmt.Println(p)
		}
		if len(ps) > 0 {
			return fmt.Errorf("okf: %d of %d files do not conform to OKF v0.2", len(ps), len(snap.Files))
		}
		term.Print(fmt.Sprintf("all %d files conform to OKF v0.2", len(snap.Files)))
		return nil
	},
}

var okfFixCmd = &Z.Cmd{
	Name:        `fix`,
	Usage:       `[help|write]`,
	Params:      []string{`write`},
	MaxArgs:     1,
	Summary:     help.S(_okf_fix),
	Description: help.D(_okf_fix),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, args ...string) error {
		keg, snap, err := okfSnapshot(x)
		if err != nil {
			return err
		}
		plan := PlanOKFFix(snap, OKFSettingsFor(os.Getenv, loginName()))
		for _, w := range plan.Writes {
			fmt.Printf("%s: +%s\n", w.Path, strings.Join(w.Added, ` +`))
		}
		for _, s := range plan.Skips {
			fmt.Printf("%s: skipped (%s)\n", s.Path, s.Reason)
		}
		if len(args) == 0 || args[0] != `write` {
			term.Print(fmt.Sprintf("%d files would change; run with write to apply", len(plan.Writes)))
			return nil
		}
		return ApplyOKF(DirWriter(keg.Path), plan.Writes)
	},
}

var okfIndexCmd = &Z.Cmd{
	Name:        `index`,
	Usage:       `[help]`,
	Summary:     help.S(_okf_index),
	Description: help.D(_okf_index),
	Commands:    []*Z.Cmd{help.Cmd},

	Call: func(x *Z.Cmd, _ ...string) error {
		keg, snap, err := okfSnapshot(x)
		if err != nil {
			return err
		}
		return ApplyOKF(DirWriter(keg.Path), PlanOKFIndex(snap, kegTitle(keg.Path)))
	},
}
