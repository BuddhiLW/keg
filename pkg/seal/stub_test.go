package seal_test

import (
	"github.com/BuddhiLW/keg/pkg/seal"
	"github.com/BuddhiLW/keg/pkg/seal/sealtest"
)

var newStub = sealtest.New

type recording = sealtest.Recording

// runnerFunc adapts a function to seal.Runner.
type runnerFunc func(argv []string, stdin []byte) seal.ExecResult

func (f runnerFunc) Run(argv []string, stdin []byte) seal.ExecResult { return f(argv, stdin) }

const (
	fpA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	fpC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)
