// Copyright 2026 Pedro G Branquinho.
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ExecResult is what a process run produced.
type ExecResult struct {
	Stdout []byte
	Stderr []byte
	Exit   int
	Err    error // failure to start or wait, not a non-zero exit
}

// Runner runs argv feeding stdin from memory, so plaintext never touches
// disk on its way to gpg.
type Runner interface {
	Run(argv []string, stdin []byte) ExecResult
}

// OSRunner is the Runner backed by os/exec.
type OSRunner struct{}

func (OSRunner) Run(argv []string, stdin []byte) ExecResult {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := ExecResult{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.Exit = exit.ExitCode()
	case err != nil:
		res.Err, res.Exit = err, -1
	}
	return res
}

// GPG is the Cipher adapter over the gpg executable.
type GPG struct {
	Opts   GPGOptions
	Runner Runner
}

// NewGPG returns a GPG running the real executable.
func NewGPG(o GPGOptions) GPG { return GPG{Opts: o, Runner: OSRunner{}} }

func (o GPGOptions) base() []string {
	bin := o.Bin
	if bin == "" {
		bin = "gpg"
	}
	argv := []string{bin}
	if o.Homedir != "" {
		argv = append(argv, "--homedir", o.Homedir)
	}
	return argv
}

// EncryptArgv reads plaintext on stdin and prints armor on stdout.
func EncryptArgv(o GPGOptions, to Recipients) []string {
	argv := append(o.base(), "--batch", "--yes", "--quiet", "--armor")
	if !o.ShowRecipients {
		argv = append(argv, "--throw-keyids")
	}
	argv = append(argv, "--trust-model", "always", "--encrypt")
	if len(to) == 0 {
		return append(argv, "--default-recipient-self")
	}
	for _, fp := range to {
		argv = append(argv, "--recipient", string(fp))
	}
	return argv
}

// DecryptArgv reads armor on stdin and prints plaintext on stdout, with
// status lines on stderr. No --batch: gpg-agent must be free to ask the
// human through pinentry.
func DecryptArgv(o GPGOptions) []string {
	return append(o.base(), "--quiet", "--status-fd", "2", "--decrypt")
}

func (g GPG) Encrypt(plain []byte, to Recipients) (string, error) {
	res := g.Runner.Run(EncryptArgv(g.Opts, to), plain)
	return ArmorResult(res)
}

func (g GPG) Decrypt(armor string) ([]byte, error) {
	res := g.Runner.Run(DecryptArgv(g.Opts), []byte(armor))
	return PlainResult(res)
}

// ArmorResult classifies an encrypt run.
func ArmorResult(r ExecResult) (string, error) {
	if r.Err != nil {
		return "", fmt.Errorf("seal: gpg did not run: %w", r.Err)
	}
	out := string(r.Stdout)
	if r.Exit != 0 || !IsArmor(out) {
		return "", fmt.Errorf("seal: gpg encrypt failed (exit %d): %s", r.Exit, stderrSummary(r.Stderr))
	}
	return out, nil
}

// PlainResult classifies a decrypt run. A non-zero exit still succeeds
// when gpg reports DECRYPTION_OKAY: with hidden recipients gpg tries
// every secret key and each wrong one sets the exit code. A failed
// integrity check always fails.
func PlainResult(r ExecResult) ([]byte, error) {
	if r.Err != nil {
		return nil, fmt.Errorf("seal: gpg did not run: %w", r.Err)
	}
	st := statusKeywords(r.Stderr)
	switch {
	case st["DECRYPTION_FAILED"] || st["BADMDC"]:
		return nil, fmt.Errorf("seal: decryption failed: %s", stderrSummary(r.Stderr))
	case st["DECRYPTION_OKAY"]:
		return r.Stdout, nil
	case r.Exit == 0:
		return r.Stdout, nil
	default:
		return nil, fmt.Errorf("seal: gpg decrypt failed (exit %d): %s", r.Exit, stderrSummary(r.Stderr))
	}
}

const statusPrefix = "[GNUPG:] "

func statusKeywords(stderr []byte) map[string]bool {
	out := map[string]bool{}
	s := bufio.NewScanner(bytes.NewReader(stderr))
	for s.Scan() {
		if rest, ok := strings.CutPrefix(s.Text(), statusPrefix); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				out[f[0]] = true
			}
		}
	}
	return out
}

func stderrSummary(stderr []byte) string {
	var lines []string
	s := bufio.NewScanner(bytes.NewReader(stderr))
	for s.Scan() && len(lines) < 3 {
		if l := strings.TrimSpace(s.Text()); l != "" && !strings.HasPrefix(l, statusPrefix) {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return "no diagnostic from gpg"
	}
	return strings.Join(lines, "; ")
}
