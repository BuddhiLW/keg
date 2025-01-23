package kegml

import (
	_ "embed"
	"fmt"

	"path/filepath"
	"strings"

	"github.com/rwxrob/pegn"
	"github.com/rwxrob/pegn/ast"
	"github.com/rwxrob/pegn/scanner"
)

//go:embed kegml.pegn
var PEGN string

const (
	Untyped int = iota
	Title
)

// ------------------------------- Title ------------------------------

func ScanTitle(s pegn.Scanner, buf *[]rune) bool {
	m := s.Mark()
	newLine := true
	for newLine {
		if s.Scan() && s.Rune() == '\n' {
			continue
		} else if s.Rune() != '#' {
			fmt.Println("Title header '#' not found, reverting...")
			newLine = false
			return s.Revert(m, Title)
		} else if s.Rune() == '#' {
			fmt.Println("Title header '#' found, continuing...")
			newLine = false
		}
	}

	if !s.Scan() || s.Rune() != ' ' {
		return s.Revert(m, Title)
	}
	var count int
	for s.Scan() {
		if count > 70 {
			return s.Revert(m, Title)
		}
		r := s.Rune()
		if r == '\n' {
			if count > 0 {
				return true
			} else {
				return s.Revert(m, Title)
			}
		}
		if buf != nil {
			*buf = append(*buf, r)
		}
		count++
	}
	return true
}

func ParseTitle(s pegn.Scanner) *ast.Node {
	// fmt.Println("Trying to Parse title?")
	buf := make([]rune, 0, 70)
	if !ScanTitle(s, &buf) {
		return nil
	}
	// fmt.Println("string(buf):", string(buf))
	return &ast.Node{T: Title, V: string(buf)}
}

var Scanner pegn.Scanner

func init() {
	Scanner = scanner.New()
	Scanner.SetErrFmtFunc(
		func(e error) string {
			return fmt.Sprintf("custom %q\n", e)
		})
}

// ReadTitle reads a KEG node title from KEGML file.
func ReadTitle(path string) (string, error) {
	// fmt.Println("[kegml.ReadTitle] path: ", path)
	if !strings.HasSuffix(path, `README.md`) {
		path = filepath.Join(path, `README.md`)
	}

	// Scan first the file with the frontmatter parser
	// So we call delegate the rest of the content (in a buffer)
	// to the pegn scanner - as intended in previous implementation.
	//
	// This behaviour is retro-compatible: KEG nodes without frontmatter will work just as usual

	// fmt.Println("Trying to parse title... ")
	rest, matter, err := ScanYAMLFrontMatter(path)
	if err != nil {
		// fmt.Println("Error processing while trying to parse the front matter")
		return "", err
	}

	if err := Scanner.Buffer(rest); err != nil {
		// fmt.Println("Error processing rest of buffer data (besides front matter)")
		return "", err
	}
	// Scanner.TraceOn()

	// fmt.Println("string(Scanner.Bytes()) :", string(*Scanner.Bytes()))
	// fmt.Println("matter:", matter)
	// fmt.Println("matter.Title:", matter.Title)

	if matter.Title == "" {
		nd := ParseTitle(Scanner)
		if nd == nil {
			fmt.Println("Error Parsing Title")
			return "", Scanner
		}
		return nd.V, nil
	}
	return matter.Title, nil
}
