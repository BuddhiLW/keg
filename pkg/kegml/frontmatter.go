package kegml

import (
	"fmt"
	"os"
	"strings"

	"github.com/BuddhiLW/keg/internal/types"
	"github.com/adrg/frontmatter"
)

func ScanYAMLFrontMatter(path string) ([]byte, types.FrontMatter, error) {
	var matter types.FrontMatter

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Couldn't read path")
		return []byte{}, matter, err
	}

	rest, err := frontmatter.Parse(strings.NewReader(string(data)), &matter)

	return rest, matter, err
}

// func ScanYAMLFrontMatter(s pegn.Scanner, buf *[]rune) bool {
// 	var matter types.FrontMatter

// 	// what should be input here?
// 	rest, err := frontmatter.Parse(strings.NewReader(input), &matter)
// 	if err != nil {
// 		// Treat error.
// 	}
// 	// NOTE: If a front matter must be present in the input data, use
// 	//       frontmatter.MustParse instead.

// 	fmt.Printf("%+v\n", matter)
// 	fmt.Println(string(rest))
// }

// func ScanYAMLFrontMatter(s pegn.Scanner, buf *[]rune) bool {
// 	fmt.Println("Entering ScanYAMLFrontMatter")
// 	m := s.Mark()

// 	// Check for opening YAML delimiter "---\n"
// 	if !s.Scan() || s.Rune() != '-' {
// 		fmt.Println("Failed to find first '-'")
// 		return s.Revert(m, Title)
// 	}
// 	if !s.Scan() || s.Rune() != '-' {
// 		fmt.Println("Failed to find second '-'")
// 		return s.Revert(m, Title)
// 	}
// 	if !s.Scan() || s.Rune() != '-' {
// 		fmt.Println("Failed to find third '-'")
// 		return s.Revert(m, Title)
// 	}
// 	if !s.Scan() || s.Rune() != '\n' {
// 		fmt.Println("No newline after YAML start delimiter")
// 		return s.Revert(m, Title)
// 	}

// 	fmt.Println("YAML front matter found, scanning content...")

// 	// Consume all lines inside YAML front matter
// 	for s.Scan() {
// 		r := s.Rune()
// 		if r == '-' {
// 			// Look ahead for closing "---"
// 			if s.Scan() && s.Rune() == '-' &&
// 				s.Scan() && s.Rune() == '-' &&
// 				s.Scan() && s.Rune() == '\n' {

// 				// Check if there is a required newline after closing YAML
// 				if s.Scan() && s.Rune() != '\n' {
// 					fmt.Println("Missing newline after closing YAML front matter")
// 					return s.Revert(m, Title)
// 				}

// 				fmt.Println("YAML front matter closed properly")
// 				break
// 			}
// 		}
// 		if buf != nil {
// 			*buf = append(*buf, r)
// 		}
// 	}

// 	// Ensure there are no unexpected trailing characters
// 	if buf != nil && len(*buf) > 0 && (*buf)[len(*buf)-1] == '-' {
// 		*buf = (*buf)[:len(*buf)-1] // Remove trailing "-"
// 	}

// 	// Scan any trailing blank lines after YAML
// 	for s.Scan() {
// 		if s.Rune() != '\n' && s.Rune() != ' ' {
// 			// s.Backup() // Step back to the first non-blank line
// 			break
// 		}
// 	}
// 	fmt.Println("Exiting ScanYAMLFrontMatter successfully")
// 	return true
// }
