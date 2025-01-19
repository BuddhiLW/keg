package kegml

import "github.com/rwxrob/pegn"

func ScanYAMLFrontMatter(s pegn.Scanner, buf *[]rune) bool {
	m := s.Mark()

	// Check for opening delimiter
	if !s.Scan() || s.Rune() != '-' {
		return s.Revert(m, Title)
	}
	if !s.Scan() || s.Rune() != '-' {
		return s.Revert(m, Title)
	}
	if !s.Scan() || s.Rune() != '-' {
		return s.Revert(m, Title)
	}
	if !s.Scan() || s.Rune() != '\n' {
		return s.Revert(m, Title)
	}

	// Check for closing delimiter "---\n\n"
	for s.Scan() {
		r := s.Rune()
		if r == '-' {
			if s.Scan() && s.Rune() == '-' && s.Scan() && s.Rune() == '-' && s.Scan() && s.Rune() == '\n' && s.Scan() && s.Rune() == '\n' {
				return true
			}
		}
		if buf != nil {
			*buf = append(*buf, r)
		}
	}
	return s.Revert(m, Title)
}
