package kegml_test

import (
	"fmt"
	"testing"

	"github.com/BuddhiLW/keg/kegml"
	"github.com/rwxrob/pegn/scanner"
)

func ExampleScanTitle_short() {
	s := scanner.New(`# A short title`)

	fmt.Println(kegml.ScanTitle(s, nil))
	s.Print()

	// Output:
	// true
	// 'e' 14-15 ""
}

func ExampleTitle_parsed_Short() {
	s := scanner.New(`# A short title`)

	title := make([]rune, 0, 100)
	fmt.Println(kegml.ScanTitle(s, &title))

	s.Print()
	fmt.Printf("%q", string(title))

	// Output:
	// true
	// 'e' 14-15 ""
	// "A short title"
}

func ExampleTitle() {
	title, _ := kegml.ReadTitle(`testdata/sample-node`)
	fmt.Println(title)

	// Output:
	// This is a title
}

func ExampleTitle_no_README() {
	title, _ := kegml.ReadTitle(`testdata/sample-node`)
	fmt.Println(title)

	// Output:
	// This is a title
}

func TestTitle_withYAMLFrontMatter(t *testing.T) {
	s := scanner.New(`---
author: John Doe
date: 2024-01-01
---

# My Actual Title`)

	title := make([]rune, 0, 100)
	result := kegml.ScanTitle(s, &title)

	if !result || string(title) != "My Actual Title" {
		t.Errorf("Expected 'My Actual Title', got %q", string(title))
	}
}

func ExampleTitle_withBlankLinesAfterYAML() {
	s := scanner.New(`---
author: Jane Doe
date: 2024-01-01
---



# Another Title`)

	title := make([]rune, 0, 100)
	fmt.Println(kegml.ScanTitle(s, &title))
	s.Print()
	fmt.Printf("%q", string(title))

	// Output:
	// true
	// '#' 49-50 ""
	// "Another Title"
}

func ExampleTitle_noTitle() {
	s := scanner.New(`---
author: Test
---

No title present here`)

	title := make([]rune, 0, 100)
	fmt.Println(kegml.ScanTitle(s, &title))
	s.Print()
	fmt.Printf("%q", string(title))

	// Output:
	// false
	// 'N' 22-23 ""
	// ""
}

func ExampleTitle_tooLong() {
	s := scanner.New(`# This is a very long title that exceeds the seventy character limit and should not be processed completely`)

	title := make([]rune, 0, 100)
	fmt.Println(kegml.ScanTitle(s, &title))
	s.Print()
	fmt.Printf("%q", string(title))

	// Output:
	// false
	// 's' 70-71 ""
	// "This is a very long title that exceeds the seventy character limit "
}

func ExampleTitle_multilineTitle() {
	s := scanner.New(`# Title line 1
Title line 2`)

	title := make([]rune, 0, 100)
	fmt.Println(kegml.ScanTitle(s, &title))
	s.Print()
	fmt.Printf("%q", string(title))

	// Output:
	// true
	// 'T' 13-14 ""
	// "Title line 1"
}
