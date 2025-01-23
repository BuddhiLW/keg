package kegml_test

import (
	// "fmt"
	"os"
	"testing"

	"github.com/BuddhiLW/keg/pkg/kegml"
	"github.com/rwxrob/pegn/scanner"
)

func setupTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func teardownTestFile(path string) {
	os.Remove(path)
}

func TestReadTitle_ValidTitle(t *testing.T) {
	path := "./testdata/sample-node/README.md"
	setupTestFile(path, `# Valid Title`)

	defer teardownTestFile(path)

	title, err := kegml.ReadTitle("./testdata/sample-node/README.md")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expected := "Valid Title"
	if title != expected {
		t.Errorf("Expected %q, got %q", expected, title)
	}
}

// func TestReadTitle_NoReadme(t *testing.T) {
// 	path := "testdata/no-readme"
// 	os.Mkdir(path, 0755)
// 	defer os.RemoveAll(path)

// 	_, err := kegml.ReadTitle(path)
// 	if err == nil {
// 		t.Errorf("Expected an error for missing README.md, got nil")
// 	}
// }

// func TestReadTitle_InvalidFormat(t *testing.T) {
// 	path := "testdata/invalid-format/README.md"
// 	setupTestFile(path, `No title here`)

// 	defer teardownTestFile(path)

// 	_, err := kegml.ReadTitle("testdata/invalid-format")
// 	if err == nil {
// 		t.Errorf("Expected an error for invalid format, got nil")
// 	}
// }

// func TestReadTitle_EmptyFile(t *testing.T) {
// 	path := "testdata/empty/README.md"
// 	setupTestFile(path, ``)

// 	defer teardownTestFile(path)

// 	_, err := kegml.ReadTitle("testdata/empty")
// 	if err == nil {
// 		t.Errorf("Expected an error for empty file, got nil")
// 	}
// }

func TestReadTitle_YAMLFrontMatter(t *testing.T) {
	path := "../testdata/samplekeg/13/README.md"
	setupTestFile(path, `---
author: Jane Doe
date: 2024-01-01
---

# Title from YAML`)

	defer teardownTestFile(path)

	title, err := kegml.ReadTitle(path)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	expected := "Title from YAML"
	if title != expected {
		t.Errorf("Expected %q, got %q", expected, title)
	}
}

// func TestReadTitle_MultilineTitle(t *testing.T) {
// 	path := "testdata/multiline/README.md"
// 	setupTestFile(path, `# First Line
// Second Line`)

// 	defer teardownTestFile(path)

//		title, err := kegml.ReadTitle("testdata/multiline")
//		if err != nil {
//			t.Fatalf("Unexpected error: %v", err)
//		}
//		expected := "First Line"
//		if title != expected {
//			t.Errorf("Expected %q, got %q", expected, title)
//		}
//	}
func TestScanYAMLFrontMatter_Valid(t *testing.T) {
	s := scanner.New(`---
author: John Doe
date: 2024-01-01
---

# Title`)

	buf := make([]rune, 0)
	result := kegml.ScanYAMLFrontMatter(s, &buf)

	if !result {
		t.Errorf("Expected ScanYAMLFrontMatter to succeed, but it failed")
	}

	expectedContent := "author: John Doe\ndate: 2024-01-01\n"
	if string(buf) != expectedContent {
		t.Errorf("Expected content %q, but got %q", expectedContent, string(buf))
	}
}

func TestScanYAMLFrontMatter_NoYAML(t *testing.T) {
	s := scanner.New(`# No YAML here`)

	buf := make([]rune, 0)
	result := kegml.ScanYAMLFrontMatter(s, &buf)

	if result {
		t.Errorf("Expected ScanYAMLFrontMatter to fail, but it succeeded")
	}

	if len(buf) != 0 {
		t.Errorf("Expected buffer to be empty, but got %q", string(buf))
	}
}

func TestScanYAMLFrontMatter_IncompleteYAML(t *testing.T) {
	s := scanner.New(`---
author: Jane Doe
date: 2024-01-01
--`)

	buf := make([]rune, 0)
	result := kegml.ScanYAMLFrontMatter(s, &buf)

	if result {
		t.Errorf("Expected ScanYAMLFrontMatter to fail, but it succeeded")
	}

	expectedContent := "author: Jane Doe\ndate: 2024-01-01\n--"
	if string(buf) != expectedContent {
		t.Errorf("Expected content %q, but got %q", expectedContent, string(buf))
	}
}

func TestScanYAMLFrontMatter_MissingNewlineAfterYAML(t *testing.T) {
	s := scanner.New(`---
author: John Doe
date: 2024-01-01
---# Title`)

	buf := make([]rune, 0)
	result := kegml.ScanYAMLFrontMatter(s, &buf)

	if result {
		t.Errorf("Expected ScanYAMLFrontMatter to fail due to missing newline, but it succeeded")
	}
}

func TestScanYAMLFrontMatter_EmptyContent(t *testing.T) {
	s := scanner.New(`---
---`)

	buf := make([]rune, 0)
	result := kegml.ScanYAMLFrontMatter(s, &buf)

	if !result {
		t.Errorf("Expected ScanYAMLFrontMatter to succeed on empty YAML front matter, but it failed")
	}

	if len(buf) != 0 {
		t.Errorf("Expected empty content in buffer, but got %q", string(buf))
	}
}

func TestScanYAMLFrontMatter_BlankLinesAfterYAML(t *testing.T) {
	s := scanner.New(`---
author: Jane Doe
date: 2024-01-01
---



# Title`)

	buf := make([]rune, 0)
	result := kegml.ScanYAMLFrontMatter(s, &buf)

	if !result {
		t.Errorf("Expected ScanYAMLFrontMatter to succeed, but it failed")
	}

	expectedContent := "author: Jane Doe\ndate: 2024-01-01\n"
	if string(buf) != expectedContent {
		t.Errorf("Expected content %q, but got %q", expectedContent, string(buf))
	}
}

func TestScanYAMLFrontMatter_NoClosingDelimiter(t *testing.T) {
	s := scanner.New(`---
author: Missing
date: 2024-01-01
`)

	buf := make([]rune, 0)
	result := kegml.ScanYAMLFrontMatter(s, &buf)

	if result {
		t.Errorf("Expected ScanYAMLFrontMatter to fail due to missing closing delimiter, but it succeeded")
	}

	expectedContent := "author: Missing\ndate: 2024-01-01\n"
	if string(buf) != expectedContent {
		t.Errorf("Expected content %q, but got %q", expectedContent, string(buf))
	}
}
