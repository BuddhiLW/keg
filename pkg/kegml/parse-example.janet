(import spork/test)

# Define PEG parser for front matter
(def front-matter-grammar
  (peg/compile
    '{:yaml (sequence "---\n" (thru "---\n") "---\n")
      :title (sequence "# " (thru "\n"))
      :main (sequence :yaml :title)}))

(defn parse-frontmatter [text]
  (peg/match front-matter-grammar text))

(test/start-suite "Front Matter Parsing Tests")

# Test valid YAML front matter and title
(test/assert
  (= (parse-frontmatter "---\nauthor: Jane Doe\ndate: 2024-01-01\n---\n\n# My Title\n")
     @{:yaml "author: Jane Doe\ndate: 2024-01-01\n", :title "My Title"})
  "Valid front matter parsing")

# Test missing front matter
(test/assert
  (nil? (parse-frontmatter "# No front matter\nJust content"))
  "Handles missing front matter correctly")

# Test malformed front matter
(test/assert
  (nil? (parse-frontmatter "---\nfoo: bar\n---\n#TitleWithoutSpace"))
  "Handles missing space after title correctly")

(test/end-suite)
