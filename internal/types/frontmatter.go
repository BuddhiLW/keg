package types

type FrontMatter struct {
	Title       string `yaml:"title,omitempty"`
	Description string `yaml:"description,omitempty"`
	Published   string `yaml:"published,omitempty"`
	Image       string `yaml:"image,omitempty"`
	Draft       bool   `yaml:"draft,omitempty"`
}
