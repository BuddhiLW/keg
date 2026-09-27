package seal_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/seal"
)

func TestParseDirective(t *testing.T) {
	cases := []struct {
		name string
		note string
		want seal.Directive
	}{
		{"no front matter", "# Title\n\nseal: true\n", seal.Directive{}},
		{"front matter without seal", "---\ntitle: x\n---\n# x\n", seal.Directive{}},
		{"seal true", "---\nseal: true\n---\n# x\n", seal.Directive{Seal: true}},
		{"seal false", "---\nseal: false\nseal-hint: h\n---\n", seal.Directive{Hint: "h"}},
		{"hint", "---\ntitle: x\nseal: yes\nseal-hint: a hard decision\n---\n",
			seal.Directive{Seal: true, Hint: "a hard decision"}},
		{"yaml list", "---\nseal: [" + fpB + ", " + fpA + "]\n---\n",
			seal.Directive{Seal: true, To: seal.Recipients{fpA, fpB}}},
		{"block list", "---\nseal:\n  - " + fpA + "\n---\n",
			seal.Directive{Seal: true, To: seal.Recipients{fpA}}},
		{"csv", "---\nseal: " + fpA + "," + fpC + "\n---\n",
			seal.Directive{Seal: true, To: seal.Recipients{fpA, fpC}}},
		{"crlf and dots", "---\r\nseal: true\r\n...\r\nbody", seal.Directive{Seal: true}},
	}
	for _, c := range cases {
		got, err := seal.ParseDirective([]byte(c.note))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%v: got %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
}

func TestParseDirectiveFailsClosed(t *testing.T) {
	for _, note := range []string{
		"---\nseal: DEADBEEF\n---\n",
		"---\nseal: alice@example.com\n---\n",
		"---\nseal: []\n---\n",
		"---\nseal: {to: x}\n---\n",
		"---\nseal: [" + fpA + "\n---\n",
		"---\nseal: \"\"\n---\n",
	} {
		if d, err := seal.ParseDirective([]byte(note)); err == nil {
			t.Errorf("%q accepted as %+v", note, d)
		}
	}
}

func TestDirectiveRecipientsOverrideThePolicy(t *testing.T) {
	rec := &recording{Cipher: newStub(fpA, fpB, fpC)}
	s := seal.Sealer{Cipher: rec, Policy: policy()}
	note := "---\nseal: [" + fpC + "]\nseal-hint: from the note\n---\n# secret\n"
	stored, err := s.Seal([]byte(note), "", []string{"diary"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rec.Calls, []seal.Recipients{{fpC}}) {
		t.Fatalf("recipients %v", rec.Calls)
	}
	env, _ := seal.Parse(stored)
	if env.Hint != "from the note" {
		t.Fatalf("hint %q", env.Hint)
	}
	if _, err := s.Seal([]byte("---\nseal: DEADBEEF\n---\n"), "", nil); err == nil {
		t.Fatal("sealed a note whose directive is malformed")
	}
}

func TestRewriteKeepsTheDirectiveHintOverTheOldOne(t *testing.T) {
	s := seal.Sealer{Cipher: newStub(fpA), Policy: policy()}
	stored, _ := s.Seal([]byte("plain"), "old hint", nil)
	env, _ := seal.Parse(stored)

	out, err := s.Rewrite(env, []byte("still plain"), nil)
	if e, _ := seal.Parse(out); err != nil || e.Hint != "old hint" {
		t.Fatalf("without directive: %q %v", e.Hint, err)
	}
	out, err = s.Rewrite(env, []byte("---\nseal: true\nseal-hint: new hint\n---\n"), nil)
	if e, _ := seal.Parse(out); err != nil || e.Hint != "new hint" {
		t.Fatalf("with directive: %q %v", e.Hint, err)
	}
	if strings.Contains(out, "seal: true") {
		t.Fatal("front matter leaked outside the ciphertext")
	}
}
