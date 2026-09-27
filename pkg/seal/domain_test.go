package seal_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/BuddhiLW/keg/pkg/seal"
)

const armor = "-----BEGIN PGP MESSAGE-----\n\nhQEMA\n-----END PGP MESSAGE-----\n"

func TestEnvelopeRoundTrip(t *testing.T) {
	for _, env := range []seal.Envelope{{Armor: armor}, {Hint: "diary", Armor: armor}} {
		got, ok := seal.Parse(env.Render())
		if !ok || got != env {
			t.Fatalf("round trip of %+v gave %+v ok=%v", env, got, ok)
		}
	}
}

func TestEnvelopeIsTheHiveFormat(t *testing.T) {
	got := seal.Envelope{Hint: "h", Armor: armor}.Render()
	want := "#hive/sealed 1\nhint: h\n" + armor
	if got != want {
		t.Fatalf("render:\n%q\nwant\n%q", got, want)
	}
}

func TestHeaderOverPlaintextIsNotSealed(t *testing.T) {
	for _, s := range []string{
		"# A title\n\nbody",
		seal.Header + "just text\n",
		seal.Header + "hint: no armor follows",
		seal.Header,
	} {
		if seal.IsSealed([]byte(s)) {
			t.Errorf("%q reported sealed", s)
		}
	}
}

func TestParseFingerprint(t *testing.T) {
	fp, err := seal.ParseFingerprint("0xaaaa AAAA aaaa AAAA aaaa AAAA aaaa AAAA aaaa AAAA")
	if err != nil || fp != fpA {
		t.Fatalf("got %q %v", fp, err)
	}
	for _, bad := range []string{"", "DEADBEEF", "someone@example.com", strings.Repeat("G", 40)} {
		if _, err := seal.ParseFingerprint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRecipientsNormal(t *testing.T) {
	rs := seal.Recipients{fpB, fpA, fpB}.Union(seal.Recipients{fpA})
	if !reflect.DeepEqual(rs, seal.Recipients{fpA, fpB}) {
		t.Fatalf("got %v", rs)
	}
}

func policy() seal.Policy {
	return seal.Policy{
		Default: seal.Recipients{fpA},
		TopicRecipients: map[string]seal.Recipients{
			"diary":  {fpB},
			"health": {fpB, fpC},
		},
		Topics: map[string]bool{"private": true},
	}
}

func TestRecipientsForUsesDefaultUnlessATagIsMapped(t *testing.T) {
	p := policy()
	cases := []struct {
		tags []string
		want seal.Recipients
	}{
		{nil, seal.Recipients{fpA}},
		{[]string{"private"}, seal.Recipients{fpA}},
		{[]string{"diary"}, seal.Recipients{fpB}},
		{[]string{"diary", "health", "x"}, seal.Recipients{fpB, fpC}},
	}
	for _, c := range cases {
		if got := p.RecipientsFor(c.tags); !reflect.DeepEqual(got, c.want) {
			t.Errorf("tags %v: got %v want %v", c.tags, got, c.want)
		}
	}
}

func TestMustSeal(t *testing.T) {
	p := policy()
	if !p.MustSeal([]string{"x", "private"}) || !p.MustSeal([]string{"diary"}) {
		t.Fatal("sealed topic or compartment not detected")
	}
	if p.MustSeal([]string{"x"}) || p.MustSeal(nil) {
		t.Fatal("unsealed tags reported")
	}
	if got := p.SealedTopics(); !reflect.DeepEqual(got, []string{"diary", "health", "private"}) {
		t.Fatalf("SealedTopics %v", got)
	}
}

const kegfile = `updated: 2026-09-27 00:00:00Z
kegv:    2023-01

title:   Private
seal:
  recipients:
    - ` + fpA + `
  topics: [private, journal]
  topic-recipients:
    diary:
      - ` + fpB + `
      - ` + fpC + `
  gpg:
    homedir: /tmp/gh

indexes:
  - file: dex/changes.md
`

func noenv(string) string { return "" }

func TestParseSettingsFromKegFile(t *testing.T) {
	s, err := seal.ParseSettings(kegfile, noenv)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Policy.Default, seal.Recipients{fpA}) {
		t.Errorf("default %v", s.Policy.Default)
	}
	if !reflect.DeepEqual(s.Policy.TopicRecipients["diary"], seal.Recipients{fpB, fpC}) {
		t.Errorf("diary %v", s.Policy.TopicRecipients["diary"])
	}
	if !s.Policy.Topics["journal"] || s.GPG.Homedir != "/tmp/gh" || s.GPG.Bin != "gpg" {
		t.Errorf("settings %+v", s)
	}
}

func TestParseSettingsEnvOverrides(t *testing.T) {
	env := map[string]string{
		seal.EnvRecipients:      fpC,
		seal.EnvTopicRecipients: "work=" + fpA + ",work=" + fpB,
		seal.EnvTopics:          "extra",
	}
	s, err := seal.ParseSettings(kegfile, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Policy.Default, seal.Recipients{fpC}) {
		t.Errorf("default %v", s.Policy.Default)
	}
	if _, ok := s.Policy.TopicRecipients["diary"]; ok {
		t.Error("env topic recipients must replace the file's")
	}
	if !reflect.DeepEqual(s.Policy.TopicRecipients["work"], seal.Recipients{fpA, fpB}) {
		t.Errorf("work %v", s.Policy.TopicRecipients["work"])
	}
	if !s.Policy.Topics["extra"] || !s.Policy.Topics["private"] {
		t.Errorf("topics %v", s.Policy.Topics)
	}
}

func TestParseSettingsRefusesMalformedEntries(t *testing.T) {
	bad := []struct {
		file string
		env  map[string]string
	}{
		{"seal:\n  recipients: [DEADBEEF]\n", nil},
		{"seal:\n  topic-recipients:\n    diary: []\n", nil},
		{"", map[string]string{seal.EnvTopicRecipients: "diary"}},
		{"", map[string]string{seal.EnvTopicRecipients: "=" + fpA}},
		{"", map[string]string{seal.EnvRecipients: "alice"}},
	}
	for _, b := range bad {
		if _, err := seal.ParseSettings(b.file, func(k string) string { return b.env[k] }); err == nil {
			t.Errorf("accepted file %q env %v", b.file, b.env)
		}
	}
}

func TestNoSealSectionMeansNoPolicy(t *testing.T) {
	s, err := seal.ParseSettings("updated: x\ntitle: y\n", noenv)
	if err != nil || len(s.Policy.Default) != 0 || len(s.Policy.SealedTopics()) != 0 {
		t.Fatalf("%+v %v", s, err)
	}
}
