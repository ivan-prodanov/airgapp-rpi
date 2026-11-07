package web

import (
	"io/fs"
	"strings"
	"testing"
)

// The Gap theme self-hosts its fonts: the console must not depend on a font
// CDN (privacy, and it has to look right when the WAN is down).
func TestFontsEmbedded(t *testing.T) {
	for _, f := range []string{"static/fonts/saira.woff2", "static/fonts/martian-mono.woff2"} {
		b, err := fs.ReadFile(Content, f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(b) < 10000 || string(b[:4]) != "wOF2" {
			t.Errorf("%s: not a woff2 font (%d bytes, magic %q)", f, len(b), b[:min(4, len(b))])
		}
	}
	for _, f := range []string{"static/fonts/OFL-Saira.txt", "static/fonts/OFL-MartianMono.txt"} {
		b, err := fs.ReadFile(Content, f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if !strings.Contains(string(b), "SIL OPEN FONT LICENSE") {
			t.Errorf("%s: missing the SIL Open Font License text", f)
		}
	}
}

func TestGapCSSDeclaresFonts(t *testing.T) {
	b, err := fs.ReadFile(Content, "static/css/gap.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(b)
	for _, want := range []string{
		"font-family:'Saira'",
		"url(/static/fonts/saira.woff2) format('woff2')",
		"font-weight:300 700",
		"font-family:'Martian Mono'",
		"url(/static/fonts/martian-mono.woff2) format('woff2')",
		"font-weight:400 600",
		"font-display:swap",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("gap.css lacks %q", want)
		}
	}
}
