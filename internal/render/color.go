package render

import (
	"io"
	"os"

	"github.com/A015cc/why-slow/internal/model"
)

// ANSI SGR codes. Kept to the minimum the report needs: severity markers and
// cluster labels. Everything else stays uncoloured so the text reads the same
// when piped to a file or viewed by someone who cannot perceive the colours.
const (
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

// ColorEnabled reports whether ANSI styling should be emitted to w.
//
// The conventions are honoured in the order they are meant to be applied:
//
//   - NO_COLOR set (to any value, including empty) forces colour off.
//   - CLICOLOR_FORCE set to a non-empty, non-"0" value forces colour on.
//   - otherwise colour is on only when w is a terminal.
//
// Terminal detection is done with os.File.Stat and the ModeCharDevice bit, so
// it needs no dependency. On Windows, enabling colour also means switching the
// console into virtual-terminal mode; that is handled by the build-tagged
// enableVirtualTerminal helpers.
func ColorEnabled(w io.Writer) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	if fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return enableVirtualTerminal(f)
}

// palette applies (or drops) ANSI styling for one render pass.
type palette struct{ on bool }

func newPalette(on bool) palette { return palette{on: on} }

func (p palette) code(c, s string) string {
	if !p.on || s == "" {
		return s
	}
	return c + s + ansiReset
}

// sev styles a severity marker such as "[!]".
func (p palette) sev(s model.Severity) string {
	return p.code(sevColor(s), sevMarker(s))
}

// cluster styles a cluster label such as "cluster B".
func (p palette) cluster(label string) string {
	return p.code(ansiCyan, label)
}

func sevColor(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return ansiRed
	case model.SevWarning:
		return ansiYellow
	case model.SevNotice:
		return ansiCyan
	default:
		return ansiDim
	}
}

// sevMarker is the textual severity tag. It is deliberately ASCII so it reads
// the same in any console codepage; colour is only ever an accelerator on top.
func sevMarker(s model.Severity) string {
	switch s {
	case model.SevCritical:
		return "[!!]"
	case model.SevWarning:
		return "[!]"
	case model.SevNotice:
		return "[*]"
	default:
		return "[i]"
	}
}
