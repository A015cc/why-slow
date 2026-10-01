package render

import (
	"strings"
	"unicode/utf8"
)

// runeLen counts display columns for the text this tool emits today.
//
// NOTE: it counts Unicode code points, not bytes. Using len() here would count
// bytes and misalign every row the moment a label contains non-ASCII text. This
// is correct for Latin/Greek/Cyrillic, but it is NOT full East-Asian width
// handling: a CJK ideograph occupies two terminal columns while counting as one
// rune, so a table containing CJK would still misalign by one column per glyph.
// Getting that right needs an East-Asian Width table, which this
// zero-dependency project deliberately defers. The tool may later emit Chinese
// text, at which point this function must be revisited (and the padding below
// will need to consult that table).
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// padRight pads s with spaces on the right to w display columns.
func padRight(s string, w int) string {
	if d := w - runeLen(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// padLeft pads s with spaces on the left to w display columns.
func padLeft(s string, w int) string {
	if d := w - runeLen(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

// alignRows pads every column to its widest cell. The final column in each row
// is left unpadded so no line carries trailing whitespace. gap is the number of
// spaces inserted between columns. Widths are measured in runes, see runeLen.
func alignRows(rows [][]string, gap int) []string {
	if len(rows) == 0 {
		return nil
	}
	cols := 0
	for _, row := range rows {
		if len(row) > cols {
			cols = len(row)
		}
	}
	widths := make([]int, cols)
	for _, row := range rows {
		for i, cell := range row {
			if n := runeLen(cell); n > widths[i] {
				widths[i] = n
			}
		}
	}
	sep := strings.Repeat(" ", gap)
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		var b strings.Builder
		for i, cell := range row {
			if i > 0 {
				b.WriteString(sep)
			}
			if i == len(row)-1 {
				b.WriteString(cell)
			} else {
				b.WriteString(padRight(cell, widths[i]))
			}
		}
		out = append(out, b.String())
	}
	return out
}

// kvTable is an ordered set of key/value rows rendered with the keys aligned.
type kvTable struct{ rows [][2]string }

func (t *kvTable) add(k, v string) { t.rows = append(t.rows, [2]string{k, v}) }

func (t *kvTable) render() []string {
	rows := make([][]string, 0, len(t.rows))
	for _, r := range t.rows {
		rows = append(rows, []string{r[0], r[1]})
	}
	return alignRows(rows, 2)
}
