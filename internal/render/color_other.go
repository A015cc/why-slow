//go:build !windows

package render

import "os"

// enableVirtualTerminal is a no-op away from Windows: terminals elsewhere speak
// ANSI natively.
func enableVirtualTerminal(_ *os.File) bool { return true }
