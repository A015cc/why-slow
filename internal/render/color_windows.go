//go:build windows

package render

import (
	"os"
	"syscall"
	"unsafe"
)

// Windows consoles only interpret ANSI escape sequences once the
// ENABLE_VIRTUAL_TERMINAL_PROCESSING bit is set in the console mode. This is
// done with the stdlib syscall package rather than golang.org/x/sys so the tool
// keeps its zero-dependency promise.
var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const enableVirtualTerminalProcessing = 0x0004

// enableVirtualTerminal turns on ANSI processing for the console behind f and
// reports whether ANSI output will be honoured. Failure (for example when f is
// not a console handle) simply means "do not colour".
func enableVirtualTerminal(f *os.File) bool {
	handle := syscall.Handle(f.Fd())
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	r, _, _ = procSetConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}
