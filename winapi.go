package main

import (
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procGetSystemDirectoryW = kernel32.NewProc("GetSystemDirectoryW")
	procLoadLibraryExW      = kernel32.NewProc("LoadLibraryExW")
	procFormatMessageW      = kernel32.NewProc("FormatMessageW")
	procRegEnumValueW       = advapi32.NewProc("RegEnumValueW")
)

func systemDir() string {
	buf := make([]uint16, syscall.MAX_PATH)
	n, _, _ := procGetSystemDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 || int(n) > len(buf) {
		return filepath.Join(windowsDir(), "System32")
	}
	return syscall.UTF16ToString(buf[:n])
}

func windowsDir() string {
	if d := os.Getenv("SystemRoot"); d != "" {
		return d
	}
	return `C:\Windows`
}

func isElevated() bool {
	var tok syscall.Token
	p, err := syscall.GetCurrentProcess()
	if err != nil || syscall.OpenProcessToken(p, syscall.TOKEN_QUERY, &tok) != nil {
		return false
	}
	defer tok.Close()
	const tokenElevation = 20
	var elevated, n uint32
	err = syscall.GetTokenInformation(tok, tokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &n)
	return err == nil && elevated != 0
}

func regOpen(path string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	err = syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, p, 0, syscall.KEY_READ, &h)
	return h, err
}

func regKeyExists(path string) bool {
	h, err := regOpen(path)
	if err != nil {
		return false
	}
	syscall.RegCloseKey(h)
	return true
}

func regString(path, name string) string {
	h, err := regOpen(path)
	if err != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	n, _ := syscall.UTF16PtrFromString(name)
	buf := make([]uint16, 512)
	size := uint32(len(buf) * 2)
	var typ uint32
	if syscall.RegQueryValueEx(h, n, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size) != nil {
		return ""
	}
	if typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ {
		return ""
	}
	return syscall.UTF16ToString(buf[:size/2])
}

func regDword(path, name string) (uint32, bool) {
	h, err := regOpen(path)
	if err != nil {
		return 0, false
	}
	defer syscall.RegCloseKey(h)
	n, _ := syscall.UTF16PtrFromString(name)
	var v, typ uint32
	size := uint32(4)
	if syscall.RegQueryValueEx(h, n, nil, &typ, (*byte)(unsafe.Pointer(&v)), &size) != nil || typ != syscall.REG_DWORD {
		return 0, false
	}
	return v, true
}

func regValueNames(path string) []string {
	h, err := regOpen(path)
	if err != nil {
		return nil
	}
	defer syscall.RegCloseKey(h)
	var names []string
	for i := uint32(0); ; i++ {
		buf := make([]uint16, 512)
		n := uint32(len(buf))
		r, _, _ := procRegEnumValueW.Call(uintptr(h), uintptr(i), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0, 0, 0, 0)
		if r != 0 {
			return names
		}
		names = append(names, syscall.UTF16ToString(buf[:n]))
	}
}
