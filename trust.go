package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// The quick check asks a different question from the WRP engine: not "does
// this file match its component manifest in WinSxS" but "does any installed
// security catalog, or an embedded signature, vouch for these exact bytes".
// It needs no elevation and never starts TrustedInstaller.

var (
	wintrust = syscall.NewLazyDLL(filepath.Join(systemDir(), "wintrust.dll"))

	procWinVerifyTrust              = wintrust.NewProc("WinVerifyTrust")
	procCATAdminAcquireContext2     = wintrust.NewProc("CryptCATAdminAcquireContext2")
	procCATAdminReleaseContext      = wintrust.NewProc("CryptCATAdminReleaseContext")
	procCATAdminCalcHash2           = wintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCATAdminEnumCatalogFromHash = wintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCATCatalogInfoFromContext   = wintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCATAdminReleaseCatalogCtx   = wintrust.NewProc("CryptCATAdminReleaseCatalogContext")
)

type guid struct {
	d1 uint32
	d2 uint16
	d3 uint16
	d4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2
var actionGenericVerifyV2 = guid{0x00AAC56B, 0xCD44, 0x11d0, [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE}}

type wintrustFileInfo struct {
	cbStruct     uint32
	filePath     *uint16
	hFile        syscall.Handle
	knownSubject *guid
}

type wintrustCatalogInfo struct {
	cbStruct       uint32
	catalogVersion uint32
	catalogPath    *uint16
	memberTag      *uint16
	memberPath     *uint16
	hMemberFile    syscall.Handle
	fileHash       *byte
	cbFileHash     uint32
	catalogContext uintptr
	hCatAdmin      uintptr
}

type wintrustData struct {
	cbStruct           uint32
	policyCallbackData uintptr
	sipClientData      uintptr
	uiChoice           uint32
	revocationChecks   uint32
	unionChoice        uint32
	info               unsafe.Pointer
	stateAction        uint32
	hWVTStateData      syscall.Handle
	urlReference       *uint16
	provFlags          uint32
	uiContext          uint32
	signatureSettings  uintptr
}

type catalogInfo struct {
	cbStruct    uint32
	catalogFile [syscall.MAX_PATH]uint16
}

const (
	wtdUINone               = 2
	wtdChoiceFile           = 1
	wtdChoiceCatalog        = 2
	wtdStateVerify          = 1
	wtdStateClose           = 2
	wtdRevocationCheckNone  = 0x10
	wtdCacheOnlyURL         = 0x1000
	trustENoSignature       = 0x800B0100
	trustEBadDigest         = 0x80096010
	trustESubjectFormUnkown = 0x800B0003
	trustEProviderUnknown   = 0x800B0001
)

func winVerifyTrust(choice uint32, info unsafe.Pointer) uint32 {
	d := wintrustData{
		uiChoice:    wtdUINone,
		unionChoice: choice,
		info:        info,
		stateAction: wtdStateVerify,
		provFlags:   wtdRevocationCheckNone | wtdCacheOnlyURL,
	}
	d.cbStruct = uint32(unsafe.Sizeof(d))
	invalidHandle := ^uintptr(0)
	r, _, _ := procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))
	d.stateAction = wtdStateClose
	procWinVerifyTrust.Call(invalidHandle, uintptr(unsafe.Pointer(&actionGenericVerifyV2)), uintptr(unsafe.Pointer(&d)))
	return uint32(r)
}

// Trust statuses, ordered from fine to worst.
const (
	TrustCatalog  = "catalog-signed"
	TrustEmbedded = "embedded-signed"
	TrustUnsigned = "unsigned"
	TrustError    = "error"
	TrustTampered = "digest-mismatch"
)

type TrustResult struct {
	File    string `json:"file"`
	Status  string `json:"status"`
	Catalog string `json:"catalog,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type catAdmin struct{ handles []uintptr }

// newCatAdmin opens one catalog context per hash algorithm in use: current
// catalogs are SHA-256, a few carried-over ones are still SHA-1.
func newCatAdmin() *catAdmin {
	c := &catAdmin{}
	for _, alg := range []string{"SHA256", "SHA1"} {
		a, _ := syscall.UTF16PtrFromString(alg)
		var h uintptr
		if r, _, _ := procCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&h)), 0, uintptr(unsafe.Pointer(a)), 0, 0); r != 0 {
			c.handles = append(c.handles, h)
		}
	}
	return c
}

func (c *catAdmin) close() {
	for _, h := range c.handles {
		procCATAdminReleaseContext.Call(h, 0)
	}
}

func (c *catAdmin) verify(path string) TrustResult {
	res := TrustResult{File: path}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		res.Status, res.Detail = TrustError, err.Error()
		return res
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		res.Status, res.Detail = TrustError, err.Error()
		return res
	}
	defer syscall.CloseHandle(h)

	for _, admin := range c.handles {
		hash := make([]byte, 64)
		n := uint32(len(hash))
		if r, _, _ := procCATAdminCalcHash2.Call(admin, uintptr(h), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&hash[0])), 0); r == 0 {
			continue
		}
		hash = hash[:n]
		ctx, _, _ := procCATAdminEnumCatalogFromHash.Call(admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(n), 0, 0)
		if ctx == 0 {
			continue
		}
		var ci catalogInfo
		ci.cbStruct = uint32(unsafe.Sizeof(ci))
		ok, _, _ := procCATCatalogInfoFromContext.Call(ctx, uintptr(unsafe.Pointer(&ci)), 0)
		procCATAdminReleaseCatalogCtx.Call(admin, ctx, 0)
		if ok == 0 {
			continue
		}
		tag, _ := syscall.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
		info := wintrustCatalogInfo{
			catalogPath: &ci.catalogFile[0],
			memberTag:   tag,
			memberPath:  p,
			hMemberFile: h,
			fileHash:    &hash[0],
			cbFileHash:  n,
			hCatAdmin:   admin,
		}
		info.cbStruct = uint32(unsafe.Sizeof(info))
		res.Catalog = filepath.Base(syscall.UTF16ToString(ci.catalogFile[:]))
		if code := winVerifyTrust(wtdChoiceCatalog, unsafe.Pointer(&info)); code != 0 {
			res.Status, res.Detail = TrustError, fmt.Sprintf("catalog found but not trusted (0x%08X)", code)
			return res
		}
		res.Status = TrustCatalog
		return res
	}

	info := wintrustFileInfo{filePath: p, hFile: h}
	info.cbStruct = uint32(unsafe.Sizeof(info))
	switch code := winVerifyTrust(wtdChoiceFile, unsafe.Pointer(&info)); code {
	case 0:
		res.Status = TrustEmbedded
	case trustENoSignature, trustESubjectFormUnkown, trustEProviderUnknown:
		res.Status, res.Detail = TrustUnsigned, "no catalog lists this file's hash and it carries no signature"
	case trustEBadDigest:
		res.Status, res.Detail = TrustTampered, "contents no longer match the embedded signature"
	default:
		res.Status, res.Detail = TrustError, fmt.Sprintf("signature not trusted (0x%08X)", code)
	}
	return res
}

var quickExts = map[string]bool{".exe": true, ".dll": true, ".sys": true, ".ocx": true, ".cpl": true, ".drv": true, ".scr": true, ".efi": true, ".winmd": true}

func defaultQuickRoots() []string {
	return []string{systemDir(), filepath.Join(systemDir(), "drivers"), filepath.Join(windowsDir(), "SysWOW64")}
}

// collectFiles expands roots into the binaries to check. A root that is a
// file is taken as-is whatever its extension.
func collectFiles(roots []string, recursive bool) ([]string, []string) {
	var files, problems []string
	seen := map[string]bool{}
	add := func(p string) {
		if k := strings.ToLower(p); !seen[k] {
			seen[k] = true
			files = append(files, p)
		}
	}
	for _, root := range roots {
		st, err := os.Stat(root)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if !st.IsDir() {
			add(root)
			continue
		}
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				if d != nil && d.IsDir() && p != root {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != root && !recursive {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() && quickExts[strings.ToLower(filepath.Ext(p))] {
				add(p)
			}
			return nil
		})
	}
	return files, problems
}

func verifyFiles(files []string, onDone func(done int)) []TrustResult {
	results := make([]TrustResult, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			admin := newCatAdmin()
			defer admin.close()
			for i := range jobs {
				results[i] = admin.verify(files[i])
				mu.Lock()
				done++
				if onDone != nil {
					onDone(done)
				}
				mu.Unlock()
			}
		}()
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	sort.SliceStable(results, func(a, b int) bool { return strings.ToLower(results[a].File) < strings.ToLower(results[b].File) })
	return results
}
