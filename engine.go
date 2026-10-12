package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// Message IDs from the RT_MESSAGETABLE of sfc.exe.mui. sfc.exe reports every
// outcome by printing exactly one of these, and collapses them all into exit
// code 0 or 1. Matching its output against the table it was printed from keeps
// the classification independent of the display language.
const (
	msgBeginScan       = 0x40001000
	msgUsage           = 0x40001001
	msgRebootToApply   = 0x40001002
	msgMaxQueuedReboot = 0x40001003
	msgMaxRepaired     = 0x40001004
	msgNotAdmin        = 0x40001005
	msgUnsupported     = 0x40001006
	msgCouldNotPerform = 0x40001007
	msgRepaired        = 0x40001008
	msgUnableToFixSome = 0x40001009
	msgNoViolations    = 0x4000100A
	msgViolationsFound = 0x4000100B
	msgNotSystemFile   = 0x4000100C
	msgRepairPending   = 0x4000100D
	msgNoRepairService = 0x4000100E
	msgOfflineIsOnline = 0x4000100F
	msgArchMismatch    = 0x40001010
	msgBeginVerify     = 0x40001011
	msgProgress        = 0x40001012
	msgServicingBusy   = 0x40001013
	msgLogSetupFailed  = 0x40001014
	msgMetadataCorrupt = 0x40001015
)

// Outcome is the single verdict of an engine run.
type Outcome string

const (
	OutcomeClean           Outcome = "clean"
	OutcomeRepaired        Outcome = "repaired"
	OutcomeViolations      Outcome = "violations-found"
	OutcomeUnrepaired      Outcome = "unrepaired"
	OutcomeMetadataCorrupt Outcome = "store-metadata-corrupt"
	OutcomeNotSystemFile   Outcome = "not-a-protected-file"
	OutcomeRepairPending   Outcome = "repair-pending-reboot"
	OutcomeBusy            Outcome = "servicing-busy"
	OutcomeNotElevated     Outcome = "not-elevated"
	OutcomeEngineError     Outcome = "engine-error"
)

// Exit codes. sfc.exe returns 0 for every completed scan, corrupt or not.
const (
	ExitClean      = 0
	ExitRepaired   = 1
	ExitViolations = 2
	ExitRetryLater = 3
	ExitNotAdmin   = 4
	ExitEngine     = 5
	ExitStoreBad   = 6
	ExitUsage      = 64
)

func (o Outcome) exitCode() int {
	switch o {
	case OutcomeClean:
		return ExitClean
	case OutcomeRepaired:
		return ExitRepaired
	case OutcomeViolations, OutcomeUnrepaired:
		return ExitViolations
	case OutcomeRepairPending, OutcomeBusy:
		return ExitRetryLater
	case OutcomeNotElevated:
		return ExitNotAdmin
	case OutcomeMetadataCorrupt:
		return ExitStoreBad
	}
	return ExitEngine
}

// Checked in order: a message whose first line is a prefix of another's must
// come after it.
var outcomeOrder = []struct {
	id      uint32
	outcome Outcome
}{
	{msgNotAdmin, OutcomeNotElevated},
	{msgRepairPending, OutcomeRepairPending},
	{msgServicingBusy, OutcomeBusy},
	{msgNotSystemFile, OutcomeNotSystemFile},
	{msgMetadataCorrupt, OutcomeMetadataCorrupt},
	{msgUnableToFixSome, OutcomeUnrepaired},
	{msgRepaired, OutcomeRepaired},
	{msgNoViolations, OutcomeClean},
	{msgViolationsFound, OutcomeViolations},
	{msgNoRepairService, OutcomeEngineError},
	{msgCouldNotPerform, OutcomeEngineError},
	{msgUnsupported, OutcomeEngineError},
	{msgOfflineIsOnline, OutcomeEngineError},
	{msgArchMismatch, OutcomeEngineError},
}

type sfcMessages map[uint32]string

func sfcPath() string { return filepath.Join(systemDir(), "sfc.exe") }

// loadSfcMessages reads sfc's message table in the current UI language. The
// module is mapped as a resource-only datafile; none of its code runs.
func loadSfcMessages() (sfcMessages, error) {
	const (
		loadAsDatafile      = 0x00000002
		loadAsImageResource = 0x00000020
		fromHModule         = 0x00000800
		ignoreInserts       = 0x00000200
	)
	p, err := syscall.UTF16PtrFromString(sfcPath())
	if err != nil {
		return nil, err
	}
	h, _, e := procLoadLibraryExW.Call(uintptr(unsafe.Pointer(p)), 0, loadAsDatafile|loadAsImageResource)
	if h == 0 {
		return nil, fmt.Errorf("mapping %s: %w", sfcPath(), e)
	}
	defer syscall.FreeLibrary(syscall.Handle(h))
	msgs := sfcMessages{}
	buf := make([]uint16, 8192)
	for id := uint32(msgBeginScan); id <= msgMetadataCorrupt; id++ {
		n, _, _ := procFormatMessageW.Call(fromHModule|ignoreInserts, h, uintptr(id), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
		if n > 0 {
			msgs[id] = syscall.UTF16ToString(buf[:n])
		}
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("%s has no readable message table", sfcPath())
	}
	return msgs, nil
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// firstLine is the first non-empty line of a message: enough to tell the
// messages apart, and free of the %-sequences later lines may carry.
func firstLine(s string) string {
	for _, l := range strings.FieldsFunc(s, func(r rune) bool { return r == '\r' || r == '\n' }) {
		if l = squash(l); l != "" {
			return l
		}
	}
	return ""
}

func (m sfcMessages) has(output string, id uint32) bool {
	key := firstLine(m[id])
	return key != "" && strings.Contains(squash(output), key)
}

func (m sfcMessages) classify(output string) Outcome {
	for _, o := range outcomeOrder {
		if m.has(output, o.id) {
			return o.outcome
		}
	}
	return OutcomeEngineError
}

func (m sfcMessages) progressRe() *regexp.Regexp {
	t := strings.TrimSpace(strings.ReplaceAll(m[msgProgress], "%0", ""))
	if !strings.Contains(t, "%1!u!") {
		return regexp.MustCompile(`(\d+)\s*%`)
	}
	q := regexp.QuoteMeta(t)
	q = strings.ReplaceAll(q, regexp.QuoteMeta("%1!u!"), `(\d+)`)
	q = strings.ReplaceAll(q, "%%", "%")
	return regexp.MustCompile(q)
}

// EngineResult is one run of the Windows Resource Protection engine.
type EngineResult struct {
	Outcome        Outcome  `json:"outcome"`
	RebootRequired bool     `json:"reboot_required"`
	MoreRemaining  bool     `json:"more_remaining"`
	SfcExitCode    int      `json:"sfc_exit_code"`
	Messages       []string `json:"messages"`
}

// runSfc drives sfc.exe, which is itself only a COM client of the
// TrustedInstaller service. Its stdout is UTF-16LE (_setmode(_O_U16TEXT)).
func runSfc(msgs sfcMessages, args []string, onProgress func(pct int)) (EngineResult, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return EngineResult{}, err
	}
	cmd := exec.Command(sfcPath(), args...)
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		w.Close()
		r.Close()
		return EngineResult{}, err
	}
	w.Close()

	progress := msgs.progressRe()
	var text strings.Builder
	var line []uint16
	flush := func() {
		s := strings.TrimSpace(string(utf16.Decode(line)))
		line = line[:0]
		if s == "" {
			return
		}
		if m := progress.FindStringSubmatch(s); m != nil {
			if pct, err := strconv.Atoi(m[1]); err == nil && onProgress != nil {
				onProgress(pct)
			}
			return
		}
		text.WriteString(s)
		text.WriteByte('\n')
	}
	buf := make([]byte, 4096)
	var odd []byte
	for {
		n, err := r.Read(buf)
		data := append(odd, buf[:n]...)
		for len(data) >= 2 {
			c := uint16(data[0]) | uint16(data[1])<<8
			data = data[2:]
			if c == '\r' || c == '\n' {
				flush()
			} else {
				line = append(line, c)
			}
		}
		odd = append([]byte(nil), data...)
		if err != nil {
			if err != io.EOF {
				return EngineResult{}, err
			}
			break
		}
	}
	flush()
	r.Close()

	res := EngineResult{Messages: []string{}}
	if err := cmd.Wait(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			return EngineResult{}, err
		}
		res.SfcExitCode = ee.ExitCode()
	}
	out := text.String()
	res.Outcome = msgs.classify(out)
	res.RebootRequired = msgs.has(out, msgRebootToApply) || msgs.has(out, msgMaxQueuedReboot)
	res.MoreRemaining = msgs.has(out, msgMaxQueuedReboot) || msgs.has(out, msgMaxRepaired)
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l != "" && !msgs.has(l, msgBeginScan) && !msgs.has(l, msgBeginVerify) {
			res.Messages = append(res.Messages, l)
		}
	}
	return res, nil
}
