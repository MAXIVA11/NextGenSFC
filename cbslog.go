package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SREvent is one "[SR]" line written to CBS.log by the Windows Resource
// Protection engine. sfc.exe only tells the user that "details are included in
// the CBS log"; these lines are those details.
type SREvent struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	File    string    `json:"file,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Message string    `json:"message"`
}

// Event kinds. The prefixes they are matched on are the same word sequences
// sfc.exe itself carries in .rdata for summarising the log.
const (
	KindScanStart      = "scan-start"
	KindVerifyStart    = "verify-start"
	KindVerifyComplete = "verify-complete"
	KindRepairStart    = "repair-start"
	KindRepairComplete = "repair-complete"
	KindCannotRepair   = "cannot-repair"
	KindCannotVerify   = "cannot-verify"
	KindRepairing      = "repairing"
	KindRepaired       = "repaired"
	KindReprojectFail  = "reproject-failed"
	KindManifestBackup = "manifest-recovered"
	KindReferencedBy   = "referenced-by"
	KindNotFound       = "component-not-found"
	KindDriverCorrupt  = "driver-corrupt"
	KindDriverRepaired = "driver-repaired"
	KindDriverFailed   = "driver-repair-failed"
	KindDriverUnverif  = "driver-verify-failed"
	KindOther          = "other"
)

var srPrefixes = []struct{ prefix, kind string }{
	{"Cannot repair member file", KindCannotRepair},
	{"Unable to repair", KindCannotRepair},
	{"Cannot verify component files for", KindCannotVerify},
	{"Could not reproject corrupted file", KindReprojectFail},
	{"Recovered manifest from backup for", KindManifestBackup},
	{"Repairing corrupted file", KindRepairing},
	{"Repaired file", KindRepaired},
	{"This component was referenced by", KindReferencedBy},
	{"Component not found:", KindNotFound},
	{"Verify complete", KindVerifyComplete},
	{"Repair complete", KindRepairComplete},
	{"Verifying", KindVerifyStart},
	{"Repairing", KindRepairStart},
}

// The engine also checks driver files against the driver store and logs those
// results under a different tag. These are the four templates in wrpint.dll.
var pnpPrefixes = []struct{ prefix, kind, reason string }{
	{"Corrupt file: ", KindDriverCorrupt, "failed driver store check"},
	{"Repaired file: ", KindDriverRepaired, ""},
	{"Failed repairing file: ", KindDriverFailed, "driver repair failed"},
	{"Failed verifying file: ", KindDriverUnverif, "driver file could not be verified"},
}

var (
	pnpLineRe  = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d), \w+\s+DEPLOY\s+\[Pnp\] (.*)$`)
	srLineRe   = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d), \w+\s+CSI\s+[0-9a-fA-F]+ \[SR\] (.*)$`)
	srNameRe   = regexp.MustCompile(`\[(?:ml|l):\d+(?:\{\d+\})?\]['"]([^'"]*)['"]`)
	srPathRe   = regexp.MustCompile(`(\\(?:\?\?|SystemRoot)\\[^\[]*)\[`)
	srReasonRe = regexp.MustCompile(`(hash mismatch|file is missing|file cannot be checked|manifest is damaged)`)
)

func parsePnpLine(line string) (SREvent, bool) {
	m := pnpLineRe.FindStringSubmatch(line)
	if m == nil {
		return SREvent{}, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
	if err != nil {
		return SREvent{}, false
	}
	ev := SREvent{Time: ts, Kind: KindOther, Message: m[2]}
	for _, p := range pnpPrefixes {
		if strings.HasPrefix(m[2], p.prefix) {
			ev.Kind, ev.Reason = p.kind, p.reason
			ev.File = strings.TrimSpace(strings.TrimPrefix(m[2], p.prefix))
			break
		}
	}
	return ev, true
}

// scanStartMarker is logged once per client of the repair service, i.e. once
// per sfc invocation, even when several run inside one TiWorker session.
const scanStartMarker = "Client requests SFP repair object"

func parseSRLine(line string) (SREvent, bool) {
	line = strings.TrimRight(line, "\r\n")
	if strings.Contains(line, scanStartMarker) && len(line) >= 19 {
		ts, err := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.Local)
		return SREvent{Time: ts, Kind: KindScanStart, Message: scanStartMarker}, err == nil
	}
	if strings.Contains(line, "[Pnp]") {
		return parsePnpLine(line)
	}
	m := srLineRe.FindStringSubmatch(line)
	if m == nil {
		return SREvent{}, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local)
	if err != nil {
		return SREvent{}, false
	}
	ev := SREvent{Time: ts, Kind: KindOther, Message: m[2]}
	for _, p := range srPrefixes {
		if strings.HasPrefix(m[2], p.prefix) {
			ev.Kind = p.kind
			break
		}
	}
	switch ev.Kind {
	case KindCannotRepair, KindRepairing, KindRepaired, KindReprojectFail:
		if n := srNameRe.FindStringSubmatch(m[2]); n != nil {
			dir := ""
			if p := srPathRe.FindStringSubmatch(m[2]); p != nil {
				dir = strings.TrimRight(strings.TrimPrefix(p[1], `\??\`), `\`) + `\`
			}
			ev.File = dir + n[1]
		}
	}
	if r := srReasonRe.FindString(m[2]); r != "" {
		ev.Reason = r
	}
	return ev, true
}

func readSREvents(r io.Reader) ([]SREvent, error) {
	var out []SREvent
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimPrefix(sc.Text(), "\ufeff")
		if !strings.Contains(line, "[SR]") && !strings.Contains(line, "[Pnp]") && !strings.Contains(line, scanStartMarker) {
			continue
		}
		if ev, ok := parseSRLine(line); ok {
			out = append(out, ev)
		}
	}
	return out, sc.Err()
}

func readSRFile(path string) ([]SREvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readSREvents(f)
}

func cbsLogDir() string {
	return filepath.Join(windowsDir(), "Logs", "CBS")
}

// findSRLog returns the events of the live CBS.log, or, when CBS has rotated
// it since the last scan, of the newest CbsPersist_*.log that still has any.
func findSRLog() (string, []SREvent, error) {
	live := filepath.Join(cbsLogDir(), "CBS.log")
	evs, err := readSRFile(live)
	if err != nil {
		return live, nil, err
	}
	if len(evs) > 0 {
		return live, evs, nil
	}
	persisted, _ := filepath.Glob(filepath.Join(cbsLogDir(), "CbsPersist_*.log"))
	sort.Sort(sort.Reverse(sort.StringSlice(persisted)))
	for _, p := range persisted {
		if evs, err := readSRFile(p); err == nil && len(evs) > 0 {
			return p, evs, nil
		}
	}
	return live, nil, nil
}

// lastRun trims evs to the most recent burst of activity: everything after the
// last gap longer than maxGap.
func lastRun(evs []SREvent, maxGap time.Duration) []SREvent {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Kind == KindScanStart {
			return evs[i:]
		}
	}
	for i := len(evs) - 1; i > 0; i-- {
		if evs[i].Time.Sub(evs[i-1].Time) > maxGap {
			return evs[i:]
		}
	}
	return evs
}

func eventsSince(evs []SREvent, t time.Time) []SREvent {
	i := sort.Search(len(evs), func(i int) bool { return !evs[i].Time.Before(t) })
	return evs[i:]
}

// FileFinding is the per-file verdict folded out of a run of events.
type FileFinding struct {
	File     string `json:"file"`
	Reason   string `json:"reason,omitempty"`
	Repaired bool   `json:"repaired"`
}

// SRSummary is what sfc.exe never prints: which files, why, and what happened.
type SRSummary struct {
	Log                string        `json:"log,omitempty"`
	First              *time.Time    `json:"first,omitempty"`
	Last               *time.Time    `json:"last,omitempty"`
	ComponentsVerified int           `json:"components_verified"`
	Files              []FileFinding `json:"files"`
	Notes              []string      `json:"notes,omitempty"`
}

var verifyingCountRe = regexp.MustCompile(`^Verifying (\d+) components`)

func summarize(evs []SREvent) SRSummary {
	s := SRSummary{Files: []FileFinding{}}
	if len(evs) > 0 {
		s.First, s.Last = &evs[0].Time, &evs[len(evs)-1].Time
	}
	idx := map[string]int{}
	seenNote := map[string]bool{}
	get := func(file string) *FileFinding {
		key := strings.ToLower(file)
		i, ok := idx[key]
		if !ok {
			i = len(s.Files)
			idx[key] = i
			s.Files = append(s.Files, FileFinding{File: file})
		}
		return &s.Files[i]
	}
	for _, ev := range evs {
		switch ev.Kind {
		case KindVerifyStart:
			if m := verifyingCountRe.FindStringSubmatch(ev.Message); m != nil {
				n := 0
				for _, c := range m[1] {
					n = n*10 + int(c-'0')
				}
				s.ComponentsVerified += n
			}
		case KindCannotRepair, KindReprojectFail, KindDriverCorrupt, KindDriverFailed, KindDriverUnverif:
			if ev.File == "" {
				break
			}
			f := get(ev.File)
			f.Repaired = false
			if ev.Reason != "" {
				f.Reason = ev.Reason
			}
		case KindRepairing, KindRepaired, KindDriverRepaired:
			if ev.File != "" {
				get(ev.File).Repaired = true
			}
		case KindCannotVerify, KindNotFound, KindManifestBackup:
			if !seenNote[ev.Message] {
				seenNote[ev.Message] = true
				s.Notes = append(s.Notes, ev.Message)
			}
		}
	}
	return s
}

func (s SRSummary) unrepaired() int {
	n := 0
	for _, f := range s.Files {
		if !f.Repaired {
			n++
		}
	}
	return n
}
