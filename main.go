// ngsfc - Next Gen System File Checker.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const usageText = `ngsfc - Next Gen System File Checker

Usage:
  ngsfc scan   [--repair] [--escalate] [--json]   verify (and repair) all protected files
  ngsfc file   [--repair] [--json] <path>         verify (and repair) one protected file
  ngsfc report [--all] [--log <path>] [--json]    list the files the last scan flagged, from CBS.log
  ngsfc quick  [--recursive] [--all] [--json] [<path>...]
                                                  signature sweep of system binaries; no elevation
  ngsfc status [--json]                           elevation, pending reboot, servicing stack, last scan

scan and file also take --offwindir, --offbootdir and --offlogfile for an offline image.

Exit codes:
  0 clean   1 corruption found and fully repaired   2 corruption found, not (all) repaired
  3 retry later (reboot pending / servicing busy)   4 needs an elevated console
  5 engine error   6 component store metadata corrupt (run DISM /RestoreHealth)   64 usage
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(ExitUsage)
	}
	cmds := map[string]func([]string) int{
		"scan": cmdScan, "file": cmdFile, "report": cmdReport, "quick": cmdQuick, "status": cmdStatus,
	}
	switch os.Args[1] {
	case "-h", "--help", "help", "/?":
		fmt.Print(usageText)
		return
	}
	cmd, ok := cmds[strings.ToLower(os.Args[1])]
	if !ok {
		fmt.Fprintf(os.Stderr, "ngsfc: unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(ExitUsage)
	}
	os.Exit(cmd(os.Args[2:]))
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("ngsfc "+name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	return fs
}

func parse(fs *flag.FlagSet, args []string) bool {
	if err := fs.Parse(args); err != nil {
		return false
	}
	return true
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func fail(code int, err error) int {
	fmt.Fprintln(os.Stderr, "ngsfc:", err)
	return code
}

func stderrIsTerminal() bool {
	st, err := os.Stderr.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

type offlineFlags struct{ winDir, bootDir, logFile string }

func (o *offlineFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&o.winDir, "offwindir", "", "offline Windows directory")
	fs.StringVar(&o.bootDir, "offbootdir", "", "offline boot directory")
	fs.StringVar(&o.logFile, "offlogfile", "", "log file for an offline run")
}

func (o *offlineFlags) args() ([]string, error) {
	if o.winDir == "" && o.bootDir == "" && o.logFile == "" {
		return nil, nil
	}
	if o.winDir == "" || o.bootDir == "" {
		return nil, errors.New("--offwindir and --offbootdir must be given together")
	}
	a := []string{"/OFFWINDIR=" + o.winDir, "/OFFBOOTDIR=" + o.bootDir}
	if o.logFile != "" {
		a = append(a, "/OFFLOGFILE="+o.logFile)
	}
	return a, nil
}

// ScanReport is the result of scan and file.
type ScanReport struct {
	EngineResult
	Target    string     `json:"target"`
	Repair    bool       `json:"repair"`
	Escalated bool       `json:"escalated,omitempty"`
	Seconds   float64    `json:"seconds"`
	Details   *SRSummary `json:"details,omitempty"`
}

// runEngine runs one sfc pass and attaches the [SR] lines it produced.
func runEngine(msgs sfcMessages, sfcArgs []string, offline bool, showProgress bool) (EngineResult, *SRSummary, error) {
	start := time.Now().Truncate(time.Second)
	var onProgress func(int)
	if showProgress {
		onProgress = func(pct int) { fmt.Fprintf(os.Stderr, "\rverifying... %3d%%", pct) }
	}
	res, err := runSfc(msgs, sfcArgs, onProgress)
	if showProgress {
		fmt.Fprint(os.Stderr, "\r                    \r")
	}
	if err != nil {
		return res, nil, err
	}
	switch res.Outcome {
	case OutcomeClean, OutcomeRepaired, OutcomeViolations, OutcomeUnrepaired, OutcomeMetadataCorrupt:
	default:
		return res, nil, nil
	}
	if offline {
		return res, nil, nil
	}
	path := filepath.Join(cbsLogDir(), "CBS.log")
	evs, err := readSRFile(path)
	if err != nil {
		return res, nil, nil
	}
	sum := summarize(eventsSince(evs, start))
	sum.Log = path
	return res, &sum, nil
}

func runDismRestoreHealth() error {
	fmt.Fprintln(os.Stderr, "ngsfc: repairing the component store with DISM /RestoreHealth...")
	cmd := exec.Command(filepath.Join(systemDir(), "dism.exe"), "/Online", "/Cleanup-Image", "/RestoreHealth")
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func runScan(target string, modeArg string, repair, escalate, asJSON bool, off offlineFlags) int {
	offArgs, err := off.args()
	if err != nil {
		return fail(ExitUsage, err)
	}
	msgs, err := loadSfcMessages()
	if err != nil {
		return fail(ExitEngine, err)
	}
	sfcArgs := append([]string{modeArg}, offArgs...)
	progress := !asJSON && stderrIsTerminal()
	began := time.Now()
	res, details, err := runEngine(msgs, sfcArgs, offArgs != nil, progress)
	if err != nil {
		return fail(ExitEngine, err)
	}
	rep := ScanReport{Target: target, Repair: repair}
	if escalate && offArgs == nil && (res.Outcome == OutcomeUnrepaired || res.Outcome == OutcomeMetadataCorrupt) {
		rep.Escalated = true
		if err := runDismRestoreHealth(); err != nil {
			fmt.Fprintln(os.Stderr, "ngsfc: DISM failed:", err)
		} else if res, details, err = runEngine(msgs, sfcArgs, false, progress); err != nil {
			return fail(ExitEngine, err)
		}
	}
	rep.EngineResult, rep.Details = res, details
	rep.Seconds = time.Since(began).Round(100 * time.Millisecond).Seconds()
	if asJSON {
		printJSON(rep)
	} else {
		printScan(rep)
	}
	return res.Outcome.exitCode()
}

var outcomeText = map[Outcome]string{
	OutcomeClean:           "No integrity violations.",
	OutcomeRepaired:        "Corruption found and repaired.",
	OutcomeViolations:      "Integrity violations found (verify only; nothing was changed).",
	OutcomeUnrepaired:      "Corruption found; some files could not be repaired.",
	OutcomeMetadataCorrupt: "No violations found, but component store metadata is corrupt, so the result is not trustworthy.",
	OutcomeNotSystemFile:   "Not a protected system file; Windows Resource Protection cannot verify it.",
	OutcomeRepairPending:   "A system repair is pending. Restart Windows, then run again.",
	OutcomeBusy:            "Another servicing or repair operation is running. Try again when it finishes.",
	OutcomeNotElevated:     "Needs an elevated (Run as administrator) console.",
	OutcomeEngineError:     "Windows Resource Protection could not perform the operation.",
}

func printScan(rep ScanReport) {
	fmt.Printf("%s  [%s, %.1fs]\n", outcomeText[rep.Outcome], rep.Outcome, rep.Seconds)
	if rep.Outcome == OutcomeEngineError {
		for _, m := range rep.Messages {
			fmt.Println("  sfc:", m)
		}
	}
	if rep.Details != nil {
		printSummary(*rep.Details)
	}
	if rep.RebootRequired {
		fmt.Println("Restart Windows to finish the repair.")
	}
	if rep.MoreRemaining {
		fmt.Println("The engine hit its per-run repair limit; run again to repair the rest.")
	}
	switch {
	case rep.Outcome == OutcomeViolations:
		fmt.Println("Next: re-run with --repair.")
	case (rep.Outcome == OutcomeUnrepaired || rep.Outcome == OutcomeMetadataCorrupt) && !rep.Escalated:
		fmt.Println("Next: re-run with --repair --escalate to repair the component store with DISM first.")
	}
}

func printSummary(s SRSummary) {
	if s.ComponentsVerified > 0 {
		fmt.Printf("Components verified: %d\n", s.ComponentsVerified)
	}
	if len(s.Files) > 0 {
		fmt.Printf("Files flagged: %d (%d not repaired)\n", len(s.Files), s.unrepaired())
		for _, f := range s.Files {
			state := "NOT REPAIRED"
			if f.Repaired {
				state = "repaired"
			}
			reason := ""
			if f.Reason != "" {
				reason = "  (" + f.Reason + ")"
			}
			fmt.Printf("  %-12s  %s%s\n", state, f.File, reason)
		}
	}
	for _, n := range s.Notes {
		fmt.Println("  note:", n)
	}
}

func cmdScan(args []string) int {
	fs := newFlags("scan")
	repair := fs.Bool("repair", false, "repair what is found")
	escalate := fs.Bool("escalate", false, "run DISM /RestoreHealth and rescan when repair fails")
	asJSON := fs.Bool("json", false, "JSON output")
	var off offlineFlags
	off.register(fs)
	if !parse(fs, args) || fs.NArg() != 0 {
		return ExitUsage
	}
	if *escalate {
		*repair = true
	}
	mode := "/VERIFYONLY"
	if *repair {
		mode = "/SCANNOW"
	}
	return runScan("all protected files", mode, *repair, *escalate, *asJSON, off)
}

func cmdFile(args []string) int {
	fs := newFlags("file")
	repair := fs.Bool("repair", false, "repair the file if it is corrupt")
	asJSON := fs.Bool("json", false, "JSON output")
	var off offlineFlags
	off.register(fs)
	if !parse(fs, args) || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "ngsfc file: exactly one path is required")
		return ExitUsage
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return fail(ExitUsage, err)
	}
	mode := "/VERIFYFILE=" + path
	if *repair {
		mode = "/SCANFILE=" + path
	}
	return runScan(path, mode, *repair, false, *asJSON, off)
}

func cmdReport(args []string) int {
	fs := newFlags("report")
	all := fs.Bool("all", false, "every scan in the log, not just the last one")
	logPath := fs.String("log", "", "log file to read instead of the live CBS log")
	asJSON := fs.Bool("json", false, "JSON output")
	if !parse(fs, args) || fs.NArg() != 0 {
		return ExitUsage
	}
	var evs []SREvent
	var err error
	path := *logPath
	if path != "" {
		evs, err = readSRFile(path)
	} else {
		path, evs, err = findSRLog()
	}
	if err != nil {
		return fail(ExitEngine, err)
	}
	if !*all {
		evs = lastRun(evs, 30*time.Minute)
	}
	sum := summarize(evs)
	sum.Log = path
	if *asJSON {
		printJSON(sum)
	} else if len(evs) == 0 {
		fmt.Printf("No scan activity recorded in %s.\n", path)
	} else {
		fmt.Printf("Log:  %s\nScan: %s to %s\n", path, sum.First.Format("2006-01-02 15:04:05"), sum.Last.Format("15:04:05"))
		printSummary(sum)
		if len(sum.Files) == 0 {
			fmt.Println("No files were flagged.")
		}
	}
	if sum.unrepaired() > 0 {
		return ExitViolations
	}
	return ExitClean
}

// QuickReport is the result of quick.
type QuickReport struct {
	Roots    []string       `json:"roots"`
	Checked  int            `json:"checked"`
	Seconds  float64        `json:"seconds"`
	Counts   map[string]int `json:"counts"`
	Findings []TrustResult  `json:"findings"`
	Problems []string       `json:"problems,omitempty"`
}

func cmdQuick(args []string) int {
	fs := newFlags("quick")
	recursive := fs.Bool("recursive", false, "descend into subdirectories")
	all := fs.Bool("all", false, "list every file, not only the ones that are not vouched for")
	asJSON := fs.Bool("json", false, "JSON output")
	if !parse(fs, args) {
		return ExitUsage
	}
	roots := fs.Args()
	if len(roots) == 0 {
		roots = defaultQuickRoots()
	}
	began := time.Now()
	files, problems := collectFiles(roots, *recursive)
	var onDone func(int)
	if !*asJSON && stderrIsTerminal() {
		onDone = func(done int) {
			if done%200 == 0 || done == len(files) {
				fmt.Fprintf(os.Stderr, "\rchecking signatures... %d/%d", done, len(files))
			}
		}
	}
	results := verifyFiles(files, onDone)
	if onDone != nil {
		fmt.Fprint(os.Stderr, "\r                                        \r")
	}
	rep := QuickReport{Roots: roots, Checked: len(results), Counts: map[string]int{}, Findings: []TrustResult{}, Problems: problems}
	for _, r := range results {
		rep.Counts[r.Status]++
		if *all || (r.Status != TrustCatalog && r.Status != TrustEmbedded) {
			rep.Findings = append(rep.Findings, r)
		}
	}
	rep.Seconds = time.Since(began).Round(100 * time.Millisecond).Seconds()
	if *asJSON {
		printJSON(rep)
	} else {
		printQuick(rep)
	}
	if rep.Counts[TrustTampered] > 0 {
		return ExitViolations
	}
	return ExitClean
}

func printQuick(rep QuickReport) {
	fmt.Printf("Checked %d files in %.1fs: ", rep.Checked, rep.Seconds)
	keys := make([]string, 0, len(rep.Counts))
	for k := range rep.Counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", rep.Counts[k], k))
	}
	fmt.Println(strings.Join(parts, ", "))
	for _, f := range rep.Findings {
		extra := f.Detail
		if extra == "" {
			extra = f.Catalog
		}
		fmt.Printf("  %-15s  %s", f.Status, f.File)
		if extra != "" {
			fmt.Printf("  (%s)", extra)
		}
		fmt.Println()
	}
	for _, p := range rep.Problems {
		fmt.Println("  skipped:", p)
	}
	if rep.Counts[TrustUnsigned] > 0 {
		fmt.Println("Unsigned files are not necessarily corrupt (third-party drivers and tools often are unsigned);")
		fmt.Println("this sweep does not compare files against the component store. Use `ngsfc scan` for that.")
	}
}

// Status is the result of status.
type Status struct {
	Elevated       bool       `json:"elevated"`
	OSBuild        string     `json:"os_build"`
	ServicingStack string     `json:"servicing_stack,omitempty"`
	RebootPending  []string   `json:"reboot_pending"`
	LastScan       *SRSummary `json:"last_scan,omitempty"`
}

const cbsKey = `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing`

func gatherStatus() Status {
	const nt = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	st := Status{Elevated: isElevated(), RebootPending: []string{}}
	st.OSBuild = regString(nt, "CurrentBuild")
	if ubr, ok := regDword(nt, "UBR"); ok {
		st.OSBuild += fmt.Sprintf(".%d", ubr)
	}
	// Same key sfc.exe enumerates to find the servicing stack.
	stacks := regValueNames(cbsKey + `\Version`)
	sort.Strings(stacks)
	if len(stacks) > 0 {
		st.ServicingStack = stacks[len(stacks)-1]
	}
	if regKeyExists(cbsKey + `\RebootPending`) {
		st.RebootPending = append(st.RebootPending, "Component Based Servicing reboot pending")
	}
	if _, err := os.Stat(filepath.Join(windowsDir(), "WinSxS", "pending.xml")); err == nil {
		st.RebootPending = append(st.RebootPending, "WinSxS\\pending.xml present")
	}
	if path, evs, err := findSRLog(); err == nil && len(evs) > 0 {
		sum := summarize(lastRun(evs, 30*time.Minute))
		sum.Log = path
		st.LastScan = &sum
	}
	return st
}

func cmdStatus(args []string) int {
	fs := newFlags("status")
	asJSON := fs.Bool("json", false, "JSON output")
	if !parse(fs, args) || fs.NArg() != 0 {
		return ExitUsage
	}
	st := gatherStatus()
	if *asJSON {
		printJSON(st)
		return ExitClean
	}
	w := io.Writer(os.Stdout)
	fmt.Fprintf(w, "Elevated:         %v\n", st.Elevated)
	fmt.Fprintf(w, "OS build:         %s\n", st.OSBuild)
	fmt.Fprintf(w, "Servicing stack:  %s\n", st.ServicingStack)
	if len(st.RebootPending) == 0 {
		fmt.Fprintln(w, "Reboot pending:   no")
	} else {
		fmt.Fprintf(w, "Reboot pending:   yes (%s)\n", strings.Join(st.RebootPending, "; "))
	}
	if st.LastScan == nil {
		fmt.Fprintln(w, "Last scan:        none recorded in the CBS logs")
	} else {
		fmt.Fprintf(w, "Last scan:        %s, %d components, %d files flagged (%d not repaired)\n",
			st.LastScan.Last.Format("2006-01-02 15:04:05"), st.LastScan.ComponentsVerified, len(st.LastScan.Files), st.LastScan.unrepaired())
	}
	return ExitClean
}
