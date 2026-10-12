package main

import (
	"strings"
	"testing"
	"time"
)

// The first three lines are verbatim from a CbsPersist log on the development
// machine. The corruption lines follow the publicly documented [SR] format;
// no corrupt system was available to capture them from.
const sampleLog = "\ufeff" + `2026-10-11 06:36:37, Info                  CSI    00000007 [SR] Verifying 1 components
2026-10-11 06:36:37, Info                  CSI    00000008 [SR] Beginning Verify and Repair transaction
2026-10-11 06:36:37, Info                  CSI    00000009 [SR] Verify complete
2026-10-11 06:36:38, Info                  CBS    Unrelated line mentioning nothing
2026-10-11 06:36:40, Info                  CSI    0000000a [SR] Cannot repair member file [l:10]'opencl.dll' of microsoft-windows-RemoteFX-clientVM-RemoteFXWinRTDrv, version 10.0.26100.1, arch amd64, nonSxS, pkt {l:8 b:31bf3856ad364e35} in the store, hash mismatch
2026-10-11 06:36:41, Info                  CSI    0000000b [SR] This component was referenced by [l:74]'Package_1_for_KB1~31bf3856ad364e35~amd64~~10.0.1.0.KB1-1_neutral'
2026-10-11 06:36:42, Info                  CSI    0000000c [SR] Repairing corrupted file \??\C:\WINDOWS\System32\\[l:9]'utilman.exe' from store
2026-10-11 06:36:43, Info                  CSI    0000000d [SR] Could not reproject corrupted file \??\C:\WINDOWS\SysWOW64\\[l:10]'opencl.dll'; source file in store is also corrupted
2026-10-11 06:36:44, Info                  CSI    0000000e [SR] Repair complete
2026-10-11 09:00:00, Info                  CSI    0000000f [SR] Verifying 100 components
2026-10-11 09:00:05, Info                  CSI    00000010 [SR] Verify complete
`

func TestParseAndSummarize(t *testing.T) {
	evs, err := readSREvents(strings.NewReader(sampleLog))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 10 {
		t.Fatalf("got %d events, want 10", len(evs))
	}
	wantKinds := []string{KindVerifyStart, KindOther, KindVerifyComplete, KindCannotRepair, KindReferencedBy,
		KindRepairing, KindReprojectFail, KindRepairComplete, KindVerifyStart, KindVerifyComplete}
	for i, k := range wantKinds {
		if evs[i].Kind != k {
			t.Errorf("event %d: kind %q, want %q (%s)", i, evs[i].Kind, k, evs[i].Message)
		}
	}
	if evs[3].File != "opencl.dll" || evs[3].Reason != "hash mismatch" {
		t.Errorf("cannot-repair parsed as file=%q reason=%q", evs[3].File, evs[3].Reason)
	}
	if evs[5].File != `C:\WINDOWS\System32\utilman.exe` {
		t.Errorf("repairing parsed as file=%q", evs[5].File)
	}

	first := summarize(evs[:8])
	if first.ComponentsVerified != 1 || len(first.Files) != 3 || first.unrepaired() != 2 {
		t.Errorf("summary = %+v", first)
	}

	last := lastRun(evs, 30*time.Minute)
	if len(last) != 2 || summarize(last).ComponentsVerified != 100 {
		t.Errorf("lastRun kept %d events", len(last))
	}
	if got := eventsSince(evs, evs[8].Time); len(got) != 2 {
		t.Errorf("eventsSince kept %d events", len(got))
	}
}

// The Corrupt lines are verbatim from a verify-only scan on the development
// machine; the other three follow the remaining [Pnp] templates in wrpint.dll.
const pnpLog = `2026-10-12 21:10:59, Info                  CBS    TiWorker: Client requests SFP repair object.
2026-10-12 21:11:01, Info                  CSI    00000007 [SR] Verifying 100 components
2026-10-12 21:11:30, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\old.sys
2026-10-12 21:12:00, Info                  CBS    TiWorker: Client requests SFP repair object.
2026-10-12 21:12:07, Info                  CSI    00000210 [SR] Verify complete
2026-10-12 21:12:07, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\BthA2dp.sys
2026-10-12 21:12:08, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\system32\DRIVERS\usbvideo.sys
2026-10-12 21:12:09, Info                  DEPLOY [Pnp] Repaired file: C:\WINDOWS\System32\drivers\usbvideo.sys
2026-10-12 21:12:09, Info                  DEPLOY [Pnp] Failed repairing file: C:\WINDOWS\System32\drivers\BthA2dp.sys
2026-10-12 21:12:09, Info                  DEPLOY [Pnp] Failed verifying file: C:\WINDOWS\System32\drivers\x.sys
`

func TestDriverLines(t *testing.T) {
	evs, err := readSREvents(strings.NewReader(pnpLog))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 10 {
		t.Fatalf("got %d events, want 10", len(evs))
	}
	// The two scans are a minute apart; only the start marker separates them.
	evs = lastRun(evs, 30*time.Minute)
	sum := summarize(evs)
	if len(sum.Files) != 3 || sum.unrepaired() != 2 {
		t.Fatalf("summary = %+v", sum)
	}
	if f := sum.Files[1]; !f.Repaired || !strings.HasSuffix(f.File, "usbvideo.sys") {
		t.Errorf("usbvideo not marked repaired: %+v", f)
	}
	if f := sum.Files[0]; f.Repaired || f.Reason != "driver repair failed" {
		t.Errorf("BthA2dp: %+v", f)
	}
}

func TestClassify(t *testing.T) {
	msgs := sfcMessages{
		msgNoViolations:    "\r\nWindows Resource Protection did not find any integrity violations.",
		msgMetadataCorrupt: "Windows Resource Protection did not find any integrity violations but cannot\r\nguarantee the integrity",
		msgViolationsFound: " \r\nWindows Resource Protection found integrity violations.\r\nFor online repairs, details",
		msgRepaired:        "\r\nWindows Resource Protection found corrupt files and successfully repaired them.\r\nFor online",
		msgUnableToFixSome: "\r\nWindows Resource Protection found corrupt files but was unable to fix some of them.\r\nFor",
		msgNotAdmin:        "\r\nYou must be an administrator running a console session in order to \r\nuse the sfc utility.",
		msgProgress:        "Verification %1!u!%% complete.%0",
	}
	cases := map[string]Outcome{
		"Windows Resource Protection did not find any integrity violations.\n":                    OutcomeClean,
		"Windows Resource Protection did not find any integrity violations but cannot\nguarantee": OutcomeMetadataCorrupt,
		"Windows Resource Protection found integrity violations.\nFor online repairs":             OutcomeViolations,
		"Windows Resource Protection found corrupt files and successfully repaired them.\n":       OutcomeRepaired,
		"Windows Resource Protection found corrupt files but was unable to fix some of them.\n":   OutcomeUnrepaired,
		"You must be an administrator running a console session in order to\nuse the sfc utility": OutcomeNotElevated,
		"something unexpected": OutcomeEngineError,
	}
	for out, want := range cases {
		if got := msgs.classify(out); got != want {
			t.Errorf("classify(%q) = %s, want %s", out, got, want)
		}
	}
	if m := msgs.progressRe().FindStringSubmatch("Verification 42% complete."); m == nil || m[1] != "42" {
		t.Errorf("progress regexp did not match: %v", m)
	}
}
