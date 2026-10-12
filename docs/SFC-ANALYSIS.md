# How `sfc.exe` works — evidence

Target: `C:\Windows\System32\sfc.exe`, 64-bit, file version 10.0.26100.7019,
SHA-256 `87157ECC458070731958B9954B7C170E36807A672E3FDA2A5413F4062CCD1D3B`,
catalog-signed by Microsoft Windows. Analysed 2026-10-12 on Windows 11 build 26300.

**Method.** Static analysis with `objdump` (disassembly), a `pefile` script
(headers, imports, strings, message table) and the registry (COM class lookup),
plus one unelevated run. The REA MCP server and Ghidra were not available in the
session, so nothing here is REA Evidence and there is no decompiler output. No
PDB was downloaded: function names below are addresses, and descriptions of what
a function does are read from its imports, strings and call arguments.

Each claim is marked **[observed]** (read directly from bytes or a run),
**[inferred]** (reasoned from observations) or **[unknown]**.

## 1. `sfc.exe` checks nothing itself

**[observed]** The import table has no hashing, crypto, catalog or directory
enumeration API. It imports `CoCreateInstance`, registry readers, file-mapping
calls, `LoadLibraryExW`/`GetProcAddress`, and CRT string functions.

**[observed]** The worker function at `0x140003a74` creates one COM object:

```
140003b0c  lea r9,  [0x140013f28]   ; IID   {90ED9FAA-A6E5-4671-8E50-1C060F8B9C47}
140003b18  lea rcx, [0x140013f38]   ; CLSID {8F5DF053-3013-4DD8-B5F4-88214E81C0CF}
140003b1f  lea r8d, [rdx+0x15]      ; CLSCTX 0x15 (in-proc | local server)
140003b23  call CoCreateInstance
```

**[observed]** Registry on this machine resolves those to:

| GUID | Registry name |
| --- | --- |
| CLSID `{8F5DF053-…}` | `SFP Repair Class`, AppID `{752073A2-23F2-4396-85F0-8FDB879ED0ED}` |
| AppID `{752073A2-…}` | `Trusted Installer Service`, `LocalService = TrustedInstaller` |
| IID `{90ED9FAA-…}` | `ISFPIntegrityCheckAndRepair` |
| IID `{E51873C8-…}` | `ISFPProgressCallback` |

**[inferred]** So the scan and repair run inside the TrustedInstaller service
(Windows Modules Installer); `sfc.exe` is a console front end for it.
`wrpint.dll` in the servicing stack exports only `SfpInitialize`/`SfpFinalize`,
consistent with it hosting that class. The verification algorithm itself lives
there and was **not** analysed.

## 2. Start-up and argument parsing (`0x140009c00`)

**[observed]**, in order:

1. `_setmode(stdout, 0x20000)` — output is UTF-16. Confirmed by a run: piped
   output starts `0D 00 0D 00 0A 00 59 00 6F 00 …`.
2. `AllocateAndInitializeSid(…, 0x20, 0x220)` + `CheckTokenMembership` — the
   BUILTIN\Administrators check. Failure prints message `0x40001005`.
3. `argc < 2` prints usage (`0x40001001`).
4. `CoInitializeEx(NULL, 2)`; failure prints `0x4000100E`.
5. Each argument must start with `-` or `/`. `SCANNOW`→mode 1 and
   `VERIFYONLY`→mode 2 are matched whole (`_wcsicmp`); `SCANFILE=`→3,
   `VERIFYFILE=`→4, `OFFBOOTDIR=`, `OFFWINDIR=`, `OFFLOGFILE=` by prefix
   (`_wcsnicmp`) followed by `=`. A second mode switch, or one offline directory
   without the other, falls through to usage.
6. `OFFLOGFILE` is implemented by setting environment variables
   `WINDOWS_TRACING_FLAGS=3` and `WINDOWS_TRACING_LOGFILE=<path>`.
7. Exit code is `worker_result == 0 ? 1 : 0`.

## 3. The two engine calls

**[observed]** Modes 1/2 call vtable slot `+0x18`, modes 3/4 call slot `+0x20`:

```
; scan all (0x140003c37)                    ; scan one file (0x140003ba9)
rdx      = offline dirs {boot, win} or NULL  rdx      = offline dirs or NULL
r8b      = (mode == 1)   ; repair?           r8       = file path
r9       = 0                                 r9b      = (mode == 3)   ; repair?
[rsp+20] = &reboot_required                  [rsp+28] = &reboot_required
[rsp+28] = &stats                            [rsp+30] = &stats
[rsp+38] = progress callback                 no callback
```

**[inferred]** The meaning of each argument comes from how the values are used
afterwards (section 4), not from a header; the interface is undocumented.

**[observed]** The progress callback object (vtable `0x140013038`) answers
`QueryInterface` for `IUnknown` and `ISFPProgressCallback`; its method at
`0x140007670` prints `0x40001011` ("Beginning verification phase") and
`0x40001012` ("Verification %1!u!%% complete.").

## 4. Result → message mapping (`0x140005c40`)

**[observed]** Every outcome is one message from the `RT_MESSAGETABLE` in
`en-US\sfc.exe.mui` (22 messages, `0x40001000`–`0x40001015`). `stats[0]` and
`stats[1]` are compared for equality; **[inferred]** they are corrupt-found and
repaired counts.

| Condition | Message |
| --- | --- |
| success or `0x80073701`, `stats[0]==0` | `…100A` no violations — or `…1015` "metadata is corrupt, run DISM" when hr is `0x80073701` |
| success, corrupt found, verify mode | `…100B` found integrity violations |
| success, repair mode, `stats[0]==stats[1]` | `…1008` repaired |
| success, repair mode, counts differ | `…1009` unable to fix some |
| …then `stats[4]` set | `…1003` / `…1004` per-run repair limit reached |
| …else reboot flag set | `…1002` takes effect after reboot |
| file mode and `0xD0000034` | `…100C` not a protected system file |
| `0x8000000A` | `…100D` repair pending, reboot |
| `0x80042000` / `0x80042001` / `0x80042002` | `…100F` offline dir is online / `…1010` arch mismatch / `…1013` servicing busy |
| any other failure | `…1007` could not perform the requested operation |

**[observed]** A completed scan that found unrepairable corruption and a clean
scan both exit 0. Unelevated run: exit code 1 with message `…1005`.

## 5. Offline images

**[observed]** With both offline directories, `CoCreateInstance` is skipped and
`0x14000e900` runs instead. Functions it reaches reference `system32\ssshim.dll`,
`syswow64\ssshim.dll`, `CopyFileW`, `GetTempPathW`, `LoadLibraryExW`,
`SssBindServicingStack`, `SssGetServicingStackFilePath`, `wrpint.dll`,
`SfpInitialize`, `SfpFinalize`.

**[inferred]** Offline, sfc copies the image's servicing-stack shim to a temp
directory, binds the offline image's own servicing stack, and hosts the engine
in-process. The exact call order was not traced.

## 6. Telemetry

**[observed]** `0x14000b434`, called first by the worker, reads `CEIPEnable`
under `SOFTWARE\Microsoft\SQMClient\Windows` and resolves 17 `Sqm*` exports from
`sqmapi.dll`. Other functions reference `CBS.log`, `CBS.persist.log`, `[SR]`,
`strstr`/`strtok`, `%%SystemRoot%%\Temp\SfcSQM_%u.sqm`, a WinSAT disk-throughput
query, and `http://sqm.microsoft.com/sqm/Windows/sqmserver.dll`.

**[inferred]** sfc re-reads the `[SR]` lines of the CBS log to build a CEIP
upload — it parses the per-file details for Microsoft but never shows them to
the user. **[unknown]** whether this path still runs when CEIP is off, and
whether `sqmapi.dll` is functional on this build.

## 7. The driver check logs under a second tag

**[observed]** A verify-only scan on the analysis machine ended with message
`…100B` (violations found) while the CBS log held no `[SR]` line other than
`Verifying N components` / `Verify complete`. The findings were five lines of
the form:

```
2026-10-12 21:12:07, Info                  DEPLOY [Pnp] Corrupt file: C:\WINDOWS\System32\drivers\BthA2dp.sys
```

**[observed]** `wrpint.dll` contains exactly four such templates:
`[Pnp] Corrupt file: {0}`, `[Pnp] Repaired file: {0}`,
`[Pnp] Failed repairing file: {0}`, `[Pnp] Failed verifying file: {0}`.

**[inferred]** After the component pass the engine checks driver files against
the driver store. Anyone following the usual advice to search CBS.log for
`[SR]` misses these entirely. **[unknown]** what the check compares: two of the
five flagged files carry a valid embedded Microsoft signature.

## 8. Not established

- How TrustedInstaller verifies a file (hash algorithm, manifest lookup).
- Exact layout of the stats structure beyond offsets 0, 4 and 0x10.
- Real `[SR]` corruption lines: this machine's logs contain only clean
  `Verifying N components` / `Verify complete` entries. Only the `[Pnp] Corrupt
  file` line has been seen for real.

## What this means for ngsfc

| sfc.exe weakness (evidence) | ngsfc |
| --- | --- |
| Exit code 0 whether clean or corrupt (§2, §4) | Distinct exit codes per outcome |
| "Details are in CBS.log" — a multi-MB servicing log (§4) | Prints the flagged files, reason and repair state |
| Localised free text only | `--json`; outcome matched against sfc's own message table, so it is language-independent |
| Tells you to run DISM yourself (`…1015`) | `--escalate` runs DISM then rescans |
| Admin-only for everything (§2) | `report`, `status` and `quick` run unelevated |
| No second opinion | `quick`: catalog/Authenticode sweep, ~7,700 files in ~8 s |

ngsfc still uses the Windows engine for `scan`/`file` by driving `sfc.exe`. It
does not call `ISFPIntegrityCheckAndRepair` directly: the signature above is
inferred from one caller, and a wrong guess would be executed inside a SYSTEM
service.
