# ngsfc — Next Gen System File Checker

A front end for Windows Resource Protection that tells you what `sfc.exe`
doesn't: which files, why, what happened to them, and an exit code you can
script against. Design rationale and the analysis of `sfc.exe` it is based on
are in [docs/SFC-ANALYSIS.md](docs/SFC-ANALYSIS.md).

```
go build -o ngsfc.exe .
go test ./...
```

Go 1.24+, standard library only.

| Command | Elevation | What it does |
| --- | --- | --- |
| `ngsfc scan [--repair] [--escalate]` | admin | Verify all protected files; `--repair` fixes them; `--escalate` runs DISM `/RestoreHealth` and rescans if repair fails |
| `ngsfc file [--repair] <path>` | admin | Same, for one file |
| `ngsfc report [--all] [--log <path>]` | none | Files the last scan flagged, read from the CBS log |
| `ngsfc quick [--recursive] [--all] [<path>...]` | none | Catalog / Authenticode signature sweep (default: System32, drivers, SysWOW64) |
| `ngsfc status` | none | Elevation, pending reboot, servicing stack, last scan |

All commands take `--json`. `scan` and `file` accept `--offwindir`,
`--offbootdir`, `--offlogfile` for offline images.

Exit codes: `0` clean · `1` corruption repaired · `2` corruption not (all)
repaired · `3` retry later (reboot pending / servicing busy) · `4` needs
elevation · `5` engine error · `6` component store metadata corrupt · `64` usage.

`quick` is not a substitute for `scan`: it checks that some installed catalog or
embedded signature vouches for a file's bytes, not that the file matches the
component store.
