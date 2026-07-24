# PowerPick-BOF

Inline Windows PowerShell host for AdaptixC2 agents (Beacon / Gopher / Kharon).

## Commands

| Command | Purpose |
|---|---|
| `powerpick [--imports] <expr>` | Run PowerShell in the agent process |
| `powerpick-load SCRIPT [name]` | Cache a `.ps1` on the agent for later use |
| `powerpick-loads` | List session imports |
| `powerpick-unload <name\|all>` | Drop cached imports |

```text
powerpick ls
powerpick "Get-Date"
powerpick-load ~/tools/PowerView.ps1
powerpick --imports Get-ComputerDetail
powerpick-unload all
```

`--imports` re-applies every session-loaded script into a fresh runspace before
the command. Omit it for normal one-liners.

## Build

Requires a build-time reference to `System.Management.Automation.dll` (not
shipped).

```sh
make SMA_REF=/path/to/System.Management.Automation.dll
```

Or with Docker:

```sh
docker build -t powerpick-bof-builder powerpick-bof
docker run --rm \
  -v "$PWD:/src" \
  -w /src/powerpick-bof \
  powerpick-bof-builder \
  make SMA_REF=/src/path/to/System.Management.Automation.dll
```

Artifacts:

```text
_bin/powerpick-probe.x64.o
_bin/PowerPickProbe.exe
```

Load `powerpick-probe.axs` in the Adaptix AxScript manager.

## Limits

- Script / combined import size: 2 MiB
- Managed deadline: 180 seconds
- Output cap: 256 KiB of characters
- x64 agents only
- Pipeline / `Write-Output` captured; `Write-Host` is not
- No AMSI/ETW patching
- Inline BOF: a crash can kill the agent; test in a disposable lab

## Provenance

Native CLR host derived from Adaptix Extension-Kit `inlineExecute-Assembly`
(GPL-3.0); AMSI/ETW patch paths removed. See `NOTICE.md` and `LICENSE`.
