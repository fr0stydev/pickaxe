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
powerpick-load ~/opt/PowerView.ps1
powerpick-load ~/opt/PowerView.ps1 recon
powerpick --imports Get-ComputerInfo
powerpick-unload all
```

`powerpick-load` defaults the import name to the script basename
(`PowerView.ps1` → `powerview`). Pass a second argument to override. Reloading the
same name replaces the cached body.

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

