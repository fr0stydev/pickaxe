# Build verification

Verification environment:

- Host: macOS arm64
- Builder: Debian `bookworm-slim` container
- Native compiler: MinGW-w64 x86_64 GCC
- Managed compiler: Mono `mcs`, .NET Framework 4 profile

Static checks:

- `powerpick-probe.x64.o` is an Intel amd64 COFF object exporting `go`
- `PowerPickProbe.exe` is a PE32 Mono/.NET assembly
- No AMSI/ETW patch identifiers in the native object or sources
- Unresolved BOF symbols limited to Beacon APIs and ordinary Win32/CLR imports

Runtime validation remains mandatory on a disposable x64 Windows Adaptix agent.
