# Third-party notices

The native CLR host is derived from:

- Adaptix-Framework/Extension-Kit
- `Execution-BOF/execute-assembly/inlineExecute-Assembly.c`
- `Execution-BOF/execute-assembly/inlineExecute-Assembly.h`

That project is licensed under GPL-3.0. Its license is included as `LICENSE`.

The managed PowerShell host is newly written for this project. It uses the
public `System.Management.Automation` API but does not redistribute the
Microsoft assembly used as a build-time reference.
