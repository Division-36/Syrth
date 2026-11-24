# Security policy

SYRTH 1.1 is a static analyser. It reads source code and writes a report; it
does not decide whether code is vulnerable and it makes no network requests at
scan time.

## Trust boundaries

- **Scanned source is data.** It is parsed by tree-sitter and never evaluated,
  imported or executed. Findings are statements about sink contacts, not
  verdicts.
- **Repository walking** prunes `.git`, virtual environments and other noise
  directories, and refuses to read a file larger than 4 MiB. An oversized file
  is recorded in the report's errors, not read into memory.
- **`--patch-command` is opt-in and explicit.** It runs the command you name,
  split with `shlex.split` and without a shell. The source is written to a
  private temporary directory that is removed when the command returns. Do not
  pass a command you do not trust.
- **`--fix-apply` prints the patched source; it does not write files.** A patch
  is accepted only if the original flow is gone, no new flow appeared, and the
  file still parses.
- **No runtime secrets.** The package contains no credentials, tokens or
  endpoints. The corpus builder and benchmark harnesses are development tools,
  not part of the installed scanner.

## Supply chain

The default install has two runtime dependencies: `tree-sitter` and
`tree-sitter-python`. Version 1.1 is tested with 0.26.0 and 0.25.0;
`pip-audit` reports no known vulnerabilities for those two pins (checked
2026-11-24). Optional extras (`ml`, `explain`, `benchmark`) are not needed for
scanning.

Verify a local build as a standalone install:

```console
make smoke-install
```

This builds a fresh virtual environment, installs the package from the working
tree, and runs the CLI against a bundled fixture.

## Reporting a vulnerability

Open a private issue with the affected version, a minimal reproducer and the
expected versus observed behaviour. Do not publish an exploit before a fix is
available. Include the command line and the source snippet if the issue
concerns `--patch-command`.

## Scope

This policy covers the `syrth/` package and its CLI. The pre-registration
documents, published measurements and generated corpora are research
artefacts; they are reproducible but are not part of the installed tool.
