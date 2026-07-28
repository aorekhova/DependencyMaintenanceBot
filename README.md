# Dependency Maintenance Bot

Automates the routine parts of dependency maintenance for Java 21 applications.

The finished system will connect **Mend SCA** (the source of vulnerability data), **Jenkins**
(scans, builds and tests) and **GitLab** (source control and code review), with this Java
application acting as the orchestrating bot.

This repository currently contains **Vertical Slice 1** only.

---

## What this slice does

A manually-run command-line tool that:

1. Reads two credentials from the environment.
2. Calls Mend's `getProjectVulnerabilityReport` API.
3. Counts the returned vulnerabilities by severity.
4. Prints a summary to the console.
5. Returns a meaningful process exit code.

### Deliberately not included yet

Scheduled execution, report history, comparison with previous reports, GitLab integration,
Jenkins integration, email or Teams notifications, dependency updates, POM rewriting, automatic
branches or merge requests, AI remediation, and automatic merging. There are no placeholder
classes for these — they will arrive with the slice that needs them.

---

## Prerequisites

- **JDK 21** (developed against Temurin 21.0.11).
- **No local Maven installation is required** — the repository ships the Maven Wrapper, pinned
  to Maven 3.9.16.
- Corporate network access. The wrapper resolves Maven and all dependencies through the internal
  Nexus mirror, so the build does not work off the corporate network or VPN.

---

## Build and test

```powershell
.\mvnw.cmd test       # run the full automated test suite
.\mvnw.cmd package    # build the runnable JAR
```

The build produces:

```
target\dependency-maintenance-bot.jar
```

Every automated test is fully synthetic. No test contacts the real Mend API, reads a real Mend
report, or uses real credentials — and that is enforced by the build, not by convention:
`NoRealMendEndpointTest` fails the build if any test file references the real Mend host, and the
Surefire configuration points test JVMs at a dead HTTPS proxy so an accidental external call
fails immediately.

---

## Running a scan

```powershell
java -jar target\dependency-maintenance-bot.jar scan
```

`scan` is the only supported command. Any other argument, or none, prints usage and exits 1.

### Required environment variables

| Variable | Purpose |
|---|---|
| `MEND_USER_KEY` | Mend user key |
| `MEND_PROJECT_TOKEN` | Mend project token |

Both must be present and non-blank. Surrounding whitespace is stripped before use.

### Recommended way to supply credentials

Type them into a masked prompt rather than assigning them directly. A direct
`$env:MEND_USER_KEY = "..."` writes the credential into your PowerShell command history, the
on-disk PSReadLine history file, and terminal scrollback.

```powershell
function ConvertFrom-SecureStringPlain([System.Security.SecureString] $s) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try     { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

try {
    $userKeySecure      = Read-Host -Prompt 'MEND_USER_KEY'      -AsSecureString
    $projectTokenSecure = Read-Host -Prompt 'MEND_PROJECT_TOKEN' -AsSecureString

    $env:MEND_USER_KEY      = ConvertFrom-SecureStringPlain $userKeySecure
    $env:MEND_PROJECT_TOKEN = ConvertFrom-SecureStringPlain $projectTokenSecure

    java -jar target\dependency-maintenance-bot.jar scan
    Write-Host "exit code: $LASTEXITCODE"
}
finally {
    Remove-Item Env:MEND_USER_KEY      -ErrorAction SilentlyContinue
    Remove-Item Env:MEND_PROJECT_TOKEN -ErrorAction SilentlyContinue
}
```

Confirm afterwards that nothing is left behind:

```powershell
Get-ChildItem Env:MEND_* -ErrorAction SilentlyContinue   # expect no output
```

For illustration only, the plain form looks like this — never use it with real values:

```powershell
$env:MEND_USER_KEY = "<set-locally>"
$env:MEND_PROJECT_TOKEN = "<set-locally>"
java -jar target\dependency-maintenance-bot.jar scan
Remove-Item Env:MEND_USER_KEY
Remove-Item Env:MEND_PROJECT_TOKEN
```

### Example output

```
Mend vulnerability check completed
Total vulnerabilities: 7
Critical: 0
High: 4
Medium: 3
Low: 0
Other: 0
Process result: SUCCESS
Security result: VULNERABILITIES FOUND
```

`Process result` and `Security result` are separate on purpose — see the note on exit code 0
below.

---

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | The scan ran and produced a report |
| 1 | `USAGE_ERROR` | No command, an unknown command, or extra arguments |
| 2 | `CONFIG_ERROR` | `MEND_USER_KEY` or `MEND_PROJECT_TOKEN` missing or blank |
| 3 | `API_ERROR` | Mend returned an error inside an HTTP 200 response |
| 4 | `NETWORK_ERROR` | Non-200 status, unreachable host, or a timeout |
| 5 | `MALFORMED_RESPONSE` | HTTP 200 with a body that could not be understood |
| 70 | `UNEXPECTED_ERROR` | An unexpected internal failure |

**Exit code 0 means the scan ran — not that the project is free of vulnerabilities.** A
successful scan that finds critical vulnerabilities still exits 0; the security verdict is the
`Security result` line. This is deliberate for slice 1. A future `--fail-on-severity` option
will provide CI gating, so please do not wire a Jenkins gate to exit code 0 on the assumption
that it means "clean".

---

## Security

- Credentials are read **only** from the two environment variables above. They are never read
  from a file or a command-line argument.
- **`.env` files are not read by this slice.** The `.gitignore` entry exists to stop one being
  committed later, not because the application consumes one.
- The application never prints credentials, the request body, the raw response body, or a stack
  trace. Text authored by Mend is passed through a redactor before display, because a Mend error
  message could in principle echo a submitted token back.
- `.gitignore` blocks real Mend report dumps at the repository root. Keep real reports outside
  the repository entirely.
- Never commit a credential, a real vulnerability report, or a real API response. If you need a
  new test fixture, hand-author a synthetic one under `src/test/resources/fixtures/`.

---

## Troubleshooting

**`errorCode 1004` / exit code 3** — Mend rejected the credentials. Check that
`MEND_PROJECT_TOKEN` is the token for the project you intend to scan and that `MEND_USER_KEY`
belongs to an account with access to it.

**Cannot reach the Mend API host / exit code 4** — most likely the corporate HTTPS proxy. The
tool honours the standard JVM proxy properties:

```powershell
java -Dhttps.proxyHost=<proxy-host> -Dhttps.proxyPort=<proxy-port> `
     -jar target\dependency-maintenance-bot.jar scan
```

On a network using WPAD or a PAC file, try `-Djava.net.useSystemProxies=true` instead. Note that
a refused connection and a DNS failure are indistinguishable at the JDK level, so this one
message covers both.

**An HTTP 3xx response** — the tool deliberately does not follow redirects. A redirect on this
endpoint almost always means a proxy or gateway intercepted the request rather than Mend
answering it. Following it would be unsafe: the JDK converts a redirected POST into a GET and
discards the request body, which is where the credentials are.

**Exit code 5** — Mend answered with something that is neither a report nor a recognised error
envelope. A common cause is a proxy login page returned as HTML. The body is not printed,
because it may contain sensitive data.

---

## Known limitations

- The response is buffered fully in memory. A very large project report could therefore use a
  lot of heap. There is a size ceiling, but it relies on a `Content-Length` header and so does
  not cover chunked responses.
- Trailing content after a valid JSON document is tolerated by the parser.
- If this repository is stored in a synced OneDrive folder, the sync client may hold locks on
  `target\`, causing intermittent `clean` failures and slow builds. Excluding the folder from
  sync avoids this.
