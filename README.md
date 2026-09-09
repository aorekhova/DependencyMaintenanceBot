# Dependency Maintenance Bot

Automates the routine parts of dependency maintenance for Java 21 applications.

The finished system will connect **Mend SCA** (the source of vulnerability data), **Jenkins**
(scans, builds and tests) and **GitLab** (source control and code review), with this Java
application acting as the orchestrating bot.

This repository currently contains **Vertical Slice 1** and **Vertical Slice 1.1**.

---

## What this slice does

A manually-run command-line tool that:

1. Reads two credentials from the environment.
2. Calls Mend's `getProjectVulnerabilityReport` API.
3. Counts the returned vulnerabilities by severity.
4. Prints a summary to the console.
5. Writes a detailed report — covering every vulnerability, at every severity — as both JSON and
   Markdown.
6. Returns a meaningful process exit code.

The console summary is unchanged from Slice 1 and still covers every severity. The detailed
report is the Slice 1.1 addition: it exists so a developer or security analyst can see what is
vulnerable, which library and version, where it was found, and what Mend recommends changing,
with the most severe findings sorted to the top.

### Deliberately not included yet

Scheduled execution, report history (each scan replaces the previous report; nothing is
archived), comparison with previous reports, GitLab integration, Jenkins integration,
email or Teams notifications, pushing, merge requests, merging, and re-scanning after a fix.
There are no placeholder classes for these — they will arrive with the slice that needs them.

Local, developer-driven remediation **is** included — see **Remediation** below. Everything it
produces stays on your machine.

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

### Commands

| Command | What it does |
|---|---|
| `scan` | Calls Mend and publishes the two report files |
| `plan-remediation` | Turns the published report into `reports/remediation-plan.{json,md}` |
| `remediate` | Scan, plan, then remediate every library — see **Remediation** |
| `remediate --dependency groupId:artifactId` | The same, limited to one library. This is the pilot form |
| `prepare-remediation-branches` | **Legacy.** Creates one branch per severity from `origin/master`. Nothing in `remediate` uses it any more |

Any other argument, or none, prints usage and exits 1.

### Required environment variables

| Variable | Required for | Purpose |
|---|---|---|
| `MEND_USER_KEY` | `scan`, `remediate` | Mend user key |
| `MEND_PROJECT_TOKEN` | `scan`, `remediate` | Mend project token |
| `WEBAPP_REPO_PATH` | `remediate` | The local WebApplication checkout to work in |
| `CLAUDE_EXECUTABLE` | optional | Defaults to `claude` on `PATH` |
| `CLAUDE_MODEL` | optional | Defaults to `opus`. Never downgraded automatically |
| `CLAUDE_MAX_TURNS` | optional | Defaults to 30 |
| `CLAUDE_TIMEOUT_SECONDS` | optional | Defaults to 1800, per Claude call |

The Mend credentials must be present and non-blank. Surrounding whitespace is stripped before use.

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
Detailed report (JSON): reports\mend-actionable-vulnerabilities.json
Detailed report (Markdown): reports\mend-actionable-vulnerabilities.md
```

`Process result` and `Security result` are separate on purpose — see the note on exit code 0
below. The console never prints a full vulnerability description or any other report detail;
that content lives only in the two report files.

---

## The detailed actionable report

Every successful scan writes two files under `reports/`, alongside the console summary:

| File | Purpose |
|---|---|
| `reports/mend-actionable-vulnerabilities.json` | Machine-readable. The contract future Jenkins, GitLab and remediation automation reads. |
| `reports/mend-actionable-vulnerabilities.md` | Human-readable. What a developer or security analyst opens directly. |

Both cover the same data: **every vulnerability Mend returned, at every severity** — Critical,
High, Medium, Low and Other alike — with the affected library and version, where it was found,
the CVSS 3 detail, and Mend's recommended fix (the preferred top fix plus every alternative Mend
offered). Nothing is filtered out; sorting (see **Sort order** below) is what puts the most
severe findings first, so the ones needing the most urgent attention are still at the top of the
document.

Severity is normalised through the same classification the console summary uses, so the two can
never disagree — a run that reports "Total vulnerabilities: 7" on screen will always list exactly
7 findings in the report. Mend's separate `cvss3_severity` field is carried in the report for
reference only and does not affect ordering or inclusion.

### Filenames are fixed, not timestamped

The two filenames above never change between runs. `generatedAt` inside each document is the only
thing that identifies which scan produced it — check that field, not the filename, when comparing
runs.

**Every scan removes the previous report pair before doing anything else** — before reading
credentials and before contacting Mend. This means:

- **If both report files exist, they belong to the most recent scan that succeeded.**
- **If a scan does not succeed for any reason** — Mend rejects the request, the response cannot
  be parsed, a required environment variable is missing, or anything else goes wrong — **neither
  report file is left behind.** Absence of the files is itself the signal that the last scan
  failed; you do not need to check the exit code to know not to trust a stale report.

The cost of this is real and accepted: even a scan that fails immediately on a missing
environment variable destroys the previous report. That trade is deliberate — an unambiguous
absence was judged more useful than a report that might silently be a week old.

Both files always share the same `generatedAt` and `reportVersion`, because they are written
together as one coordinated operation rather than as two independent file writes. See
**Exit codes** below for what happens when that operation cannot complete.

### Sort order

Within the report, findings are ordered:

1. Severity — Critical, then High, then Medium, then Low, then Other.
2. CVSS 3 score, descending — most severe first within the same severity. A finding with no
   usable score (missing, non-numeric, or a non-finite value such as `NaN`/`Infinity`) sorts
   after every finding that has one.
3. Vulnerability ID, ascending.
4. Library coordinates (`groupId:artifactId:version`), ascending.

This order is fully determined by the data, so re-running a scan against an unchanged Mend
response reproduces byte-identical findings in the same sequence.

### An empty result is a valid result

A scan where Mend returns no vulnerabilities at all still writes both files. Each states clearly
that no vulnerabilities were found, and the summary is still present in both, with every count at
zero.

### What "Not provided" means

Mend does not always supply every optional field — a library object, a location, a recommended
fix, a groupId. The report never invents a value to fill the gap: a missing field is `null` in the
JSON and reads `Not provided` in the Markdown. In particular, library coordinates
(`groupId:artifactId:version`) are only shown when all three parts were genuinely present; a
partial coordinate is never assembled, because it would look authoritative while being wrong.

---

## Remediation

`remediate` hands every vulnerability to Claude, as a developer rather than as a script runner.
Every finding is assessed before any of them is implemented, related findings are grouped, and
each group goes through the gates below together. Between calls, the bot does the things a model
must not be trusted with.

```
Mend findings
  -> the bot refreshes every remote branch and tag, once for the whole batch (stops here if it cannot)
  -> Claude assesses every finding, read-only, before any implementation runs at all
       (which ref is really affected? does this need to be fixed together with something else?)
  -> the automation-safety decision decides, per finding    (HUMAN_REVIEW_REQUIRED => a human decides, no group)
  -> the bot verifies each named ref through git                 (its own SHA, never the model's)
  -> remediation groups are formed from what the assessments actually said
       (most groups are one finding; a group of more than one exists only when an assessment
        said so explicitly, and never spans two findings that resolved to different commits)
  -> for each group: the bot creates one branch from its one shared verified commit
  -> Claude implements the whole group together, may edit anything the fix needs
  -> the bot resolves the dependency tree offline for every member of the group
  -> the bot commits the group, or undoes everything
  -> if committed: the bot runs one full `mvn -B package` on the group's branch
  -> the next group is attempted regardless of how this one went
  -> once every group is done, the checkout returns to the branch it started on
```

The assessment decides which ref is affected, where the dependency comes from, which version
fixes it forward, what has to change, how large that change is, and whether it can be fixed safely
on its own. The bot supplies **no** target version as an instruction: the one it derived from
Mend's fix text is passed along explicitly labelled unverified, because in the first pilot that
value was a downgrade.

**Neither Claude call may ever publish anything.** Nothing leaves your machine: no push, no fetch,
no touching a remote, no merge request. Both calls otherwise have full local git. See
[Developer permissions](#developer-permissions) for the exact boundary.

### Developer permissions

Claude runs as an ordinary developer, not a curated menu of pre-approved commands: an unrestricted
shell (Maven, Java, `curl`, package and archive tools, anything a real investigation or fix needs),
full local git, file reading and searching, and web search/fetch for an advisory or a compatibility
question. The implementation call additionally gets `Edit`/`Write`/`MultiEdit`; the assessment call
does not.

**The boundary is the remote, not git itself.** `git log`, `git show`, `git diff`, `git grep`,
`git blame`, `git for-each-ref`, `git checkout`, `git switch`, `git branch`, `git reset`,
`git restore`, `git commit` and every other local operation are simply available to both calls, the
same way `Bash` makes Maven or `curl` available — there is no curated allow-list of individual git
subcommands to keep in sync. Only `git push`, `git fetch` and `git remote` are refused at the tool
level: publishing is never Claude's to do, and refreshing this bot's own single, deliberate view of
the remote is not either. This is a real widening from an earlier version of this pilot, which
refused Claude *all* git, including read-only inspection, and had the bot prepare a read-only
snapshot of refs and `pom.xml` files as a substitute — now that git itself is available, an
assessment investigates another ref directly (`git show <ref>:pom.xml`, `git log`,
`git for-each-ref`) and that snapshot mechanism no longer exists.

Local git write access is real but does not change who owns the outcome. An assessment is asked, in
the prompt rather than by tool restriction, not to switch branches or commit on the one checkout the
whole run shares. An implementation is free to use `git commit` for its own workflow, but the bot is
still what stages, reviews and finally commits or rolls back the change it reports — the prompt asks
it to leave the remediation as ordinary working-tree edits rather than sealing it inside a commit
only it made, since that is what the bot's own review and gates actually inspect.

### Remediation groups

Most findings stand on their own and end up in a group of one, implemented exactly as a single
library always was. A group of more than one exists only when an assessment set
`coordinatedRemediationRequired` and named `relatedCoordinates` — other Mend findings, or
coordinates with no finding of their own ("companions") that the fix is still incomplete without.

Grouping is by transitive closure: if A names B and B names C, all three end up in one group even
though A never named C. Two coordinates that ask to be grouped but verify to **different** commits
are never merged onto one branch — each keeps its own group, and the refusal is recorded rather
than silently dropped. If an assessment requires coordination with a finding whose own automation
safety came back `HUMAN_REVIEW_REQUIRED`, the whole requirement is pulled out of automation rather
than remediating only the automatable half of something declared inseparable.

A worked example: if the assessment for `httpclient5` reports that it, `httpclient5-cache`,
`httpcore5` and `httpcore5-h2` all have to move together — the last one via a companion coordinate
with no Mend finding of its own — all four end up in one group, one branch, one implementation
call that sees every finding and the companion together, one dependency-resolution check covering
every Mend finding in the group, one commit, and one full build. A human reading the run summary
sees this because every member's entry shares the same branch name and the same commit.

### The impact score

The assessment scores the size of the change it proposes, 1 to 10 — a measure of size only, and
nothing else. It does not by itself decide whether the bot may run unattended; that is a separate
decision, below.

### Automation safety

The assessment also states, independently of the impact score, whether it trusts the bot to carry
the change out unattended: `AUTOMATIC_ALLOWED` or `HUMAN_REVIEW_REQUIRED`.

- **`AUTOMATIC_ALLOWED`** — Implementation runs, every gate runs, and a passing result is committed
  locally; this is the fully-automated case.
- **`HUMAN_REVIEW_REQUIRED`** — no Implementation call is made at all. Instead, a separate,
  read-only Human Review Engineer writes up a report — what is vulnerable, why, and what the
  assessment already established — for a person to act on. Nothing about the repository changes.
  This covers both a safe, reviewable plan the assessment simply did not authorise to run
  unattended, and a case where no safe plan could be established at all.

Anything the bot cannot read at all — a malformed answer, a missing score, a missing
automation-safety decision, an inconclusive investigation, a ref that does not exist — is treated
exactly like `HUMAN_REVIEW_REQUIRED`: it fails closed. (An older run's persisted analysis may still
carry the legacy `AUTOMATION_BLOCKED` value; this bot treats it identically to `HUMAN_REVIEW_REQUIRED`
wherever it is read.)

**The two decisions are deliberately independent and never derived from each other.** A one-line
version bump inside a coordinated, runtime-sensitive dependency family can be `impactScore: 3` and
`HUMAN_REVIEW_REQUIRED` at the same time; a large, multi-file change can be `impactScore: 9` and
`AUTOMATIC_ALLOWED` if the assessment found a clean, well-validated path through it. Judging one
from the other was an earlier version of this policy and is exactly what this design replaces.

### The dependency-resolution gate

Before a commit, the bot runs `dependency:tree` offline once per member of the group and asks two
questions of each: does the build model still resolve, and is the vulnerable version still what
resolves? A failure on any member rolls back the whole group's change. So does a gate that could
not answer at all for any member.

This is **not** a build and **not** a test run. Passing it means the change is not *knowably*
wrong — which is why a kept change is only ever called `COMMITTED_PENDING_VALIDATION` until the
second gate below has actually run.

### The full build gate

**Pilot capability, embedded in the standard flow — it runs unconditionally, once per group, for
every commit.** Once a group's commit has been made, the bot runs one full `mvn -B package` on the
branch, online (not offline, unlike the dependency-resolution gate — a remediation may move to a
version that is not yet cached anywhere), with a generous timeout (45 minutes by default) since it
compiles, tests and packages the whole reactor.

**A failing build never undoes the commit.** The commit already happened; this gate is purely
diagnostic. If the build fails, the commit stays on its branch for you to look at, the safe build
log and the failure reason are recorded, and every member of that group is reported as **not fully
validated** — which now also means the run's overall exit code is `10`
(`MANUAL_REMEDIATION_REQUIRED`), the same code used when a library needs a human for any other
reason. One group's build failing never stops the next group in the run.

The run summary and console distinguish four outcomes per library: **fully validated** (committed
and the full build passed — the only state that counts as fully done), **build validation failed**
(committed, but the build did not pass), **nothing to remediate**, and **needs a human** (every
other reason a library never got a commit at all — including a finding pulled out of automation
because it required coordination with something not itself automatable).

While the build runs, the console prints a heartbeat roughly every 30 seconds so a slow build and a
hung one do not look identical:

```
[04:40:02] org.bouncycastle:bcprov-jdk18on -- full build validation: running mvn package on the committed branch; this can take a long time
[04:40:32] org.bouncycastle:bcprov-jdk18on -- full build validation still running (30s elapsed)
[04:41:02] org.bouncycastle:bcprov-jdk18on -- full build validation still running (1m00s elapsed)
[04:46:18] org.bouncycastle:bcprov-jdk18on -- full build validation done in 6m16s: PASSED
```

### What a run leaves behind

Everything lands under `reports/runs/<runId>/`:

| Path | What it holds |
|---|---|
| `remediation-summary.json` | The whole run on one page. Open this first |
| `units/<unit>/assessment/prompt.md` | Exactly what the assessment was asked |
| `units/<unit>/assessment/assessment.json` | The validated assessment. Its presence means one succeeded |
| `units/<unit>/assessment/assessment-attempt.json` | The invocation, the verdict, and why |
| `units/<unit>/assessment/stdout.json` | Claude's answer verbatim, reasoning included |
| `units/<unit>/implementation/attempt-1/prompt.md` | What the implementation was asked |
| `units/<unit>/implementation/attempt-1/implementation-report.json` | What it says it did, or why it stopped |
| `units/<unit>/implementation/attempt-1/patch.diff` | The actual diff — kept even when rolled back |
| `units/<unit>/implementation/attempt-1/validation.json` | The dependency-resolution gate's verdict |
| `units/<unit>/implementation/attempt-1/validation-output.txt` | Its Maven output |
| `units/<unit>/implementation/attempt-1/full-build-validation.json` | The full build gate's verdict — present whenever a commit was made |
| `units/<unit>/implementation/attempt-1/full-build-output.txt` | The full build's own safe log |

The commit, if there is one, is on `remediation/<runId>/<severity>/<groupId>__<artifactId>` for an
ordinary single-library group, or `remediation/<runId>/<severity>/<remediation group id>` for a
group of more than one, in your WebApplication checkout. Every member of a multi-member group
shares that one branch and that one implementation directory. The checkout itself is returned to
whatever branch it was on once every group in the run has been attempted.

### Watching a run

Each step is announced on stdout as it starts and again when it finishes, timestamped and with how
long it took. Both Claude calls and the validation gate can run for minutes, and this is what tells
a working run from a stuck one:

```
[04:30:07] org.bouncycastle:bcprov-jdk18on -- refreshing remote refs: every branch and tag
[04:30:11] org.bouncycastle:bcprov-jdk18on -- refreshing remote refs done in 4s: up to date
[04:30:11] org.bouncycastle:bcprov-jdk18on -- developer assessment: read-only; Claude decides for itself how to investigate, so this can take minutes
[04:33:47] org.bouncycastle:bcprov-jdk18on -- developer assessment done in 3m36s: REMEDIATION_REQUIRED, impact 2 -> AUTOMATIC_ALLOWED, automation AUTOMATIC_ALLOWED
[04:33:47] org.bouncycastle:bcprov-jdk18on -- verifying the source ref: origin/hotfix-2026.1
[04:33:48] org.bouncycastle:bcprov-jdk18on -- verifying the source ref done in 0s: refs/remotes/origin/hotfix-2026.1 is bbf3e65...
```

Only two things are repeated at the end, both on stderr: why a library stopped, and a checkout that
could not be put back. Everything else was already said as it happened.

### When something goes wrong internally

The console still refuses to print details of an unexpected internal error — the failure could have
come from code holding text authored by Mend or read out of a product repository. It now names a
file instead:

```
An unexpected internal error occurred. No details are shown to avoid leaking sensitive data.
Diagnostic details (safe to share, credentials masked): reports\diagnostics\internal-error-20260811-043007-1a2b.log
```

That file holds the command, the exception type, its message and the full stack trace including
causes. It holds **no** environment variable values, no credentials and no file contents, and every
known credential is masked before it is written. One file per incident; nothing is overwritten.

A **configuration** problem is not an internal error and never produces one: a missing
`WEBAPP_REPO_PATH`, or an unusable `CLAUDE_MAX_TURNS`, exits 2 and names the variable.

### Running a pilot

```powershell
$env:WEBAPP_REPO_PATH = "C:\path\to\WebApplication"
java -jar target\dependency-maintenance-bot.jar remediate --dependency org.bouncycastle:bcprov-jdk18on
```

The checkout must be clean before you start, with no merge or rebase in progress.

---

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | The command ran; every library was either committed locally or genuinely needed nothing |
| 1 | `USAGE_ERROR` | No command, an unknown command, extra arguments, or a malformed `--dependency` value |
| 2 | `CONFIG_ERROR` | A required environment variable is missing, blank or unusable |
| 3 | `API_ERROR` | Mend returned an error inside an HTTP 200 response |
| 4 | `NETWORK_ERROR` | Non-200 status, unreachable host, or a timeout |
| 5 | `MALFORMED_RESPONSE` | HTTP 200 with a body that could not be understood |
| 6 | `REPORT_WRITE_ERROR` | The work succeeded but a report or summary could not be written |
| 7 | `REMEDIATION_SOURCE_ERROR` | A local document an earlier command should have produced is missing, unreadable, or does not contain the requested dependency |
| 8 | `GIT_OPERATION_ERROR` | The repository rejected an operation, was not safe to touch, or could not be returned to its original branch |
| 9 | `REMEDIATION_EXECUTION_ERROR` | Reserved for a failure during execution itself |
| 10 | `MANUAL_REMEDIATION_REQUIRED` | Nothing broke, but at least one library is waiting on a person |
| 70 | `UNEXPECTED_ERROR` | An unexpected internal failure |

**Exit code 0 means the scan ran — not that the project is free of vulnerabilities.** A
successful scan that finds critical vulnerabilities still exits 0; the security verdict is the
`Security result` line. This is deliberate for slice 1. A future `--fail-on-severity` option
will provide CI gating, so please do not wire a Jenkins gate to exit code 0 on the assumption
that it means "clean".

**Exit code 6 has two variants in practice**, both printed to stderr:

- *"Report write error: ..."* — the write failed, but the tool was able to clean up afterwards, so
  **no report files remain**. Nothing to inspect; retry the scan.
- *"Report write error: ..." followed by "WARNING: the current report file state could not be
  guaranteed"* and a list of paths — the write failed **and** the cleanup itself was blocked (for
  example, by an antivirus scanner or a sync client holding a file open). Publishing two files can
  never be made fully atomic by application code alone, so this is the honest limit of that
  guarantee: **inspect the named paths by hand before trusting anything in `reports/`.**

Either way, if the scan reached Mend successfully the console summary was already printed before
the write was attempted, so a report-write failure never costs you the scan's primary result —
only the two files on disk.

---

## Security

- Credentials are read **only** from the two environment variables above. They are never read
  from a file or a command-line argument.
- **`.env` files are not read by this slice.** The `.gitignore` entry exists to stop one being
  committed later, not because the application consumes one.
- The application never prints credentials, the request body, the raw response body, or a stack
  trace. Text authored by Mend is passed through a redactor before display, because a Mend error
  message could in principle echo a submitted token back.
- The same redaction applies to the two report files, and it happens **before** rendering, not by
  searching the finished JSON or Markdown for the credential text. That ordering matters: JSON
  escaping rewrites a credential's characters (a quote becomes `\"`, a newline becomes `\n`), so a
  search over the rendered text would miss it. Masking the report data first means the renderers
  never see an unmasked credential at all.
- `.gitignore` blocks real Mend report dumps at the repository root **and the entire `reports/`
  directory**, where the detailed reports are written. Both are excluded from version control.
- **The `reports/` directory is still real, sensitive data on disk.** If this repository lives in
  a synced folder (OneDrive, Dropbox, etc.), that sync client will upload the reports even though
  git ignores them — git ignoring a path does not stop other software from reading or syncing it.
  Consider excluding `reports/` from such syncing, or writing reports to a location outside any
  synced folder.
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

**Exit code 6** — see the two variants described under **Exit codes** above. If the message
mentions that the report state "could not be guaranteed", inspect the listed paths under
`reports/` by hand — do not assume they hold a complete or consistent pair until you have checked.
A likely cause on Windows is another process (an antivirus scanner, a sync client) briefly
holding one of the report files open.

**Both report files exist but look old** — check `generatedAt` inside either file, not the file's
modification timestamp, to see which scan actually produced them. The previous pair is only
removed when a new scan starts, so if the tool has not been run again since, the existing report
is simply the last successful result and is not stale in the sense this design guards against.

---

## Known limitations

- The response is buffered fully in memory. A very large project report could therefore use a
  lot of heap. There is a size ceiling, but it relies on a `Content-Length` header and so does
  not cover chunked responses.
- Trailing content after a valid JSON document is tolerated by the parser.
- If this repository is stored in a synced OneDrive folder, the sync client may hold locks on
  `target\`, causing intermittent `clean` failures and slow builds. Excluding the folder from
  sync avoids this. The same applies to `reports\`, with the added concern that its contents are
  sensitive (see **Security** above).
- Publishing the two report files is **coordinated best-effort, not fully transactional.** Each
  file is replaced atomically on its own, and a failure partway through triggers cleanup of both —
  but that cleanup can itself be blocked by the filesystem. When that happens the tool exits 6 and
  says explicitly that the report state could not be guaranteed, rather than silently leaving a
  possibly-mismatched pair. See **Exit codes** above.
- The current-scan report pair (`mend-actionable-vulnerabilities.{json,md}`) is still overwritten by
  every scan, as before. Distinct vulnerability snapshots are now additionally kept in
  `reports/mend-history/` (content-addressed by a canonical fingerprint of the redacted findings,
  never the raw Mend response), so an identical snapshot is never duplicated on disk and a run's
  manifest/plan records which snapshot it worked from — no manual cleanup is required between runs.
