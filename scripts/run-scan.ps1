<#
    Temporary local convenience wrapper for manual testing.

    Reads MEND_USER_KEY / MEND_PROJECT_TOKEN from a local .env.local file (KEY=VALUE per line,
    '#' comments and blank lines ignored), sets them as process environment variables, runs the
    scan, then clears them again -- so the running application still only ever sees environment
    variables (EnvConfig is unchanged) and no credential value is echoed to the console.

    .env.local is not committed (see .gitignore's existing .env.* pattern) and is not created by
    this script -- create it yourself, next to this repo's root, with:

        MEND_USER_KEY=<your-user-key>
        MEND_PROJECT_TOKEN=<your-project-token>
#>

$repoRoot = Split-Path $PSScriptRoot -Parent
$envFile = Join-Path $repoRoot ".env.local"
$jarPath = Join-Path $repoRoot "target\dependency-maintenance-bot.jar"

if (-not (Test-Path $envFile)) {
    Write-Error "Missing $envFile. Create it with two lines:`n  MEND_USER_KEY=<your-user-key>`n  MEND_PROJECT_TOKEN=<your-project-token>"
    exit 1
}

if (-not (Test-Path $jarPath)) {
    Write-Error "Missing $jarPath. Run .\mvnw.cmd package first."
    exit 1
}

$values = @{}
foreach ($line in Get-Content $envFile) {
    $trimmed = $line.Trim()
    if ($trimmed -eq "" -or $trimmed.StartsWith("#")) {
        continue
    }
    $separatorIndex = $trimmed.IndexOf("=")
    if ($separatorIndex -lt 1) {
        continue
    }
    $key = $trimmed.Substring(0, $separatorIndex).Trim()
    $value = $trimmed.Substring($separatorIndex + 1).Trim()
    $values[$key] = $value
}

if (-not $values.ContainsKey("MEND_USER_KEY") -or -not $values.ContainsKey("MEND_PROJECT_TOKEN")) {
    Write-Error "$envFile must define both MEND_USER_KEY and MEND_PROJECT_TOKEN."
    exit 1
}

try {
    $env:MEND_USER_KEY = $values["MEND_USER_KEY"]
    $env:MEND_PROJECT_TOKEN = $values["MEND_PROJECT_TOKEN"]

    & java -jar $jarPath scan
    exit $LASTEXITCODE
}
finally {
    Remove-Item Env:MEND_USER_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:MEND_PROJECT_TOKEN -ErrorAction SilentlyContinue
}
