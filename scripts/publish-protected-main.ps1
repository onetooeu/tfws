# TFWS protected-main publisher
#
# Publishes one or more already-signed local commits from `main` through a
# temporary ci/publish-* branch. The exact tip commit must pass all required CI
# checks before the same SHA is pushed to protected `main`.
#
# Typical use:
#
#   git commit -S -m "..."
#   powershell -NoProfile -ExecutionPolicy Bypass `
#     -File .\scripts\publish-protected-main.ps1 -Mode Publish
#
# Audit only:
#
#   powershell -NoProfile -ExecutionPolicy Bypass `
#     -File .\scripts\publish-protected-main.ps1 -Mode Audit
#
# The tool never creates commits and never reads or transmits a private key.
# Compatible with Windows PowerShell 5.1.

[CmdletBinding()]
param(
    [ValidateSet("Audit", "Publish")]
    [string]$Mode = "Audit",

    [string]$RepoRoot = "C:\ONETOO\Workspace\Repos\tfws",

    [ValidateRange(1, 50)]
    [int]$MaxCommits = 20,

    # Bootstrap-only exception used while this file is first generated.
    # It is honored only in Audit mode and only when this exact script is the
    # sole untracked path. Publish mode always requires a fully clean tree.
    [switch]$AllowBootstrapSelfUntracked
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedLogin = "onetooeu"
$ExpectedUserId = 250212667
$Repository = "onetooeu/tfws"
$RulesetId = 19610282
$WorkflowRelative = ".github/workflows/ci.yml"

$RequiredChecks = @(
    "python-node",
    "rust (windows-latest)",
    "rust (ubuntu-latest)",
    "rust (macos-latest)"
)

$ApiVersion = "2026-03-10"
$AcceptHeader = "Accept: application/vnd.github+json"
$VersionHeader = "X-GitHub-Api-Version: $ApiVersion"

$LogRoot = "C:\ONETOO\Logs"
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile = Join-Path $LogRoot (
    "safe-publish-{0}-{1}.log" -f $Mode.ToLowerInvariant(), $Stamp
)
$ResultFile = Join-Path $LogRoot (
    "safe-publish-{0}-{1}.json" -f $Mode.ToLowerInvariant(), $Stamp
)

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$PreflightBranch = $null
$PreflightPushed = $false
$MainPushed = $false
$PreflightDeleted = $false
$BaselineRemoteMain = $null
$LocalHead = $null
$BootstrapSelfUntrackedActive = $false

New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null
Start-Transcript -Path $LogFile -Force | Out-Null

$env:GIT_PAGER = "cat"
$env:GH_PAGER = "cat"
$env:PAGER = "cat"

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)

    Write-Host ""
    Write-Host ("=== {0} ===" -f $Message) -ForegroundColor Cyan
}

function Invoke-GhJson {
    param([Parameter(Mandatory = $true)][string]$Endpoint)

    $lines = @(
        & gh api `
            -H $AcceptHeader `
            -H $VersionHeader `
            $Endpoint
    )

    if ($LASTEXITCODE -ne 0) {
        throw ("GitHub API GET zlyhalo pre endpoint: {0}" -f $Endpoint)
    }

    return ($lines -join [Environment]::NewLine)
}

function Get-RemoteMainSha {
    return ((
        & gh api `
            -H $AcceptHeader `
            -H $VersionHeader `
            ("repos/{0}/commits/main" -f $Repository) `
            --jq ".sha"
    ) -join " ").Trim()
}

function Assert-WorkflowAndRuleset {
    $workflowPath = Join-Path $RepoRoot $WorkflowRelative

    if (-not (Test-Path -LiteralPath $workflowPath -PathType Leaf)) {
        throw ("CI workflow chyba: {0}" -f $workflowPath)
    }

    $workflow = [System.IO.File]::ReadAllText($workflowPath)
    $workflow = $workflow.Replace("`r`n", "`n").Replace("`r", "`n")

    foreach ($requiredText in @(
        "name: CI",
        "pull_request:",
        "push:",
        "- main",
        '- "ci/**"'
    )) {
        if (-not $workflow.Contains($requiredText)) {
            throw ("CI workflow neobsahuje: {0}" -f $requiredText)
        }
    }

    $ruleset = (
        Invoke-GhJson -Endpoint (
            "repos/{0}/rulesets/{1}" -f $Repository, $RulesetId
        )
    ) | ConvertFrom-Json

    if ([int64]$ruleset.id -ne [int64]$RulesetId) {
        throw ("Neocekavany ruleset ID: {0}" -f $ruleset.id)
    }

    if ([string]$ruleset.enforcement -ne "active") {
        throw ("Ruleset nie je active: {0}" -f $ruleset.enforcement)
    }

    $includes = @($ruleset.conditions.ref_name.include)

    if ($includes -notcontains "refs/heads/main") {
        throw "Ruleset necieli na refs/heads/main."
    }

    $bypassActors = @()

    if ($ruleset.PSObject.Properties["bypass_actors"] -and
        $null -ne $ruleset.bypass_actors) {
        $bypassActors = @($ruleset.bypass_actors)
    }

    if ($bypassActors.Count -ne 0) {
        throw "Ruleset obsahuje bypass actorov."
    }

    $rules = @($ruleset.rules)
    $ruleTypes = @($rules | ForEach-Object { [string]$_.type })

    foreach ($requiredType in @(
        "deletion",
        "non_fast_forward",
        "required_signatures",
        "required_status_checks"
    )) {
        if ($ruleTypes -notcontains $requiredType) {
            throw ("Ruleset neobsahuje pravidlo: {0}" -f $requiredType)
        }
    }

    if ($ruleTypes -contains "pull_request") {
        throw "Ruleset neocakavane vyzaduje pull request."
    }

    $statusRules = @(
        $rules |
        Where-Object {
            [string]$_.type -eq "required_status_checks"
        }
    )

    if ($statusRules.Count -ne 1) {
        throw "Ruleset nema presne jedno required_status_checks pravidlo."
    }

    $statusRule = $statusRules[0]
    $contexts = @(
        $statusRule.parameters.required_status_checks |
        ForEach-Object { [string]$_.context }
    )

    foreach ($requiredCheck in $RequiredChecks) {
        if ($contexts -notcontains $requiredCheck) {
            throw ("Ruleset nevyzaduje check: {0}" -f $requiredCheck)
        }
    }

    if ($contexts.Count -ne $RequiredChecks.Count) {
        throw ("Ruleset obsahuje neocakavany pocet checkov: {0}" -f `
            $contexts.Count)
    }

    if ([bool]$statusRule.parameters.strict_required_status_checks_policy) {
        throw "strict_required_status_checks_policy ma byt false."
    }
}

function Get-WorkflowRunForCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$Branch,
        [int]$Attempts = 60
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $response = (
            Invoke-GhJson -Endpoint (
                "repos/{0}/actions/runs?head_sha={1}&event=push&per_page=30" -f `
                    $Repository,
                    $Commit
            )
        ) | ConvertFrom-Json

        $candidateRuns = @(
            $response.workflow_runs |
            Where-Object {
                [string]$_.head_sha -eq $Commit -and
                [string]$_.head_branch -eq $Branch -and
                [string]$_.name -eq "CI"
            } |
            Sort-Object created_at -Descending
        )

        if ($candidateRuns.Count -gt 0) {
            return $candidateRuns[0]
        }

        Write-Host (
            "CI beh pre vetvu {0} este nie je viditelny; pokus {1}/{2}..." -f `
                $Branch,
                $attempt,
                $Attempts
        )

        Start-Sleep -Seconds 3
    }

    return $null
}

function Watch-And-VerifyRun {
    param(
        [Parameter(Mandatory = $true)][int64]$RunId,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [Parameter(Mandatory = $true)][string]$ExpectedBranch
    )

    $watchOutput = @(
        & gh run watch `
            $RunId `
            --repo $Repository `
            --compact `
            --exit-status 2>&1
    )
    $watchExit = $LASTEXITCODE

    $watchOutput | ForEach-Object { Write-Host $_ }

    $viewOutput = @(
        & gh run view `
            $RunId `
            --repo $Repository `
            --json status,conclusion,url,headSha,headBranch,workflowName,jobs
    )

    if ($LASTEXITCODE -ne 0) {
        throw ("Nacitanie CI runu {0} zlyhalo." -f $RunId)
    }

    $view = (($viewOutput -join [Environment]::NewLine) | ConvertFrom-Json)

    if ([string]$view.headSha -ne $ExpectedCommit) {
        throw ("CI run {0} patri inemu commitu: {1}" -f `
            $RunId,
            $view.headSha)
    }

    if ([string]$view.headBranch -ne $ExpectedBranch) {
        throw ("CI run {0} patri inej vetve: {1}" -f `
            $RunId,
            $view.headBranch)
    }

    if ([string]$view.workflowName -ne "CI") {
        throw ("CI run {0} patri inemu workflow: {1}" -f `
            $RunId,
            $view.workflowName)
    }

    if ($watchExit -ne 0 -or
        [string]$view.status -ne "completed" -or
        [string]$view.conclusion -ne "success") {
        throw ("CI run {0} nepresiel. status={1}, conclusion={2}" -f `
            $RunId,
            $view.status,
            $view.conclusion)
    }

    $jobs = @($view.jobs)

    foreach ($requiredCheck in $RequiredChecks) {
        $successful = @(
            $jobs |
            Where-Object {
                [string]$_.name -eq $requiredCheck -and
                [string]$_.status -eq "completed" -and
                [string]$_.conclusion -eq "success"
            }
        )

        if ($successful.Count -eq 0) {
            throw ("CI run {0} nema uspesny job: {1}" -f `
                $RunId,
                $requiredCheck)
        }

        Write-Host ("{0}: SUCCESS" -f $requiredCheck) -ForegroundColor Green
    }

    return [pscustomobject][ordered]@{
        id = [int64]$RunId
        url = [string]$view.url
        branch = [string]$view.headBranch
        commit = [string]$view.headSha
        conclusion = [string]$view.conclusion
    }
}

function Verify-GitHubCommitSignatures {
    param([Parameter(Mandatory = $true)][string[]]$CommitShas)

    foreach ($commitSha in $CommitShas) {
        $commitData = (
            Invoke-GhJson -Endpoint (
                "repos/{0}/commits/{1}" -f $Repository, $commitSha
            )
        ) | ConvertFrom-Json

        if (-not $commitData.commit.verification.verified) {
            throw ("GitHub neoveril podpis commitu {0}. Dovod: {1}" -f `
                $commitSha,
                $commitData.commit.verification.reason)
        }

        Write-Host ("GitHub signature VERIFIED: {0}" -f $commitSha) -ForegroundColor Green
    }
}

try {
    Write-Step ("Safe publish - rezim {0}" -f $Mode)

    foreach ($command in @("git.exe", "gh.exe")) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw ("Nastroj sa nenasiel v PATH: {0}" -f $command)
        }
    }

    foreach ($path in @(
        $RepoRoot,
        (Join-Path $RepoRoot ".git")
    )) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw ("Chyba pozadovany subor alebo priecinok: {0}" -f $path)
        }
    }

    $user = (Invoke-GhJson -Endpoint "user") | ConvertFrom-Json

    if ([string]$user.login -ne $ExpectedLogin -or
        [int64]$user.id -ne [int64]$ExpectedUserId) {
        throw ("Aktivny GitHub ucet nie je {0}." -f $ExpectedLogin)
    }

    Assert-WorkflowAndRuleset

    Push-Location $RepoRoot
    try {
        $branch = ((& git branch --show-current) -join " ").Trim()
        $status = @(& git status --porcelain=v1 --untracked-files=all)
        $origin = ((& git remote get-url origin) -join " ").Trim()

        if ($branch -ne "main") {
            throw ("Aktualna vetva nie je main: {0}" -f $branch)
        }

        if ($status.Count -ne 0) {
            $expectedBootstrapStatus = (
                "?? scripts/publish-protected-main.ps1"
            )

            if ($Mode -eq "Audit" -and
                $AllowBootstrapSelfUntracked -and
                $status.Count -eq 1 -and
                [string]$status[0] -eq $expectedBootstrapStatus) {
                $BootstrapSelfUntrackedActive = $true
                Write-Host (
                    "Bootstrap exception: generated tool is the only untracked file."
                ) -ForegroundColor Yellow
            }
            else {
                throw ("Pracovny strom nie je cisty:`n{0}" -f `
                    ($status -join "`n"))
            }
        }

        if ($origin -ne "https://github.com/onetooeu/tfws.git") {
            throw ("Origin ma neocakavanu adresu: {0}" -f $origin)
        }

        & git fetch --prune origin main

        if ($LASTEXITCODE -ne 0) {
            throw "git fetch origin main zlyhal."
        }

        $LocalHead = ((& git rev-parse HEAD) -join " ").Trim()
        $originMain = ((& git rev-parse origin/main) -join " ").Trim()

        $BaselineRemoteMain = Get-RemoteMainSha

        if ($LASTEXITCODE -ne 0 -or
            [string]::IsNullOrWhiteSpace($BaselineRemoteMain)) {
            throw "Nepodarilo sa zistit remote main cez GitHub API."
        }

        if ($originMain -ne $BaselineRemoteMain) {
            throw ("origin/main {0} sa nezhoduje s GitHub main {1}." -f `
                $originMain,
                $BaselineRemoteMain)
        }

        & git merge-base --is-ancestor origin/main HEAD
        $isFastForward = ($LASTEXITCODE -eq 0)

        if (-not $isFastForward) {
            throw "Lokalny HEAD nie je fast-forward pokracovanim origin/main."
        }

        $behindCount = [int]((
            & git rev-list --count "HEAD..origin/main"
        ) -join " ").Trim()

        $aheadCount = [int]((
            & git rev-list --count "origin/main..HEAD"
        ) -join " ").Trim()

        if ($behindCount -ne 0) {
            throw ("Lokalny main zaostava o {0} commitov." -f $behindCount)
        }

        if ($aheadCount -gt $MaxCommits) {
            throw ("Lokalny main je vpredu o {0} commitov; limit je {1}." -f `
                $aheadCount,
                $MaxCommits)
        }

        & git verify-commit HEAD

        if ($LASTEXITCODE -ne 0) {
            throw "HEAD commit nema platny lokalny podpis."
        }

        $commitsToPublish = @()

        if ($aheadCount -gt 0) {
            $commitsToPublish = @(
                & git rev-list --reverse "origin/main..HEAD"
            )

            foreach ($commitSha in $commitsToPublish) {
                & git verify-commit $commitSha

                if ($LASTEXITCODE -ne 0) {
                    throw ("Commit nema platny podpis: {0}" -f $commitSha)
                }

                Write-Host ("Lokalny podpis PASS: {0}" -f $commitSha) -ForegroundColor Green
            }
        }
    }
    finally {
        Pop-Location
    }

    Write-Host ("GitHub ucet: {0}" -f $ExpectedLogin) -ForegroundColor Green
    Write-Host ("Remote main: {0}" -f $BaselineRemoteMain)
    Write-Host ("Lokalny HEAD: {0}" -f $LocalHead)
    Write-Host ("Ahead commits: {0}" -f $aheadCount)
    Write-Host "Pracovny strom: CISTY" -ForegroundColor Green
    Write-Host "Ruleset a required checks: PASS" -ForegroundColor Green

    $stalePublishBranches = @(
        & git ls-remote `
            --heads `
            "https://github.com/onetooeu/tfws.git" `
            "refs/heads/ci/publish-*"
    )

    if ($LASTEXITCODE -ne 0) {
        throw "Kontrola ci/publish-* vetiev zlyhala."
    }

    if ($stalePublishBranches.Count -ne 0) {
        Write-Host "Stale existuju ci/publish-* vetvy:" -ForegroundColor Yellow
        $stalePublishBranches | ForEach-Object { Write-Host $_ }
        throw "Najprv odstran alebo prever stare publish vetvy."
    }

    if ($Mode -eq "Audit") {
        $result = [ordered]@{
            completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
            mode = $Mode
            repository = $Repository
            remote_main = $BaselineRemoteMain
            local_head = $LocalHead
            ahead_commits = $aheadCount
            behind_commits = $behindCount
            worktree_clean = (-not $BootstrapSelfUntrackedActive)
            bootstrap_self_untracked = $BootstrapSelfUntrackedActive
            ruleset_id = $RulesetId
            required_checks = $RequiredChecks
            stale_publish_branches = 0
            status = "PASS"
            log = $LogFile
        }

        [System.IO.File]::WriteAllText(
            $ResultFile,
            (($result | ConvertTo-Json -Depth 10) + "`n"),
            $Utf8NoBom
        )

        Write-Step "Vysledok"
        Write-Host "SAFE-PUBLISH AUDIT: PASS" -ForegroundColor Green
        Write-Host "Ziadny push nebol vykonany."
        Write-Host ("Log: {0}" -f $LogFile)
        Write-Host ("JSON vysledok: {0}" -f $ResultFile)
        return
    }

    if ($aheadCount -eq 0) {
        throw "Nie je co publikovat: lokalny main sa zhoduje s remote main."
    }

    $shortHead = $LocalHead.Substring(0, 12)
    $PreflightBranch = "ci/publish-$Stamp-$shortHead"

    Write-Step "Push na preflight vetvu"

    Push-Location $RepoRoot
    try {
        & git push origin "HEAD:refs/heads/$PreflightBranch"

        if ($LASTEXITCODE -ne 0) {
            throw "Push preflight vetvy zlyhal."
        }

        $PreflightPushed = $true
    }
    finally {
        Pop-Location
    }

    Write-Host ("Preflight vetva: {0}" -f $PreflightBranch) -ForegroundColor Green

    $preflightRun = Get-WorkflowRunForCommit `
        -Commit $LocalHead `
        -Branch $PreflightBranch

    if ($null -eq $preflightRun) {
        throw "CI run pre preflight vetvu sa nenasiel."
    }

    Write-Step "Sledovanie preflight CI"

    $preflightResult = Watch-And-VerifyRun `
        -RunId ([int64]$preflightRun.id) `
        -ExpectedCommit $LocalHead `
        -ExpectedBranch $PreflightBranch

    $remoteMainBeforePush = Get-RemoteMainSha

    if ($remoteMainBeforePush -ne $BaselineRemoteMain) {
        throw ("Remote main sa pocas preflightu zmenil z {0} na {1}." -f `
            $BaselineRemoteMain,
            $remoteMainBeforePush)
    }

    Write-Step "Push otestovaneho SHA na protected main"

    Push-Location $RepoRoot
    try {
        & git push origin "HEAD:refs/heads/main"

        if ($LASTEXITCODE -ne 0) {
            throw "Push na protected main zlyhal."
        }

        $MainPushed = $true
    }
    finally {
        Pop-Location
    }

    $remoteMainAfterPush = Get-RemoteMainSha

    if ($remoteMainAfterPush -ne $LocalHead) {
        throw ("Remote main neukazuje na publikovany commit: {0}" -f `
            $remoteMainAfterPush)
    }

    $mainRun = Get-WorkflowRunForCommit `
        -Commit $LocalHead `
        -Branch "main"

    if ($null -eq $mainRun) {
        throw "CI run pre publikovany main commit sa nenasiel."
    }

    Write-Step "Sledovanie main CI"

    $mainResult = Watch-And-VerifyRun `
        -RunId ([int64]$mainRun.id) `
        -ExpectedCommit $LocalHead `
        -ExpectedBranch "main"

    Write-Step "Overenie GitHub podpisov"

    Verify-GitHubCommitSignatures -CommitShas $commitsToPublish

    Write-Step "Odstranenie preflight vetvy"

    Push-Location $RepoRoot
    try {
        & git push origin --delete $PreflightBranch

        if ($LASTEXITCODE -ne 0) {
            throw "Odstranenie preflight vetvy zlyhalo."
        }

        $PreflightDeleted = $true

        & git fetch --prune origin main

        if ($LASTEXITCODE -ne 0) {
            throw "Finalny fetch origin main zlyhal."
        }

        $finalOriginMain = ((& git rev-parse origin/main) -join " ").Trim()
        $finalHead = ((& git rev-parse HEAD) -join " ").Trim()
        $finalStatus = @(& git status --porcelain=v1 --untracked-files=all)

        if ($finalOriginMain -ne $LocalHead -or
            $finalHead -ne $LocalHead) {
            throw "Finalny lokalny alebo origin/main SHA nie je publikovany SHA."
        }

        if ($finalStatus.Count -ne 0) {
            throw ("Finalny pracovny strom nie je cisty:`n{0}" -f `
                ($finalStatus -join "`n"))
        }
    }
    finally {
        Pop-Location
    }

    $result = [ordered]@{
        completed_at_utc = (Get-Date).ToUniversalTime().ToString("o")
        mode = $Mode
        repository = $Repository
        previous_remote_main = $BaselineRemoteMain
        published_head = $LocalHead
        published_commits = $commitsToPublish
        preflight_branch = $PreflightBranch
        preflight_run = [ordered]@{
            id = $preflightResult.id
            url = $preflightResult.url
            conclusion = $preflightResult.conclusion
        }
        main_run = [ordered]@{
            id = $mainResult.id
            url = $mainResult.url
            conclusion = $mainResult.conclusion
        }
        github_signatures_verified = $true
        preflight_branch_deleted = $PreflightDeleted
        worktree_clean = $true
        status = "PASS"
        log = $LogFile
    }

    [System.IO.File]::WriteAllText(
        $ResultFile,
        (($result | ConvertTo-Json -Depth 12) + "`n"),
        $Utf8NoBom
    )

    Write-Step "Vysledok"
    Write-Host "SAFE-PUBLISH: PASS" -ForegroundColor Green
    Write-Host ("Publikovany SHA: {0}" -f $LocalHead)
    Write-Host ("Publikovane commity: {0}" -f $aheadCount)
    Write-Host "Preflight CI: SUCCESS"
    Write-Host "Main CI: SUCCESS"
    Write-Host "GitHub podpisy: VERIFIED"
    Write-Host "Docasna vetva odstranena: ANO"
    Write-Host "Pracovny strom: CISTY"
    Write-Host ("Log: {0}" -f $LogFile)
    Write-Host ("JSON vysledok: {0}" -f $ResultFile)
}
catch {
    Write-Host ""
    Write-Host "SAFE-PUBLISH ZLYHAL:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red

    if ($PreflightPushed -and -not $PreflightDeleted) {
        Write-Host ("Preflight vetva moze stale existovat: {0}" -f `
            $PreflightBranch) -ForegroundColor Yellow
    }

    if ($MainPushed) {
        Write-Host "Remote main uz mohol byt aktualizovany." -ForegroundColor Yellow
    }
    else {
        Write-Host "Remote main nebol tymto behom aktualizovany." -ForegroundColor Yellow
    }

    Write-Host "Privatny signing key nebol citany ani odoslany." -ForegroundColor Yellow
    Write-Host ("Log: {0}" -f $LogFile)
    exit 1
}
finally {
    Stop-Transcript | Out-Null
}
