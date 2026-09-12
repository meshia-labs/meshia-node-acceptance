$ErrorActionPreference = 'Stop'
$AccountName = 'meshia37-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
$Root = Join-Path $env:SystemDrive ('meshia37-' + [Guid]::NewGuid().ToString('N'))
$Evidence = Join-Path (Get-Location) 'windows37-evidence'
$Python = (Get-Command python.exe).Source
$Account = $null
$Child = $null
$Receipt = @{ account_removed = $false; profile_removed = $false; passed = $false }
function Quote-PsLiteral([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
try {
    $null = New-Item -ItemType Directory -Path $Root
    foreach ($Name in @('windows37_package.py', 'test_windows37_descriptors.py')) {
        Copy-Item -LiteralPath $Name -Destination $Root
    }
    Copy-Item -LiteralPath $Evidence -Destination $Root -Recurse
    $Random = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Random)
    $Password = ConvertTo-SecureString ('mA!9-' + [Convert]::ToBase64String($Random)) -AsPlainText -Force
    $Account = New-LocalUser -Name $AccountName -Password $Password -PasswordNeverExpires -AccountNeverExpires
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member $AccountName
    & icacls.exe $Root /grant ('*' + $Account.SID.Value + ':(OI)(CI)M') /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture directory grant failed.' }
    $Body = @'
$ErrorActionPreference = 'Stop'
$UserRoot = [Environment]::GetFolderPath('UserProfile')
if (-not $UserRoot -or $UserRoot -match '(?i)runneradmin') { throw 'Ordinary profile not loaded.' }
$env:USERPROFILE = $UserRoot
$env:LOCALAPPDATA = Join-Path $UserRoot 'AppData\Local'
$env:APPDATA = Join-Path $UserRoot 'AppData\Roaming'
$env:USERNAME = [Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
$env:TEMP = Join-Path $env:LOCALAPPDATA 'MeshiaDescriptorTest'
$env:TMP = $env:TEMP
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:PYTHONUTF8 = '1'
$null = New-Item -ItemType Directory -Force -Path $env:TEMP
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
$Owner = (Get-Acl -LiteralPath $env:TEMP).Owner
$OwnerSid = ([Security.Principal.NTAccount]::new($Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
$Admin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Admin -or $OwnerSid -ne $Identity.User.Value) { throw 'Ordinary owner identity mismatch.' }
@{ current_sid = $Identity.User.Value; owner_sid = $OwnerSid; admin = $Admin } | ConvertTo-Json |
    Set-Content -LiteralPath 'windows37-evidence/owner.json' -Encoding UTF8
'@
    $Body += "`n`$Python = " + (Quote-PsLiteral $Python) + "`n"
    $Body += @'
& $Python windows37_package.py verify
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -m pytest test_windows37_descriptors.py -q --junitxml=windows37-evidence/tests.xml
exit $LASTEXITCODE
'@
    $Bootstrap = Join-Path $Root 'ordinary.ps1'
    [IO.File]::WriteAllText($Bootstrap, $Body, [Text.UTF8Encoding]::new($false))
    $Credential = [PSCredential]::new(($env:COMPUTERNAME + '\' + $AccountName), $Password)
    $Child = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
        -Credential $Credential -LoadUserProfile -PassThru -WorkingDirectory $Root `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $Bootstrap + '"')) `
        -RedirectStandardOutput (Join-Path $Root 'stdout.txt') -RedirectStandardError (Join-Path $Root 'stderr.txt')
    if (-not $Child.WaitForExit(240000)) { throw 'Ordinary descriptor test exceeded four minutes.' }
    $Child.Refresh()
    if ($Child.ExitCode -ne 0) { throw ('Ordinary descriptor test failed: ' + $Child.ExitCode) }
    $Receipt.passed = $true
} finally {
    if ($Child -and -not $Child.HasExited) {
        & taskkill.exe /PID $Child.Id /T /F | Out-Null
    }
    if ($Child) { $Child.Dispose() }
    foreach ($Name in @('installed.json', 'tests.xml', 'owner.json')) {
        $Result = Join-Path (Join-Path $Root 'windows37-evidence') $Name
        if (Test-Path -LiteralPath $Result) { Copy-Item -LiteralPath $Result -Destination $Evidence -Force }
    }
    foreach ($Name in @('stdout.txt', 'stderr.txt')) {
        $Output = Join-Path $Root $Name
        if (Test-Path -LiteralPath $Output) {
            Get-Content -LiteralPath $Output -Tail 35 | Write-Output
        }
    }
    if ($Account) {
        $Sid = $Account.SID.Value
        Remove-LocalUser -Name $AccountName
        $Receipt.account_removed = -not [bool](Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue)
        $Profile = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $Sid }
        if ($Profile) { $Profile | Remove-CimInstance }
        $Receipt.profile_removed = -not [bool](Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $Sid })
    }
    if (Test-Path -LiteralPath $Root) { Remove-Item -LiteralPath $Root -Recurse -Force }
    $Receipt.fixture_removed = -not (Test-Path -LiteralPath $Root)
    $Receipt | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Evidence 'cleanup.json') -Encoding UTF8
}
if (-not $Receipt.account_removed -or -not $Receipt.profile_removed -or -not $Receipt.fixture_removed) {
    throw 'Disposable ordinary account cleanup incomplete.'
}
