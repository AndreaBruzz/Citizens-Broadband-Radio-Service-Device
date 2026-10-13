#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'MutualTls')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'MutualTls')]
    [string]$ClientCa,
    [Parameter(Mandatory = $true, ParameterSetName = 'NoClientCert')]
    [switch]$AllowNoClientCertificate,
    [string]$RadioTrustBundle,
    [Parameter(Mandatory = $true, ParameterSetName = 'MutualTls')]
    [ValidatePattern('^[a-fA-F0-9]{64}$')]
    [string]$ClientRootSha256,
    [ValidatePattern('^root@[a-zA-Z0-9][a-zA-Z0-9.-]*$')]
    [string]$SshTarget,
    [ValidateRange(1, 65535)]
    [int]$SshPort = 22,
    [string]$IdentityFile,
    [string]$KnownHostsFile,
    [Parameter(Mandatory = $true)]
    [string]$ServerIp,
    [ValidateRange(1, 65535)]
    [int]$HttpsPort = 8443,
    [ValidatePattern('^/(opt|srv)/[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$')]
    [string]$RemoteDirectory = '/opt/winnf-mock-sas-lab',
    [ValidateSet('RS256', 'ES256')]
    [string]$CpiAlgorithm = 'RS256',
    [string]$OutputDirectory = '.\mock-sas-deploy-output\lab-server',
    [ValidateSet('registration-cpi-only', 'lab-positive')]
    [string]$Profile = 'registration-cpi-only',
    [string]$LabPositiveConfig,
    [ValidateSet('1', '2')]
    [string]$StateVersion = '1',
    [switch]$EnableOperatorControl,
    [switch]$PackageOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $PackageOnly.IsPresent -and -not $SshTarget) {
    throw 'Deployment requires explicit -SshTarget root@HOST; no host is selected by default.'
}
if ($PSCmdlet.ParameterSetName -eq 'NoClientCert' -and -not $AllowNoClientCertificate.IsPresent) {
    throw 'The no-client-certificate LAB mode requires an explicit true switch.'
}
$ip = [System.Net.IPAddress]::Parse($ServerIp)
if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'This deployment launcher requires an IPv4 SAN/address.'
}
$ServerIp = $ip.ToString()
$mutualTls = if ($AllowNoClientCertificate.IsPresent) { 'false' } else { 'true' }
if ($Profile -eq 'lab-positive') {
    if ($mutualTls -ne 'true' -or -not $LabPositiveConfig) {
        throw 'lab-positive requires mTLS and an explicit -LabPositiveConfig; no defaults or fallback.'
    }
    $policyPath = (Resolve-Path -LiteralPath $LabPositiveConfig).Path
    if ((Get-Item -LiteralPath $policyPath).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'LAB policy must not be a symlink/reparse point.'
    }
    $policyText = [IO.File]::ReadAllText($policyPath)
    if ($policyText -match '-----BEGIN') { throw 'LAB policy must be JSON, not certificate/key material.' }
    $policy = $policyText | ConvertFrom-Json
    if ($policy.labOnlyAcknowledged -isnot [bool] -or -not $policy.labOnlyAcknowledged -or
        $policy.rfContainmentAcknowledged -isnot [bool] -or -not $policy.rfContainmentAcknowledged) {
        throw 'lab-positive requires explicit LAB-only and verified RF-containment acknowledgments.'
    }
    if (-not $PSBoundParameters.ContainsKey('OutputDirectory')) {
        $OutputDirectory = '.\mock-sas-deploy-output\lab-positive'
    }
} elseif ($LabPositiveConfig) {
    throw '-LabPositiveConfig requires explicit -Profile lab-positive.'
}
$profileExplicit = if ($PSBoundParameters.ContainsKey('Profile')) { 'true' } else { 'false' }
if ($StateVersion -eq '2' -and $Profile -ne 'lab-positive') {
    throw 'StateVersion 2 is an explicit positive-session storage setting; registration-only has no persisted session.'
}
if ($EnableOperatorControl -and ($Profile -ne 'lab-positive' -or $StateVersion -ne '2')) {
    throw 'Operator controls require explicit lab-positive and migrated -StateVersion 2.'
}
$operatorControl = if ($EnableOperatorControl.IsPresent) { 'true' } else { 'false' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$tar = (Get-Command tar -CommandType Application -ErrorAction Stop).Source
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('winnf-mock-sas-package-' + [guid]::NewGuid().ToString('N'))
$remoteUpload = $null

function Invoke-Native([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Copy-PublicCa([string]$Path, [string]$Destination, [string]$ExpectedFingerprint = '') {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $text = [System.IO.File]::ReadAllText($resolved)
    $pattern = '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----'
    $certificates = [regex]::Matches($text, $pattern)
    if ($certificates.Count -eq 0 -or ([regex]::Replace($text, $pattern, '')).Trim()) {
        throw "Expected a public CA PEM bundle, not private keys: $resolved"
    }
    if ($ExpectedFingerprint) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $fingerprints = @($certificates | ForEach-Object {
                $der = [Convert]::FromBase64String($_.Groups[1].Value)
                -join ($sha.ComputeHash($der) | ForEach-Object { $_.ToString('x2') })
            })
            if ($fingerprints -notcontains $ExpectedFingerprint.ToLowerInvariant()) {
                throw 'The client CA does not contain the expected radio root SHA256 fingerprint.'
            }
        } finally { $sha.Dispose() }
    }
    Copy-Item -LiteralPath $resolved -Destination $Destination
}

function Protect-Output([string]$Directory) {
    if ($env:OS -ne 'Windows_NT') { throw 'Use this launcher on Windows; use the documented native Linux path elsewhere.' }
    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $isDirectory = (Get-Item -LiteralPath $Directory).PSIsContainer
    # Write only the DACL; preserving owner/audit data must not require SeSecurityPrivilege.
    $acl = if ($isDirectory) {
        New-Object System.Security.AccessControl.DirectorySecurity
    } else {
        New-Object System.Security.AccessControl.FileSecurity
    }
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
    if ($isDirectory) {
        $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    }
    $existing = Get-Acl -LiteralPath $Directory
    $existingRules = @($existing.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
    $unexpectedRules = @($existingRules | Where-Object {
        $_.IdentityReference.Value -notin @($sid, 'S-1-5-18') -or
        $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $_.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
        $_.InheritanceFlags -ne $inherit -or
        $_.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None
    })
    if ($existing.AreAccessRulesProtected -and $existingRules.Count -eq 2 -and $unexpectedRules.Count -eq 0) {
        if ($isDirectory) {
            foreach ($child in @(Get-ChildItem -LiteralPath $Directory -Force)) {
                $childRules = @((Get-Acl -LiteralPath $child.FullName).GetAccessRules(
                    $true, $true, [System.Security.Principal.SecurityIdentifier]))
                $unexpectedChildRules = @($childRules | Where-Object {
                    $_.IdentityReference.Value -notin @($sid, 'S-1-5-18') -or
                    $_.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
                    $_.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl
                })
                if ($childRules.Count -ne 2 -or $unexpectedChildRules.Count -ne 0) {
                    throw "Existing output child has unexpected permissions; review it or use a new output directory: $($child.FullName)"
                }
            }
        }
        return
    }
    foreach ($identity in @($sid, 'S-1-5-18')) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            (New-Object System.Security.Principal.SecurityIdentifier($identity)),
            [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Directory -AclObject $acl
}

try {
    $stage = Join-Path $work 'source'
    [void](New-Item -ItemType Directory -Path $stage)
    $files = @(
        '.dockerignore', 'Dockerfile.mock-sas', 'compose.mock-sas.yml', 'LICENSE',
        'compose.mock-sas.lab-positive.yml',
        'deploy\mock-sas\app.py', 'deploy\mock-sas\gunicorn.conf.py',
        'deploy\mock-sas\lab_protocol.py',
        'deploy\mock-sas\lab_state.py',
        'deploy\mock-sas\operator_control.py',
        'deploy\mock-sas\offline-image-check.py', 'deploy\mock-sas\offline-image-check.sh',
        'deploy\mock-sas\test_lab.py', 'deploy\mock-sas\lab-certificates\README.md',
        'deploy\mock-sas\response_contracts.json', 'deploy\mock-sas\lab-positive.example.json',
        'deploy\mock-sas\generate_lab.py', 'deploy\mock-sas\deploy_support.py',
        'deploy\mock-sas\requirements.txt',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\cbrsPython\model\__init__.py',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\cbrsPython\model\CBRSRequestHandler.py',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\cbrsPython\model\Utils\__init__.py',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\cbrsPython\model\Utils\Assert.py',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\cbrsPython\model\Utils\Consts.py',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\cbrsPython\model\Utils\JsonComparisonUtils.py',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\Configuration\conf.xml',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\Configuration\CBSDconfig\cbsdc1.xml',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\Configuration\ObjectListConfig\laterDefindedOptional.json',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\jsonExpectedFolder\REG_SingleStep_CPI_Success_cbsd1.json',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\jsonExpectedFolder\OptionalParams\registrationOptional.json',
        'CBRS_Mock_SAS_Python_Master\cbrsPython-master\jsonExpectedFolder\OptionalParams\cpiSignatureDataSchema.json'
    )
    foreach ($operation in @('spectrumInquiry', 'grant', 'heartbeat', 'relinquishment', 'deregistration')) {
        $files += "CBRS_Mock_SAS_Python_Master\cbrsPython-master\jsonExpectedFolder\OptionalParams\${operation}Optional.json"
    }
    foreach ($scenario in @('HBT_spectrumInquiry_Cbsd', 'HBT_grant_Cbsd', 'HBT_heartbeat_GrantedState',
                            'RLQ_relinquish_success', 'DRG_Success')) {
        $files += "CBRS_Mock_SAS_Python_Master\cbrsPython-master\jsonExpectedFolder\$scenario.json"
    }
    foreach ($relative in $files) {
        $source = Join-Path $repo $relative
        $item = Get-Item -LiteralPath $source
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw "Refusing a symlink/reparse-point package source: $source"
        }
        $destination = Join-Path $stage $relative
        [void](New-Item -ItemType Directory -Path (Split-Path $destination) -Force)
        Copy-Item -LiteralPath $source -Destination $destination
    }
    $inputDirectory = Join-Path $stage 'inputs'
    [void](New-Item -ItemType Directory -Path $inputDirectory)
    if ($mutualTls -eq 'true') { Copy-PublicCa $ClientCa (Join-Path $inputDirectory 'client-ca.pem') $ClientRootSha256 }
    if ($RadioTrustBundle) { Copy-PublicCa $RadioTrustBundle (Join-Path $inputDirectory 'radio-trust-bundle.pem') }
    if ($Profile -eq 'lab-positive') { Copy-Item -LiteralPath $policyPath -Destination (Join-Path $inputDirectory 'lab-policy.json') }
    $manifest = @(
        Get-ChildItem -LiteralPath $stage -File -Recurse | Sort-Object FullName | ForEach-Object {
            $relative = $_.FullName.Substring($stage.Length + 1).Replace('\', '/')
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $relative
        }
    )
    [System.IO.File]::WriteAllText((Join-Path $stage 'package.sha256'),
        (($manifest -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    $archive = Join-Path $work 'package.tar'
    Invoke-Native $tar @('-cf', $archive, '-C', $stage, '.')
    $archiveSha = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    $releaseId = (Get-FileHash -LiteralPath (Join-Path $stage 'package.sha256') -Algorithm SHA256).Hash.ToLowerInvariant()
    $output = [System.IO.Path]::GetFullPath($OutputDirectory)
    if ($output -eq $repo -or $output -eq [System.IO.Path]::GetPathRoot($output) -or
        $output -eq [Environment]::GetFolderPath('UserProfile')) {
        throw 'Use a dedicated private output directory, not the repository, home or drive root.'
    }
    [void](New-Item -ItemType Directory -Path $output -Force)
    foreach ($existing in @(Get-ChildItem -LiteralPath $output -Force)) {
        if ($existing.PSIsContainer -or $existing.Name -notmatch '^(radio-server-ca\.pem|radio-trust-bundle-with-lab\.pem|cpi-key\.pem|cpi-cert\.pem|device\.json|deployment\.json|package-[a-f0-9]{64}\.tar)$') {
            throw 'Output directory contains unrelated files; choose a dedicated private directory before changing its ACL.'
        }
    }
    Protect-Output $output
    foreach ($artifact in @(Get-ChildItem -LiteralPath $output -File)) { Protect-Output $artifact.FullName }
    if ($PackageOnly) {
        $packageOutput = Join-Path $output "package-$releaseId.tar"
        if (Test-Path -LiteralPath $packageOutput) {
            throw 'Package output already exists; choose a new output directory. No server was contacted.'
        }
        Copy-Item -LiteralPath $archive -Destination $packageOutput
        Write-Host "Offline package created: $packageOutput"
        Write-Host "Content release ID: $releaseId; no SSH connection, credential generation or deployment performed."
        return
    }
    $ssh = (Get-Command ssh -CommandType Application -ErrorAction Stop).Source
    $scp = (Get-Command scp -CommandType Application -ErrorAction Stop).Source
    Protect-Output $work
    $sshArgs = @('-p', [string]$SshPort)
    $scpArgs = @('-P', [string]$SshPort)
    if ($IdentityFile) {
        $identity = (Resolve-Path -LiteralPath $IdentityFile).Path
        $sshArgs += @('-i', $identity)
        $scpArgs += @('-i', $identity)
    }
    if ($KnownHostsFile) {
        $knownHosts = (Resolve-Path -LiteralPath $KnownHostsFile).Path
        $hostOptions = @('-o', 'StrictHostKeyChecking=yes', '-o', "UserKnownHostsFile=$knownHosts")
        $sshArgs += $hostOptions
        $scpArgs += $hostOptions
    }
    # Authentication and host-key checking use ordinary OpenSSH defaults.
    $payload = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'deploy-server.sh')).Replace("`r", '')
    $explicitPort = if ($PSBoundParameters.ContainsKey('HttpsPort')) { 'true' } else { 'false' }
    $preflight = "bash -s -- --preflight '$RemoteDirectory' '$HttpsPort' '$explicitPort' '$Profile' '$profileExplicit'"
    $lines = @(($payload + "`n# End of read-only preflight") | & $ssh @sshArgs -T $SshTarget $preflight)
    if ($LASTEXITCODE -ne 0) { throw 'Read-only host/Docker/coexistence preflight failed. No upload or package installation was attempted.' }
    $lines | ForEach-Object { Write-Host $_ }
    $selectedPort = @($lines | Where-Object { $_ -match '^SELECTED_HTTPS_PORT=[0-9]+$' })
    if ($selectedPort.Count -ne 1) { throw 'Unexpected port-selection output; refusing deployment.' }
    $HttpsPort = [int]$selectedPort[0].Split('=')[1]
    if ($HttpsPort -lt 1 -or $HttpsPort -gt 65535) { throw 'Invalid selected HTTPS port.' }
    $lines = @(& $ssh @sshArgs $SshTarget 'umask 077; mktemp -d /tmp/winnf-mock-sas-upload.XXXXXXXX')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the private upload directory after preflight.' }
    $remoteUpload = ($lines | Select-Object -Last 1).Trim()
    if ($remoteUpload -notmatch '^/tmp/winnf-mock-sas-upload\.[a-zA-Z0-9]+$') {
        throw 'Unexpected SSH preflight output; refusing upload.'
    }
    Invoke-Native $scp ($scpArgs + @($archive, "${SshTarget}:$remoteUpload/package.tar"))
    $command = "bash -s -- '$remoteUpload' '$RemoteDirectory' '$ServerIp' '$HttpsPort' '$mutualTls' '$archiveSha' '$CpiAlgorithm' '$($ClientRootSha256.ToLowerInvariant())' '$Profile' '$profileExplicit' '$StateVersion' '$operatorControl'"
    ($payload + "`n# End of deployment payload") | & $ssh @sshArgs -T $SshTarget $command
    if ($LASTEXITCODE -ne 0) {
        throw 'Remote deployment/check failed. Inspect the reported error and server logs; no radio configuration was changed.'
    }
    $exportDirectory = "$RemoteDirectory/releases/$releaseId/exports"
    $downloads = @(
        @("$exportDirectory/radio-server-ca.pem", 'radio-server-ca.pem'),
        @("$exportDirectory/cpi-cert.pem", 'cpi-cert.pem'),
        @("$exportDirectory/device.json", 'device.json'),
        @("$exportDirectory/deployment.json", 'deployment.json')
    )
    if ($RadioTrustBundle) {
        $bundleName = 'radio-trust-bundle-with-lab.pem'
        $downloads += ,@("$exportDirectory/$bundleName", $bundleName)
    }
    foreach ($download in $downloads) {
        $temporary = Join-Path $work $download[1]
        Invoke-Native $scp ($scpArgs + @("${SshTarget}:$($download[0])", $temporary))
        $destination = Join-Path $output $download[1]
        if (Test-Path -LiteralPath $destination) {
            if ((Get-FileHash $temporary).Hash -ne (Get-FileHash $destination).Hash) {
                throw "Existing local artifact differs; nothing overwritten: $destination. Use another output directory."
            }
        } else {
            Move-Item -LiteralPath $temporary -Destination $destination
        }
    }
    Protect-Output $output
    Write-Host "Deployment checks completed; endpoint https://${ServerIp}:$HttpsPort/v1.2/"
    Write-Host "Profile: $Profile. Positive LAB responses are not real RF authorization."
    Write-Host "Public radio artifacts only: $output. No CPI/server/client private key is downloaded."
    Write-Host 'The radio registration flow is NOT verified. Preserve its existing TLS alias and import the complete merged bundle only after backup.'
}
finally {
    if ($remoteUpload -and $remoteUpload -match '^/tmp/winnf-mock-sas-upload\.[a-zA-Z0-9]+$') {
        if (Get-Variable ssh -ErrorAction SilentlyContinue) {
            & $ssh @sshArgs $SshTarget "rm -rf -- '$remoteUpload'"
            if ($LASTEXITCODE -ne 0) { Write-Warning "Could not remove this upload directory: $remoteUpload" }
        }
    }
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
}
