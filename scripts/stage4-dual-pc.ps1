[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('GenerateIdentity', 'Source', 'Receiver', 'Fetch', 'Verify')]
    [string]$Action,

    [string]$ExecutablePath = (Join-Path $PSScriptRoot 'clipferry.exe'),
    [string]$IdentityDirectory,
    [string]$IdentityCertificate,
    [string]$IdentityPrivateKey,
    [string]$PeerCertificate,
    [string]$PeerFingerprint,
    [string]$ListenAddress,
    [string]$ConnectAddress,
    [string]$SourceFile,
    [string]$OutputFile,
    [uint64]$OfferTtlSeconds = 900,
    [uint64]$TransferTtlSeconds = 3600,
    [uint64]$IoTimeoutSeconds = 30,
    [uint64]$LifetimeSeconds = 3600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ParameterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParameterName,
        [AllowEmptyString()]
        [string]$ParameterValue
    )

    if ([string]::IsNullOrWhiteSpace($ParameterValue)) {
        throw "-$ParameterName is required for action $Action."
    }
}

function Resolve-ExistingFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ParameterName,
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    Assert-ParameterValue -ParameterName $ParameterName -ParameterValue $FilePath
    $resolvedFile = Resolve-Path -LiteralPath $FilePath -ErrorAction Stop
    $fileItem = Get-Item -LiteralPath $resolvedFile.ProviderPath -Force
    if ($fileItem.PSIsContainer) {
        throw "-$ParameterName must name a file: $FilePath"
    }
    return $fileItem.FullName
}

function Resolve-Executable {
    return Resolve-ExistingFile -ParameterName 'ExecutablePath' -FilePath $ExecutablePath
}

function Get-TlsArguments {
    $identityCertPath = Resolve-ExistingFile -ParameterName 'IdentityCertificate' -FilePath $IdentityCertificate
    $identityKeyPath = Resolve-ExistingFile -ParameterName 'IdentityPrivateKey' -FilePath $IdentityPrivateKey
    $peerCertPath = Resolve-ExistingFile -ParameterName 'PeerCertificate' -FilePath $PeerCertificate
    Assert-ParameterValue -ParameterName 'PeerFingerprint' -ParameterValue $PeerFingerprint
    return @(
        '--identity-cert', $identityCertPath,
        '--identity-key', $identityKeyPath,
        '--peer-cert', $peerCertPath,
        '--peer-fingerprint', $PeerFingerprint
    )
}

function Invoke-ClipFerry {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $clipFerryExecutable = Resolve-Executable
    & $clipFerryExecutable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "clipferry.exe exited with code $LASTEXITCODE."
    }
}

switch ($Action) {
    'GenerateIdentity' {
        Assert-ParameterValue -ParameterName 'IdentityDirectory' -ParameterValue $IdentityDirectory
        $identityRoot = [System.IO.Path]::GetFullPath($IdentityDirectory)
        [System.IO.Directory]::CreateDirectory($identityRoot) | Out-Null
        $certificateOutput = Join-Path $identityRoot 'identity-cert.der'
        $privateKeyOutput = Join-Path $identityRoot 'identity-key.der'
        if ([System.IO.File]::Exists($certificateOutput) -or [System.IO.File]::Exists($privateKeyOutput)) {
            throw 'Identity output already exists; refusing to overwrite it.'
        }
        Invoke-ClipFerry -Arguments @(
            'identity-test-generate',
            '--cert-out', $certificateOutput,
            '--key-out', $privateKeyOutput
        )
    }
    'Source' {
        Assert-ParameterValue -ParameterName 'ListenAddress' -ParameterValue $ListenAddress
        $sourcePath = Resolve-ExistingFile -ParameterName 'SourceFile' -FilePath $SourceFile
        $tlsArguments = Get-TlsArguments
        Invoke-ClipFerry -Arguments (@(
            'secure-source-test',
            '--listen', $ListenAddress,
            '--file', $sourcePath,
            '--offer-ttl-seconds', $OfferTtlSeconds,
            '--transfer-ttl-seconds', $TransferTtlSeconds,
            '--io-timeout-seconds', $IoTimeoutSeconds,
            '--lifetime-seconds', $LifetimeSeconds
        ) + $tlsArguments)
    }
    'Receiver' {
        Assert-ParameterValue -ParameterName 'ConnectAddress' -ParameterValue $ConnectAddress
        $tlsArguments = Get-TlsArguments
        Invoke-ClipFerry -Arguments (@(
            'secure-receiver-test',
            '--connect', $ConnectAddress,
            '--io-timeout-seconds', $IoTimeoutSeconds,
            '--async-mode',
            '--lifetime-seconds', $LifetimeSeconds
        ) + $tlsArguments)
    }
    'Fetch' {
        Assert-ParameterValue -ParameterName 'ConnectAddress' -ParameterValue $ConnectAddress
        Assert-ParameterValue -ParameterName 'OutputFile' -ParameterValue $OutputFile
        $outputPath = [System.IO.Path]::GetFullPath($OutputFile)
        if ([System.IO.File]::Exists($outputPath)) {
            throw 'Fetch output already exists; refusing to overwrite it.'
        }
        $tlsArguments = Get-TlsArguments
        Invoke-ClipFerry -Arguments (@(
            'secure-fetch-test',
            '--connect', $ConnectAddress,
            '--output', $outputPath,
            '--io-timeout-seconds', $IoTimeoutSeconds
        ) + $tlsArguments)
    }
    'Verify' {
        $sourcePath = Resolve-ExistingFile -ParameterName 'SourceFile' -FilePath $SourceFile
        $outputPath = Resolve-ExistingFile -ParameterName 'OutputFile' -FilePath $OutputFile
        $sourceItem = Get-Item -LiteralPath $sourcePath
        $outputItem = Get-Item -LiteralPath $outputPath
        $sourceDigest = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
        $outputDigest = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
        [pscustomobject]@{
            SourceLength = $sourceItem.Length
            OutputLength = $outputItem.Length
            SourceSha256 = $sourceDigest
            OutputSha256 = $outputDigest
            Match = ($sourceItem.Length -eq $outputItem.Length -and $sourceDigest -eq $outputDigest)
        } | Format-List
        if ($sourceItem.Length -ne $outputItem.Length -or $sourceDigest -ne $outputDigest) {
            throw 'Files differ.'
        }
    }
}
