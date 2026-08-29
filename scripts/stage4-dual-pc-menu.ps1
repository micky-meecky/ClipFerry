[CmdletBinding()]
param(
    [string]$ExecutablePath,
    [string]$RunnerPath,
    [string]$DataRoot = (Join-Path $env:LOCALAPPDATA 'ClipFerry\Stage4Test'),
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 may otherwise auto-load these modules in a nested
# script scope and then hide their exported commands when that scope exits.
Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
    $ExecutablePath = Join-Path $PSScriptRoot 'clipferry.exe'
}
if ([string]::IsNullOrWhiteSpace($RunnerPath)) {
    $RunnerPath = Join-Path $PSScriptRoot 'stage4-dual-pc.ps1'
}

$script:ExpectedExecutableSha256 = 'FC274BA8D0DFC997D83A2E863BD105F1D5A7678B9DAF6533BC4E8928E0FD63F7'
$script:ExpectedRunnerSha256 = '02F80505CD2C4EE097C79578DD6CF135F127FBB6ABC12BF545A07C392D6010E8'

try {
    [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Console]::OutputEncoding
}
catch {
    # Encoding setup is cosmetic; keep the test usable on restricted consoles.
}

function New-DefaultConfig {
    return [pscustomobject]@{
        PeerFingerprint = ''
        PeerCertificate = ''
        ListenIp = ''
        PeerAddress = ''
        Port = '45231'
        LastSourceFile = ''
    }
}

function Get-TestConfig {
    $defaults = New-DefaultConfig
    if (-not [System.IO.File]::Exists($script:ConfigPath)) {
        return $defaults
    }

    $saved = Get-Content -LiteralPath $script:ConfigPath -Raw | ConvertFrom-Json
    foreach ($property in $defaults.PSObject.Properties) {
        $savedProperty = $saved.PSObject.Properties[$property.Name]
        if ($null -ne $savedProperty) {
            $property.Value = [string]$savedProperty.Value
        }
    }
    return $defaults
}

function Save-TestConfig {
    param([Parameter(Mandatory = $true)]$Config)

    $Config | ConvertTo-Json | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
}

function Read-Value {
    param(
        [Parameter(Mandatory = $true)][string]$Prompt,
        [string]$DefaultValue = ''
    )

    if ([string]::IsNullOrWhiteSpace($DefaultValue)) {
        $value = Read-Host $Prompt
    }
    else {
        $value = Read-Host "$Prompt [$DefaultValue]"
        if ([string]::IsNullOrWhiteSpace($value)) {
            $value = $DefaultValue
        }
    }

    return $value.Trim().Trim('"')
}

function Wait-ForMenu {
    [void](Read-Host '按 Enter 返回菜单')
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    $stream = [System.IO.File]::OpenRead($FilePath)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha256.ComputeHash($stream)
        return (($digest | ForEach-Object { $_.ToString('X2') }) -join '')
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

function Format-CertificateFingerprint {
    param([Parameter(Mandatory = $true)][string]$CertificatePath)

    $digest = Get-Sha256Hex -FilePath $CertificatePath
    return (([regex]::Matches($digest, '..') | ForEach-Object { $_.Value }) -join ':')
}

function Normalize-Fingerprint {
    param([Parameter(Mandatory = $true)][string]$Fingerprint)

    $compact = ($Fingerprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($compact.Length -ne 64) {
        throw '完整 SHA-256 指纹应当包含 64 个十六进制字符。'
    }
    return (([regex]::Matches($compact, '..') | ForEach-Object { $_.Value }) -join ':')
}

function Assert-Package {
    if (-not [System.IO.File]::Exists($ExecutablePath)) {
        throw "缺少 clipferry.exe：$ExecutablePath"
    }
    if (-not [System.IO.File]::Exists($RunnerPath)) {
        throw "缺少 stage4-dual-pc.ps1：$RunnerPath"
    }

    $executableDigest = Get-Sha256Hex -FilePath $ExecutablePath
    if ($executableDigest -ne $script:ExpectedExecutableSha256) {
        throw "clipferry.exe 哈希不匹配：$executableDigest"
    }
    $runnerDigest = Get-Sha256Hex -FilePath $RunnerPath
    if ($runnerDigest -ne $script:ExpectedRunnerSha256) {
        throw "stage4-dual-pc.ps1 哈希不匹配：$runnerDigest"
    }
}

function Invoke-Runner {
    param([Parameter(Mandatory = $true)][hashtable]$Parameters)

    $invokeParameters = @{}
    foreach ($entry in $Parameters.GetEnumerator()) {
        $invokeParameters[$entry.Key] = $entry.Value
    }
    $invokeParameters.ExecutablePath = $ExecutablePath
    & $RunnerPath @invokeParameters
    if ($LASTEXITCODE -ne 0) {
        throw "验收程序退出码为 $LASTEXITCODE。"
    }
}

function Initialize-Identity {
    if (-not [System.IO.File]::Exists($script:IdentityCertificate) -or
        -not [System.IO.File]::Exists($script:IdentityPrivateKey)) {
        if ([System.IO.File]::Exists($script:IdentityCertificate) -or
            [System.IO.File]::Exists($script:IdentityPrivateKey)) {
            throw "身份文件不完整，请保留现场并检查：$script:IdentityRoot"
        }

        Invoke-Runner -Parameters @{
            Action = 'GenerateIdentity'
            IdentityDirectory = $script:IdentityRoot
        }
    }

    $fingerprint = Format-CertificateFingerprint -CertificatePath $script:IdentityCertificate
    Write-Host ''
    Write-Host '本机身份已就绪。' -ForegroundColor Green
    Write-Host "本机证书：$script:IdentityCertificate"
    Write-Host "本机私钥：$script:IdentityPrivateKey"
    Write-Host "完整指纹：$fingerprint" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '只把本机证书交给另一台电脑；绝对不要复制 identity-key.der。' -ForegroundColor Yellow
}

function Import-PeerIdentity {
    $sourceText = Read-Value -Prompt '输入对端 identity-cert.der 的路径'
    $source = (Resolve-Path -LiteralPath $sourceText).ProviderPath
    $item = Get-Item -LiteralPath $source -Force
    if ($item.PSIsContainer) {
        throw '对端证书路径不能是目录。'
    }

    $typedFingerprint = Normalize-Fingerprint -Fingerprint (Read-Value -Prompt '输入在对端屏幕上核对的完整指纹')
    $certificateFingerprint = Format-CertificateFingerprint -CertificatePath $source
    if ($typedFingerprint -ne $certificateFingerprint) {
        throw "指纹不匹配。输入：$typedFingerprint；证书实际：$certificateFingerprint"
    }

    [System.IO.Directory]::CreateDirectory($script:PeerRoot) | Out-Null
    Copy-Item -LiteralPath $source -Destination $script:PeerCertificate -Force

    $config = Get-TestConfig
    $config.PeerCertificate = $script:PeerCertificate
    $config.PeerFingerprint = $typedFingerprint
    Save-TestConfig -Config $config

    Write-Host ''
    Write-Host '对端证书和完整指纹已核对并保存。' -ForegroundColor Green
    Write-Host "保存位置：$script:PeerCertificate"
    Write-Host "对端指纹：$typedFingerprint"
}

function Assert-IdentityReady {
    param([Parameter(Mandatory = $true)]$Config)

    if (-not [System.IO.File]::Exists($script:IdentityCertificate) -or
        -not [System.IO.File]::Exists($script:IdentityPrivateKey)) {
        throw '本机身份尚未生成，请先选择菜单 1。'
    }
    if ([string]::IsNullOrWhiteSpace($Config.PeerFingerprint) -or
        [string]::IsNullOrWhiteSpace($Config.PeerCertificate) -or
        -not [System.IO.File]::Exists($Config.PeerCertificate)) {
        throw '对端身份尚未配置，请先选择菜单 2。'
    }

    $actual = Format-CertificateFingerprint -CertificatePath $Config.PeerCertificate
    if ($actual -ne (Normalize-Fingerprint -Fingerprint $Config.PeerFingerprint)) {
        throw '已保存的对端证书与指纹不一致，请重新导入。'
    }
}

function Get-PrivateIpv4Addresses {
    return @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {
            $_.AddressState -eq 'Preferred' -and
            $_.IPAddress -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
        } |
        Sort-Object InterfaceMetric |
        Select-Object InterfaceAlias, IPAddress)
}

function Test-PortValue {
    param([Parameter(Mandatory = $true)][string]$PortText)

    $parsed = 0
    if (-not [int]::TryParse($PortText, [ref]$parsed) -or $parsed -lt 1 -or $parsed -gt 65535) {
        throw '端口必须是 1 到 65535 之间的整数。'
    }
    return [string]$parsed
}

function New-DeterministicPatternFile {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][int64]$Length
    )

    if ($Length -le 0) {
        throw '确定性测试文件长度必须大于零。'
    }
    if ([System.IO.File]::Exists($FilePath)) {
        if ((Get-Item -LiteralPath $FilePath).Length -ne $Length) {
            throw "已有大文件长度不正确，请保留现场并检查：$FilePath"
        }
        return
    }

    $temporaryPath = "$FilePath.partial-$PID-$([Guid]::NewGuid().ToString('N'))"
    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )
        $buffer = [byte[]]::new(1MB)
        for ($index = 0; $index -lt $buffer.Length; $index++) {
            $buffer[$index] = [byte](1 + (($index * 131 + 17) % 251))
        }

        $written = [int64]0
        while ($written -lt $Length) {
            $count = [int][Math]::Min($buffer.Length, $Length - $written)
            $stream.Write($buffer, 0, $count)
            $written += $count
            if (($written % 64MB) -eq 0 -or $written -eq $Length) {
                Write-Progress `
                    -Activity '正在写入确定性非零大文件' `
                    -Status "$written / $Length bytes" `
                    -PercentComplete ([int](100 * $written / $Length))
            }
        }
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        [System.IO.File]::Move($temporaryPath, $FilePath)
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        if ([System.IO.File]::Exists($temporaryPath)) {
            [System.IO.File]::Delete($temporaryPath)
        }
        Write-Progress -Activity '正在写入确定性非零大文件' -Completed
    }
}

function New-TestFiles {
    $smallPath = Join-Path $script:SourceRoot 'ClipFerry-Small-Test.txt'
    $zeroPath = Join-Path $script:SourceRoot 'ClipFerry-Zero-Test.bin'

    if (-not [System.IO.File]::Exists($smallPath)) {
        [System.IO.File]::WriteAllText(
            $smallPath,
            "ClipFerry dual-PC test`r`n中文内容`r`n$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss'))",
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    if (-not [System.IO.File]::Exists($zeroPath)) {
        [System.IO.File]::WriteAllBytes($zeroPath, [byte[]]::new(0))
    }

    $sizeText = Read-Value -Prompt '大文件大小（MiB，暂停/取消建议 1024）' -DefaultValue '1024'
    $sizeMiB = 0
    if (-not [int]::TryParse($sizeText, [ref]$sizeMiB) -or $sizeMiB -lt 64 -or $sizeMiB -gt 16384) {
        throw '大文件大小必须是 64 到 16384 MiB。'
    }

    $largePath = Join-Path $script:SourceRoot "ClipFerry-Pattern-$sizeMiB-MiB.bin"
    $largeLength = [int64]$sizeMiB * 1MB
    New-DeterministicPatternFile -FilePath $largePath -Length $largeLength

    $config = Get-TestConfig
    if ([string]::IsNullOrWhiteSpace($config.LastSourceFile)) {
        $config.LastSourceFile = $smallPath
    }
    elseif ([System.IO.Path]::GetFileName($config.LastSourceFile) -like 'ClipFerry-Large-*-MiB.bin') {
        $config.LastSourceFile = $largePath
    }
    Save-TestConfig -Config $config

    Write-Host ''
    Write-Host '测试文件已就绪：' -ForegroundColor Green
    Get-Item -LiteralPath $zeroPath, $smallPath, $largePath |
        Select-Object FullName, Length |
        Format-Table -AutoSize
}

function Start-SourceWizard {
    $config = Get-TestConfig
    Assert-IdentityReady -Config $config

    $addresses = Get-PrivateIpv4Addresses
    if ($addresses.Count -eq 0) {
        throw '没有找到 RFC1918 专用 IPv4 地址。'
    }

    Write-Host ''
    Write-Host '本机可用的专用 IPv4：'
    $addresses | Format-Table -AutoSize

    $defaultIp = $config.ListenIp
    if ([string]::IsNullOrWhiteSpace($defaultIp)) {
        $defaultIp = [string]$addresses[0].IPAddress
    }
    $listenIp = Read-Value -Prompt '选择 A 端监听 IPv4' -DefaultValue $defaultIp
    $port = Test-PortValue -PortText (Read-Value -Prompt '监听端口' -DefaultValue $config.Port)

    $defaultSource = $config.LastSourceFile
    if ([string]::IsNullOrWhiteSpace($defaultSource)) {
        $defaultSource = Join-Path $script:SourceRoot 'ClipFerry-Small-Test.txt'
    }
    $sourceText = Read-Value -Prompt '源文件路径' -DefaultValue $defaultSource
    $sourcePath = (Resolve-Path -LiteralPath $sourceText).ProviderPath
    if ((Get-Item -LiteralPath $sourcePath).PSIsContainer) {
        throw '源文件路径不能是目录。'
    }

    $config.ListenIp = $listenIp
    $config.Port = $port
    $config.LastSourceFile = $sourcePath
    Save-TestConfig -Config $config

    Write-Host ''
    Write-Host 'A 源端即将启动。保持本窗口运行；可输入 status 或 quit。' -ForegroundColor Cyan
    Write-Host '如果出现防火墙提示，只允许“专用网络”，不要允许“公用网络”。' -ForegroundColor Yellow
    $sourceItem = Get-Item -LiteralPath $sourcePath
    Write-Host "源文件长度：$($sourceItem.Length) bytes"
    Write-Host "源文件 SHA-256：$(Get-Sha256Hex -FilePath $sourcePath)"
    Write-Host ''

    Invoke-Runner -Parameters @{
        Action = 'Source'
        ListenAddress = "${listenIp}:$port"
        SourceFile = $sourcePath
        IdentityCertificate = $script:IdentityCertificate
        IdentityPrivateKey = $script:IdentityPrivateKey
        PeerCertificate = $config.PeerCertificate
        PeerFingerprint = $config.PeerFingerprint
    }
}

function Read-PeerAddress {
    param([Parameter(Mandatory = $true)]$Config)

    $defaultAddress = $Config.PeerAddress
    if ([string]::IsNullOrWhiteSpace($defaultAddress)) {
        $defaultAddress = "192.168.1.2:$($Config.Port)"
    }
    $address = Read-Value -Prompt '输入 A 端地址（IPv4:端口）' -DefaultValue $defaultAddress
    if ($address -notmatch '^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$') {
        throw '地址格式应类似 192.168.1.23:45231。'
    }
    return $address
}

function Start-ReceiverWizard {
    $config = Get-TestConfig
    Assert-IdentityReady -Config $config
    $address = Read-PeerAddress -Config $config
    $config.PeerAddress = $address
    Save-TestConfig -Config $config

    Write-Host ''
    Write-Host 'B 接收端即将启动。看到 READY 后，在资源管理器空目录按 Ctrl+V。' -ForegroundColor Cyan
    Write-Host '控制命令：status / pause / resume / cancel / quit' -ForegroundColor Cyan
    Write-Host ''

    Invoke-Runner -Parameters @{
        Action = 'Receiver'
        ConnectAddress = $address
        IdentityCertificate = $script:IdentityCertificate
        IdentityPrivateKey = $script:IdentityPrivateKey
        PeerCertificate = $config.PeerCertificate
        PeerFingerprint = $config.PeerFingerprint
    }
}

function Start-FetchWizard {
    $config = Get-TestConfig
    Assert-IdentityReady -Config $config
    $address = Read-PeerAddress -Config $config
    $config.PeerAddress = $address
    Save-TestConfig -Config $config

    $output = Join-Path $script:ReceiveRoot "fetch-$([DateTime]::Now.ToString('yyyyMMdd-HHmmss-fff')).bin"
    Invoke-Runner -Parameters @{
        Action = 'Fetch'
        ConnectAddress = $address
        OutputFile = $output
        IdentityCertificate = $script:IdentityCertificate
        IdentityPrivateKey = $script:IdentityPrivateKey
        PeerCertificate = $config.PeerCertificate
        PeerFingerprint = $config.PeerFingerprint
    }

    Write-Host ''
    Write-Host 'Fetch 完成：' -ForegroundColor Green
    Get-Item -LiteralPath $output | Select-Object FullName, Length | Format-List
    [pscustomobject]@{
        Path = $output
        Sha256 = Get-Sha256Hex -FilePath $output
    } | Format-List
}

function Show-Diagnostics {
    Write-Host ''
    Write-Host '程序包哈希：' -ForegroundColor Cyan
    $packageFiles = @(
        $ExecutablePath,
        $RunnerPath,
        $PSCommandPath,
        (Join-Path $PSScriptRoot 'start-stage4-test.cmd')
    ) | Where-Object { [System.IO.File]::Exists($_) }
    $packageFiles | ForEach-Object {
        [pscustomobject]@{
            Path = $_
            Hash = Get-Sha256Hex -FilePath $_
        }
    } | Format-Table -AutoSize

    Write-Host '系统：' -ForegroundColor Cyan
    Get-ComputerInfo |
        Select-Object WindowsProductName, WindowsVersion, OsBuildNumber |
        Format-List

    Write-Host '网络配置：' -ForegroundColor Cyan
    Get-NetConnectionProfile |
        Select-Object InterfaceAlias, NetworkCategory, IPv4Connectivity |
        Format-Table -AutoSize

    Write-Host '专用 IPv4：' -ForegroundColor Cyan
    Get-PrivateIpv4Addresses | Format-Table -AutoSize

    Write-Host "测试数据目录：$DataRoot"
    if ([System.IO.File]::Exists($script:IdentityCertificate)) {
        Write-Host "本机指纹：$(Format-CertificateFingerprint -CertificatePath $script:IdentityCertificate)"
    }
    $config = Get-TestConfig
    if (-not [string]::IsNullOrWhiteSpace($config.PeerFingerprint)) {
        Write-Host "对端指纹：$($config.PeerFingerprint)"
    }
}

Assert-Package
$DataRoot = [System.IO.Path]::GetFullPath($DataRoot)
$script:IdentityRoot = Join-Path $DataRoot 'identity'
$script:IdentityCertificate = Join-Path $script:IdentityRoot 'identity-cert.der'
$script:IdentityPrivateKey = Join-Path $script:IdentityRoot 'identity-key.der'
$script:PeerRoot = Join-Path $DataRoot 'peer'
$script:PeerCertificate = Join-Path $script:PeerRoot 'peer-cert.der'
$script:SourceRoot = Join-Path $DataRoot 'source'
$script:ReceiveRoot = Join-Path $DataRoot 'receive'
$script:ConfigPath = Join-Path $DataRoot 'config.json'

[System.IO.Directory]::CreateDirectory($DataRoot) | Out-Null
[System.IO.Directory]::CreateDirectory($script:SourceRoot) | Out-Null
[System.IO.Directory]::CreateDirectory($script:ReceiveRoot) | Out-Null

if ($SelfTest) {
    Initialize-Identity
    $selfTestFingerprint = Format-CertificateFingerprint -CertificatePath $script:IdentityCertificate
    if ((Normalize-Fingerprint -Fingerprint $selfTestFingerprint) -ne $selfTestFingerprint) {
        throw 'Fingerprint self-test failed.'
    }
    $selfTestConfig = Get-TestConfig
    $selfTestConfig.Port = '45231'
    Save-TestConfig -Config $selfTestConfig
    if ((Get-TestConfig).Port -ne '45231') {
        throw 'Configuration self-test failed.'
    }
    $selfTestPattern = Join-Path $script:SourceRoot 'selftest-pattern.bin'
    New-DeterministicPatternFile -FilePath $selfTestPattern -Length 2MB
    $firstPatternDigest = Get-Sha256Hex -FilePath $selfTestPattern
    $sample = [System.IO.File]::ReadAllBytes($selfTestPattern)[0..4095]
    if (-not ($sample | Where-Object { $_ -ne 0 } | Select-Object -First 1)) {
        throw 'Pattern file self-test produced only zero bytes.'
    }
    [System.IO.File]::Delete($selfTestPattern)
    New-DeterministicPatternFile -FilePath $selfTestPattern -Length 2MB
    if ((Get-Sha256Hex -FilePath $selfTestPattern) -ne $firstPatternDigest) {
        throw 'Pattern file self-test is not deterministic.'
    }
    [System.IO.File]::Delete($selfTestPattern)
    Write-Host 'SELFTEST PASS' -ForegroundColor Green
    exit 0
}

while ($true) {
    Clear-Host
    Write-Host 'ClipFerry 阶段 4 双机交互验收' -ForegroundColor Cyan
    Write-Host '================================'
    Write-Host '首次使用顺序：两端 1 -> 交换证书 -> 两端 2 -> A 端 A -> B 端 F/B'
    Write-Host ''
    Write-Host '[1] 生成或显示本机身份'
    Write-Host '[2] 导入并核对对端证书'
    Write-Host '[3] 创建 0 B、小文件和大文件样本'
    Write-Host '[A] 启动 A 源端'
    Write-Host '[F] B 端 Fetch 基线下载'
    Write-Host '[B] 启动 B 接收端（Explorer Ctrl+V）'
    Write-Host '[D] 显示系统、网络和哈希诊断'
    Write-Host '[O] 打开本机测试数据目录'
    Write-Host '[0] 退出'
    Write-Host ''

    $selection = (Read-Host '请选择').Trim().ToUpperInvariant()
    if ($selection -eq '0') {
        break
    }

    try {
        switch ($selection) {
            '1' { Initialize-Identity }
            '2' { Import-PeerIdentity }
            '3' { New-TestFiles }
            'A' { Start-SourceWizard }
            'F' { Start-FetchWizard }
            'B' { Start-ReceiverWizard }
            'D' { Show-Diagnostics }
            'O' {
                Start-Process explorer.exe -ArgumentList "`"$DataRoot`""
                Write-Host "已打开：$DataRoot"
            }
            default { Write-Host '无法识别这个选项。' -ForegroundColor Yellow }
        }
    }
    catch {
        Write-Host ''
        Write-Host "操作失败：$($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ''
    Wait-ForMenu
}
