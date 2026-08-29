[CmdletBinding()]
param(
    [string]$ExecutablePath,
    [string]$DataRoot,
    [switch]$Stage6,
    [switch]$Stage7,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module Microsoft.PowerShell.Management -ErrorAction Stop
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
    $ExecutablePath = Join-Path $PSScriptRoot 'clipferry.exe'
}
if ([string]::IsNullOrWhiteSpace($DataRoot)) {
    # Stage 7 intentionally reuses the Stage 6 device store so the already verified pairing
    # remains valid after upgrading the test executable.
    $stageDirectory = if ($Stage6 -or $Stage7) { 'Stage6Test' } else { 'Stage5Test' }
    $DataRoot = Join-Path $env:LOCALAPPDATA "ClipFerry\$stageDirectory"
}

$script:IsTreeStage = $Stage6 -or $Stage7
$script:ExpectedExecutableSha256 = 'D6E40676A0D7404B9AC4F3F8B70C1DD4CDE3F4BA972386FF3FE41E56624F3030'
$configName = if ($Stage7) { 'stage7-menu.json' } elseif ($Stage6) { 'stage6-menu.json' } else { 'stage5-menu.json' }
$script:ConfigPath = Join-Path $DataRoot $configName
$script:SourceRoot = Join-Path $DataRoot 'source'
$script:ReceiveRoot = Join-Path $DataRoot 'receive'
$script:TreeName = if ($Stage7) { 'ClipFerry-Stage7-Recovery-2x512MiB' } else { 'ClipFerry-Stage6-Tree' }
$script:DefaultSource = if ($script:IsTreeStage) {
    Join-Path $script:SourceRoot $script:TreeName
}
else {
    Join-Path $script:SourceRoot 'ClipFerry-Stage5-Test.txt'
}

try {
    [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $OutputEncoding = [Console]::OutputEncoding
}
catch {
    # Restricted consoles may reject encoding changes; functionality is unaffected.
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

function Assert-Package {
    if (-not [System.IO.File]::Exists($ExecutablePath)) {
        throw "缺少 clipferry.exe：$ExecutablePath"
    }
    $actual = Get-Sha256Hex -FilePath $ExecutablePath
    if ($actual -ne $script:ExpectedExecutableSha256) {
        throw "clipferry.exe 版本不匹配。实际 SHA-256：$actual"
    }
}

function New-DefaultConfig {
    return [pscustomobject]@{
        ListenIp = ''
        PeerAddress = ''
        Port = '45232'
        LastSourceFile = $script:DefaultSource
        LastReceiveTree = (Join-Path $script:ReceiveRoot $script:TreeName)
        LastPeerFingerprint = ''
    }
}

function Get-TestConfig {
    $config = New-DefaultConfig
    if (-not [System.IO.File]::Exists($script:ConfigPath)) {
        return $config
    }
    try {
        $saved = Get-Content -LiteralPath $script:ConfigPath -Raw | ConvertFrom-Json
        foreach ($property in $config.PSObject.Properties) {
            $savedProperty = $saved.PSObject.Properties[$property.Name]
            if ($null -ne $savedProperty) {
                $property.Value = [string]$savedProperty.Value
            }
        }
        return $config
    }
    catch {
        throw "测试配置损坏，请保留现场并检查：$script:ConfigPath"
    }
}

function Save-TestConfig {
    param([Parameter(Mandatory = $true)]$Config)

    [System.IO.Directory]::CreateDirectory($DataRoot) | Out-Null
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

function Invoke-ClipFerry {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & $ExecutablePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "clipferry.exe 退出码为 $LASTEXITCODE。"
    }
}

function Write-DeterministicFile {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][int]$SizeMiB,
        [Parameter(Mandatory = $true)][int]$Seed
    )

    $expectedLength = [int64]$SizeMiB * 1MB
    if ([System.IO.File]::Exists($FilePath) -and
        (Get-Item -LiteralPath $FilePath).Length -eq $expectedLength) {
        return
    }
    $buffer = [byte[]]::new(1MB)
    $random = [System.Random]::new($Seed)
    $random.NextBytes($buffer)
    $stream = [System.IO.File]::Open(
        $FilePath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None
    )
    try {
        for ($index = 0; $index -lt $SizeMiB; $index++) {
            $stream.Write($buffer, 0, $buffer.Length)
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Initialize-Stage6Tree {
    if (-not $script:IsTreeStage) {
        return
    }
    if ($Stage7) {
        [System.IO.Directory]::CreateDirectory($script:DefaultSource) | Out-Null
        $first = Join-Path $script:DefaultSource 'large-a.bin'
        $second = Join-Path $script:DefaultSource 'large-b.bin'
        Write-Host '正在准备阶段 7 固定样本（首次约写入 512 MiB，请稍候）...' -ForegroundColor Yellow
        Write-DeterministicFile -FilePath $first -SizeMiB 512 -Seed 7001
        if (-not [System.IO.File]::Exists($second)) {
            New-Item -ItemType HardLink -Path $second -Target $first | Out-Null
        }
        elseif ((Get-Item -LiteralPath $second).Length -ne (Get-Item -LiteralPath $first).Length) {
            throw "阶段 7 样本长度异常，请检查：$second"
        }
        return
    }
    $unicodeDirectory = Join-Path $script:DefaultSource '资料-🚢'
    $nestedDirectory = Join-Path $unicodeDirectory '子目录'
    $emptyDirectory = Join-Path $script:DefaultSource '空目录'
    [System.IO.Directory]::CreateDirectory($nestedDirectory) | Out-Null
    [System.IO.Directory]::CreateDirectory($emptyDirectory) | Out-Null
    [System.IO.File]::WriteAllText(
        (Join-Path $script:DefaultSource '根目录-说明.txt'),
        "ClipFerry Stage 6 deterministic tree.`r`nUnicode: 你好，剪贴摆渡 🚢`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllBytes((Join-Path $nestedDirectory '0-byte.bin'), [byte[]]::new(0))
    [System.IO.File]::WriteAllText(
        (Join-Path $nestedDirectory 'Unicode-你好-🚢.txt'),
        "alpha`r`nbeta`r`ngamma`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Write-DeterministicFile -FilePath (Join-Path $unicodeDirectory 'alpha-32-MiB.bin') -SizeMiB 32 -Seed 6001
    Write-DeterministicFile -FilePath (Join-Path $nestedDirectory 'beta-32-MiB.bin') -SizeMiB 32 -Seed 6002
}

function Get-TreeManifest {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $root = (Resolve-Path -LiteralPath $RootPath).ProviderPath.TrimEnd('\')
    return @(Get-ChildItem -LiteralPath $root -Force -Recurse |
        ForEach-Object {
            $relative = $_.FullName.Substring($root.Length).TrimStart('\')
            if ($_.PSIsContainer) {
                "D|$relative"
            }
            else {
                $hash = Get-Sha256Hex -FilePath $_.FullName
                "F|$relative|$($_.Length)|$hash"
            }
        } |
        Sort-Object)
}

function Show-Stage6SourceManifest {
    Initialize-Stage6Tree
    Write-Host ''
    Write-Host "固定测试树：$script:DefaultSource" -ForegroundColor Cyan
    Get-TreeManifest -RootPath $script:DefaultSource | ForEach-Object { Write-Host $_ }
}

function Test-Stage6ReceivedTree {
    if (-not $script:IsTreeStage) {
        throw '该功能仅用于阶段 6/7。'
    }
    Initialize-Stage6Tree
    $config = Get-TestConfig
    $target = Read-Value -Prompt '粘贴后生成的完整根目录路径' -DefaultValue $config.LastReceiveTree
    $target = (Resolve-Path -LiteralPath $target).ProviderPath
    $config.LastReceiveTree = $target
    Save-TestConfig -Config $config
    $expected = @(Get-TreeManifest -RootPath $script:DefaultSource)
    $actual = @(Get-TreeManifest -RootPath $target)
    $difference = @(Compare-Object -ReferenceObject $expected -DifferenceObject $actual)
    if ($difference.Count -ne 0) {
        $difference | Format-Table -AutoSize | Out-Host
        throw '目录树不一致；上表 <= 仅源端应有，=> 仅接收端应有。'
    }
    Write-Host "TREE_VERIFY passed=true entries=$($expected.Count) root=$target" -ForegroundColor Green
}

function Initialize-Device {
    [System.IO.Directory]::CreateDirectory($DataRoot) | Out-Null
    [System.IO.Directory]::CreateDirectory($script:SourceRoot) | Out-Null
    [System.IO.Directory]::CreateDirectory($script:ReceiveRoot) | Out-Null
    if ($script:IsTreeStage) {
        Initialize-Stage6Tree
    }
    elseif (-not [System.IO.File]::Exists($script:DefaultSource)) {
        $content = "ClipFerry Stage 5 dual-PC pairing test.`r`nCreated: $([DateTime]::UtcNow.ToString('O'))`r`n"
        [System.IO.File]::WriteAllText($script:DefaultSource, $content, [System.Text.UTF8Encoding]::new($false))
    }

    Invoke-ClipFerry -Arguments @('device-init', '--store', $DataRoot)
    Invoke-ClipFerry -Arguments @('device-show', '--store', $DataRoot)
    Write-Host ''
    Write-Host '设备身份已由当前 Windows 用户的 DPAPI 持久保护，不需要交换证书文件。' -ForegroundColor Green
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

function Read-Port {
    param([Parameter(Mandatory = $true)][string]$DefaultValue)

    $text = Read-Value -Prompt '端口' -DefaultValue $DefaultValue
    $port = 0
    if (-not [int]::TryParse($text, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw '端口必须是 1 到 65535 之间的整数。'
    }
    return [string]$port
}

function Read-ListenIp {
    param([Parameter(Mandatory = $true)]$Config)

    $addresses = @(Get-PrivateIpv4Addresses)
    if ($addresses.Count -eq 0) {
        throw '没有找到可用的专用 IPv4 地址。'
    }
    Write-Host ''
    Write-Host '本机可用的专用 IPv4：'
    $addresses | Format-Table -AutoSize | Out-Host
    $defaultIp = $Config.ListenIp
    if ([string]::IsNullOrWhiteSpace($defaultIp)) {
        $defaultIp = [string]$addresses[0].IPAddress
    }
    $selected = Read-Value -Prompt '监听 IPv4' -DefaultValue $defaultIp
    if ($selected -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') {
        throw '监听地址必须是本机专用 IPv4。'
    }
    return $selected
}

function Get-TrustedPeers {
    $output = @(& $ExecutablePath trust-list --store $DataRoot 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "读取可信设备失败：$($output -join ' ')"
    }
    $peers = @()
    foreach ($line in $output) {
        $text = [string]$line
        if ($text -match '^PEER fingerprint=([^ ]+) label=(.+)$') {
            $peers += [pscustomobject]@{
                Fingerprint = $Matches[1]
                Label = $Matches[2]
            }
        }
    }
    return @($peers)
}

function Select-TrustedPeer {
    $peers = @(Get-TrustedPeers)
    if ($peers.Count -eq 0) {
        throw '当前没有可信设备，请先在两台电脑上完成配对。'
    }
    if ($peers.Count -eq 1) {
        Write-Host "目标设备：$($peers[0].Label)  $($peers[0].Fingerprint)" -ForegroundColor Cyan
        return [string]$peers[0].Fingerprint
    }

    Write-Host ''
    for ($index = 0; $index -lt $peers.Count; $index++) {
        Write-Host "[$($index + 1)] $($peers[$index].Label)  $($peers[$index].Fingerprint)"
    }
    $choiceText = Read-Value -Prompt '选择目标设备编号' -DefaultValue '1'
    $choice = 0
    if (-not [int]::TryParse($choiceText, [ref]$choice) -or $choice -lt 1 -or $choice -gt $peers.Count) {
        throw '设备编号无效。'
    }
    return [string]$peers[$choice - 1].Fingerprint
}

function Start-PairingListener {
    Initialize-Device
    $config = Get-TestConfig
    $ip = Read-ListenIp -Config $config
    $port = Read-Port -DefaultValue $config.Port
    $label = Read-Value -Prompt '给对端设备起一个本机显示名称' -DefaultValue '从机'
    $config.ListenIp = $ip
    $config.Port = $port
    Save-TestConfig -Config $config

    Write-Host ''
    Write-Host "正在监听 $ip`:$port。现在去另一台电脑选择 [3] 连接配对。" -ForegroundColor Yellow
    Write-Host '两边出现 PAIR 后，先核对 verify_code 完全相同，再在两边输入大写 YES。' -ForegroundColor Yellow
    Invoke-ClipFerry -Arguments @(
        'pair-listen', '--listen', "$ip`:$port", '--label', $label,
        '--store', $DataRoot, '--timeout-seconds', '300'
    )
}

function Start-PairingConnector {
    Initialize-Device
    $config = Get-TestConfig
    $defaultAddress = $config.PeerAddress
    if ([string]::IsNullOrWhiteSpace($defaultAddress)) {
        $defaultAddress = "192.168.1.2:$($config.Port)"
    }
    $address = Read-Value -Prompt '输入监听端显示的 IPv4:端口' -DefaultValue $defaultAddress
    $label = Read-Value -Prompt '给对端设备起一个本机显示名称' -DefaultValue '主机'
    $config.PeerAddress = $address
    if ($address -match ':(\d+)$') {
        $config.Port = $Matches[1]
    }
    Save-TestConfig -Config $config

    Write-Host ''
    Write-Host '连接后两边会显示 verify_code；完全相同才在两边输入大写 YES。' -ForegroundColor Yellow
    Invoke-ClipFerry -Arguments @(
        'pair-connect', '--connect', $address, '--label', $label,
        '--store', $DataRoot, '--timeout-seconds', '300'
    )
}

function Show-TrustedPeers {
    Invoke-ClipFerry -Arguments @('trust-list', '--store', $DataRoot)
}

function Revoke-TrustedPeer {
    $fingerprint = Select-TrustedPeer
    $answer = Read-Value -Prompt '输入 REVOKE 确认撤销该设备'
    if ($answer -ne 'REVOKE') {
        Write-Host '已取消。'
        return
    }
    Invoke-ClipFerry -Arguments @(
        'trust-revoke', '--store', $DataRoot, '--fingerprint', $fingerprint
    )
}

function Start-SecureSource {
    Initialize-Device
    $fingerprint = Select-TrustedPeer
    $config = Get-TestConfig
    $ip = Read-ListenIp -Config $config
    $port = Read-Port -DefaultValue $config.Port
    $sourcePath = Read-Value -Prompt '源文件路径' -DefaultValue $config.LastSourceFile
    $sourcePath = (Resolve-Path -LiteralPath $sourcePath).ProviderPath
    $sourceItem = Get-Item -LiteralPath $sourcePath -Force
    if ($sourceItem.PSIsContainer -and -not $script:IsTreeStage) {
        throw '阶段 5 当前仍只验收单文件。'
    }
    $config.ListenIp = $ip
    $config.Port = $port
    $config.LastSourceFile = $sourcePath
    Save-TestConfig -Config $config

    Write-Host ''
    if ($script:IsTreeStage) {
        Write-Host '源端将只发布目录清单；看到 READY 前不应读取文件内容。' -ForegroundColor Yellow
        Get-TreeManifest -RootPath $sourcePath | ForEach-Object { Write-Host $_ }
        Write-Host ''
    }
    Write-Host '源端启动后保持本窗口运行，可输入 status 或 quit。' -ForegroundColor Yellow
    Invoke-ClipFerry -Arguments @(
        'secure-source-test', '--listen', "$ip`:$port", '--file', $sourcePath,
        '--store', $DataRoot, '--peer-fingerprint', $fingerprint,
        '--lifetime-seconds', '3600'
    )
}

function Read-PeerAddress {
    param([Parameter(Mandatory = $true)]$Config)

    $defaultAddress = $Config.PeerAddress
    if ([string]::IsNullOrWhiteSpace($defaultAddress)) {
        $defaultAddress = "192.168.1.2:$($Config.Port)"
    }
    $address = Read-Value -Prompt '输入源端 READY 显示的 IPv4:端口' -DefaultValue $defaultAddress
    $Config.PeerAddress = $address
    Save-TestConfig -Config $Config
    return $address
}

function Start-SecureFetch {
    if ($script:IsTreeStage) {
        throw '阶段 6/7 的目录树请使用 [B] Explorer 原生粘贴，再用 [V] 逐项核对。'
    }
    Initialize-Device
    $fingerprint = Select-TrustedPeer
    $config = Get-TestConfig
    $address = Read-PeerAddress -Config $config
    [System.IO.Directory]::CreateDirectory($script:ReceiveRoot) | Out-Null
    $output = Join-Path $script:ReceiveRoot ("fetch-{0}.bin" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
    Invoke-ClipFerry -Arguments @(
        'secure-fetch-test', '--connect', $address, '--output', $output,
        '--store', $DataRoot, '--peer-fingerprint', $fingerprint,
        '--io-timeout-seconds', '30'
    )
    Get-Item -LiteralPath $output | Format-List FullName, Length | Out-Host
    Get-FileHash -Algorithm SHA256 -LiteralPath $output | Format-List Path, Hash | Out-Host
}

function Start-SecureReceiver {
    Initialize-Device
    $fingerprint = Select-TrustedPeer
    $config = Get-TestConfig
    $address = Read-PeerAddress -Config $config
    Write-Host ''
    Write-Host '看到 READY 后，在资源管理器空目录按 Ctrl+V。控制命令：status / pause / resume / cancel / quit' -ForegroundColor Yellow
    if ($Stage7) {
        Write-Host '传输开始后让本机网络断开 10 到 20 秒，再恢复同一个局域网；不要关闭本窗口。' -ForegroundColor Yellow
        Write-Host '恢复后等待粘贴完成，再输入 status；应看到 reconnect_attempts/recovered_commands 大于 0。' -ForegroundColor Yellow
    }
    $arguments = @(
        'secure-receiver-test', '--connect', $address,
        '--store', $DataRoot, '--peer-fingerprint', $fingerprint,
        '--io-timeout-seconds', $(if ($Stage7) { '5' } else { '30' }),
        '--recovery-seconds', $(if ($Stage7) { '180' } else { '120' }),
        '--async-mode', '--lifetime-seconds', '3600'
    )
    Invoke-ClipFerry -Arguments $arguments
}

function Show-Diagnostics {
    Write-Host ''
    Write-Host "EXE：$ExecutablePath"
    Write-Host "SHA-256：$(Get-Sha256Hex -FilePath $ExecutablePath)"
    Write-Host "数据目录：$DataRoot"
    Write-Host "系统：$([Environment]::OSVersion.VersionString)"
    Write-Host ''
    Invoke-ClipFerry -Arguments @('device-show', '--store', $DataRoot)
    Invoke-ClipFerry -Arguments @('trust-list', '--store', $DataRoot)
    Write-Host ''
    Get-PrivateIpv4Addresses | Format-Table -AutoSize | Out-Host
}

function Show-Menu {
    Clear-Host
    if ($Stage7) {
        Write-Host '# ClipFerry 阶段 7：短断网重连与按 offset 续传验收' -ForegroundColor Cyan
    }
    elseif ($Stage6) {
        Write-Host '# ClipFerry 阶段 6：多文件与文件夹验收' -ForegroundColor Cyan
    }
    else {
        Write-Host '# ClipFerry 阶段 5：持久配对与动态撤销验收' -ForegroundColor Cyan
    }
    Write-Host ''
    Write-Host '首次配对：两端 1 -> 主机 2 -> 从机 3 -> 核对同一 verify_code -> 两端输入 YES'
    if ($Stage7) {
        Write-Host '重连复核：主机 A -> 从机 B -> Ctrl+V -> 断网 10~20 秒 -> 恢复网络 -> 从机 V'
    }
    elseif ($Stage6) {
        Write-Host '目录树复核：主机 A -> 从机 B -> Explorer Ctrl+V -> 从机 V'
    }
    else {
        Write-Host '传输复核：主机 A -> 从机 F（基线）或 B（Explorer Ctrl+V）'
    }
    Write-Host ''
    Write-Host '[1] 初始化或显示本机持久身份'
    Write-Host '[2] 监听首次配对（主机先选）'
    Write-Host '[3] 连接首次配对（从机后选）'
    Write-Host '[4] 显示已配对设备'
    Write-Host '[5] 撤销一个已配对设备'
    Write-Host '[A] 启动安全源端'
    Write-Host '[B] 启动 Explorer 接收端'
    if ($script:IsTreeStage) {
        Write-Host '[C] 显示固定测试树及哈希'
        Write-Host '[V] 核对粘贴后的完整目录树'
    }
    else {
        Write-Host '[F] Fetch 基线下载'
    }
    Write-Host '[D] 显示诊断'
    Write-Host '[O] 打开测试数据目录'
    Write-Host '[0] 退出'
    Write-Host ''
}

Assert-Package
if ($SelfTest) {
    Write-Host "SELFTEST passed=true exe_sha256=$script:ExpectedExecutableSha256"
    exit 0
}

[System.IO.Directory]::CreateDirectory($DataRoot) | Out-Null
while ($true) {
    Show-Menu
    $choice = (Read-Host '请选择').Trim().ToUpperInvariant()
    try {
        switch ($choice) {
            '1' { Initialize-Device; Wait-ForMenu }
            '2' { Start-PairingListener; Wait-ForMenu }
            '3' { Start-PairingConnector; Wait-ForMenu }
            '4' { Show-TrustedPeers; Wait-ForMenu }
            '5' { Revoke-TrustedPeer; Wait-ForMenu }
            'A' { Start-SecureSource; Wait-ForMenu }
            'F' { Start-SecureFetch; Wait-ForMenu }
            'B' { Start-SecureReceiver; Wait-ForMenu }
            'C' { Show-Stage6SourceManifest; Wait-ForMenu }
            'V' { Test-Stage6ReceivedTree; Wait-ForMenu }
            'D' { Show-Diagnostics; Wait-ForMenu }
            'O' { Start-Process explorer.exe -ArgumentList @($DataRoot) }
            '0' { exit 0 }
            default { Write-Host '无效选项。' -ForegroundColor Yellow; Start-Sleep -Milliseconds 700 }
        }
    }
    catch {
        Write-Host ''
        Write-Host "操作失败：$($_.Exception.Message)" -ForegroundColor Red
        Write-Host ''
        Wait-ForMenu
    }
}
