# SE Agent 虛擬顯示器（Virtual Display Driver 24.12.24 / MttVDD 11.30.4.434，MIT，
# 由 SignPath Foundation 簽章）的安裝／移除腳本。在「系統管理員」PowerShell 執行；在一般
# PowerShell 執行時會自己跳出 UAC 要求系統管理員權限（-Status 除外）：
#
#   powershell -ExecutionPolicy Bypass -File install-vdd.ps1             # 安裝（已安裝則修復）
#   powershell -ExecutionPolicy Bypass -File install-vdd.ps1 -Uninstall  # 完整移除
#   powershell -ExecutionPolicy Bypass -File install-vdd.ps1 -Status     # 只顯示狀態（不需管理員）
#
# 它做的事：驗證驅動檔案的 SHA-256 與簽章 → 寫入設定（只開 1 台 1920×1080@60 的虛擬螢幕）→
# 加入驅動程式並建立 Root\MttVDD 裝置 → 把虛擬螢幕放到你所有螢幕的「右下角外側」（只有角落相接，
# 滑鼠幾乎移不過去），主螢幕與你現有螢幕的位置、解析度都不變。
# 不會開啟測試簽章、不會關閉安全開機、不會把任何憑證加入信任清單。
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Status,
    [string]$DriverDir = '',
    [switch]$Relaunched
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 在參數預設值裡讀不到 $PSScriptRoot（是空字串），所以在這裡才決定驅動資料夾。
if (-not $DriverDir) { $DriverDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'driver' }

# 重新執行自己時要帶的參數。
function Self-Args {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-DriverDir', "`"$DriverDir`"")
    if ($Uninstall) { $a += '-Uninstall' }
    if ($Status) { $a += '-Status' }
    if ($Relaunched) { $a += '-Relaunched' }
    $a
}
# 32 位元 PowerShell（例如由 32 位元安裝程式啟動）看到的是 32 位元的登錄和 Program Files，
# 驅動讀不到：改用 64 位元 PowerShell 重新執行。
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    & (Join-Path $env:WINDIR 'sysnative\WindowsPowerShell\v1.0\powershell.exe') @(Self-Args)
    exit $LASTEXITCODE
}

$HwId     = 'Root\MttVDD'
$ConfDir  = Join-Path $env:ProgramFiles 'SEAgent\VirtualDisplay'
$RegKey   = 'HKLM:\SOFTWARE\MikeTheTech\VirtualDisplayDriver'
# 官方 release 25.7.23 的 VirtualDisplayDriver-x86.Driver.Only.zip 內容（x64 驅動）的 SHA-256。
$Pinned = @{
    'MttVDD.inf' = '550d211fe481e74dfe3f9d724ed78be48b3a9113405965d683d9373e8d672f5d'
    'MttVDD.dll' = 'c9ca837f57a98fbd43bc416a7f535a95843626e7759eaf85cf0cd7ce334dbb05'
    'mttvdd.cat' = '08a0093fc9b2e32b287a6f8a77ca4de0a31830d29fc33d2b13a918dc859468f6'
}
$Signer = 'CN=SignPath Foundation, O=SignPath Foundation, L=Lewes, S=Delaware, C=US'

# 用 Win32 API 建立裝置節點與調整螢幕位置（PowerShell 沒有內建指令可做）。
Add-Type -TypeDefinition @'
using System; using System.ComponentModel; using System.Runtime.InteropServices;
public static class SeagentVdd {
  [StructLayout(LayoutKind.Sequential)] struct DEVINFO { public int cb; public Guid Class; public int Inst; public IntPtr R; }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct DISPLAY_DEVICE {
    public int cb; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string Name;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string String; public int Flags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Id; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Key; }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct DEVMODE {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName; public short Spec, DrvVer, Size, Extra; public int Fields;
    public int X, Y, Orientation, FixedOutput; public short Color, Duplex, YRes, TT, Collate;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string Form; public short LogPixels;
    public int Bits, Width, Height, Flags, Hz, a, b, c, d, e, f, g, h; }
  [DllImport("setupapi.dll", SetLastError = true)] static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid g, IntPtr w);
  [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool SetupDiCreateDeviceInfoW(IntPtr s, string n, ref Guid g, string d, IntPtr w, int f, ref DEVINFO i);
  [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr s, ref DEVINFO i, int p, byte[] b, int n);
  [DllImport("setupapi.dll", SetLastError = true)] static extern bool SetupDiCallClassInstaller(int f, IntPtr s, ref DEVINFO i);
  [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr s);
  [DllImport("newdev.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr w, string id, string inf, int f, out bool reboot);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool EnumDisplayDevicesW(string d, int i, ref DISPLAY_DEVICE dd, int f);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool EnumDisplaySettingsW(string d, int m, ref DEVMODE dm);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int ChangeDisplaySettingsExW(string d, ref DEVMODE dm, IntPtr w, int f, IntPtr p);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int ChangeDisplaySettingsExW(string d, IntPtr dm, IntPtr w, int f, IntPtr p);
  // 每台螢幕一行：名稱|是否虛擬|是否在桌面上|是否主螢幕|X|Y|寬|高|更新率
  public static string[] Screens() {
    var o = new System.Collections.Generic.List<string>();
    for (int i = 0; ; i++) {
      var dd = new DISPLAY_DEVICE(); dd.cb = Marshal.SizeOf(typeof(DISPLAY_DEVICE));
      if (!EnumDisplayDevicesW(null, i, ref dd, 0)) break;
      var dm = new DEVMODE(); dm.Size = (short)Marshal.SizeOf(typeof(DEVMODE));
      bool on = (dd.Flags & 1) != 0 && EnumDisplaySettingsW(dd.Name, -1, ref dm);
      o.Add(string.Join("|", dd.Name, dd.String.Contains("Virtual Display") || (dd.Id ?? "").ToUpper().Contains("MTTVDD"), on, (dd.Flags & 4) != 0, dm.X, dm.Y, dm.Width, dm.Height, dm.Hz));
    }
    return o.ToArray();
  }
  // 設定一台螢幕的位置與模式（CDS_UPDATEREGISTRY | CDS_NORESET，然後一次套用）。
  public static int Place(string name, int x, int y, int w, int h, int hz) {
    var dm = new DEVMODE(); dm.Size = (short)Marshal.SizeOf(typeof(DEVMODE));
    dm.Fields = 0x20 | 0x80000 | 0x100000 | 0x400000; dm.X = x; dm.Y = y; dm.Width = w; dm.Height = h; dm.Hz = hz;
    int r = ChangeDisplaySettingsExW(name, ref dm, IntPtr.Zero, 0x10000001, IntPtr.Zero);
    ChangeDisplaySettingsExW(null, IntPtr.Zero, IntPtr.Zero, 0, IntPtr.Zero);
    return r;
  }
  // 等同 devcon install：建立一個 Root 列舉的顯示卡裝置，再讓它套用這份 INF。
  public static bool CreateDevice(string hwid, string inf) {
    Guid g = new Guid("4d36e968-e325-11ce-bfc1-08002be10318");
    IntPtr s = SetupDiCreateDeviceInfoList(ref g, IntPtr.Zero);
    if (s == new IntPtr(-1)) throw new Win32Exception();
    try {
      DEVINFO i = new DEVINFO(); i.cb = Marshal.SizeOf(typeof(DEVINFO));
      if (!SetupDiCreateDeviceInfoW(s, "Display", ref g, null, IntPtr.Zero, 1, ref i)) throw new Win32Exception();
      byte[] id = System.Text.Encoding.Unicode.GetBytes(hwid + "\0\0");
      if (!SetupDiSetDeviceRegistryPropertyW(s, ref i, 1, id, id.Length)) throw new Win32Exception();
      if (!SetupDiCallClassInstaller(0x19, s, ref i)) throw new Win32Exception();
    } finally { SetupDiDestroyDeviceInfoList(s); }
    bool reboot;
    if (!UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, hwid, inf, 1, out reboot)) throw new Win32Exception();
    return reboot;
  }
}
'@

# 列出目前桌面上的螢幕：名稱、是不是虛擬螢幕、位置與大小。
function Get-Screens {
    [SeagentVdd]::Screens() | ForEach-Object {
        $f = $_ -split '\|'
        [pscustomobject]@{ Name = $f[0]; Virtual = $f[1] -eq 'True'; Attached = $f[2] -eq 'True'; Primary = $f[3] -eq 'True'
            X = [int]$f[4]; Y = [int]$f[5]; W = [int]$f[6]; H = [int]$f[7]; Hz = [int]$f[8] }
    }
}

function Show-Status {
    $dev = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.HardwareID -contains $HwId }
    $drv = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.HardWareID -eq $HwId } | Select-Object -First 1
    Write-Host "裝置：     $(if ($dev) { "$($dev.InstanceId) [$($dev.Status)]" } else { '（沒有）' })"
    Write-Host "驅動版本： $(if ($drv) { "$($drv.DriverVersion)（$($drv.InfName)，簽章者 $($drv.Signer)）" } else { '（沒有）' })"
    Get-Screens | Where-Object Attached | Format-Table Name, Virtual, Primary, X, Y, W, H, Hz -AutoSize | Out-String | Write-Host
}

if ($Status) { Show-Status; exit 0 }

# 這些步驟會改系統驅動，必須是系統管理員。
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    # 不是系統管理員：用 UAC 以系統管理員身分重新執行自己，等它結束並傳回它的結束碼。
    $a = @(Self-Args) + $(if (-not $Relaunched) { '-Relaunched' })
    try { $p = Start-Process powershell.exe -Verb RunAs -ArgumentList $a -Wait -PassThru } catch { Write-Host -ForegroundColor Red '需要系統管理員權限（UAC 被拒絕）。'; exit 2 }
    exit $p.ExitCode
}
# 自己跳出的系統管理員視窗結束時會自動關閉：先停幾秒讓人看到結果。
function Exit-Script([int]$code) { if ($Relaunched) { Start-Sleep -Seconds 8 }; exit $code }
trap { Write-Host -ForegroundColor Red "失敗：$_"; Exit-Script 5 }

if ($Uninstall) {
    # 1. 移除所有 Root\MttVDD 裝置（含已拔除的殘留），虛擬螢幕會立即消失。
    Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.HardwareID -contains $HwId } | ForEach-Object {
        Write-Host "移除裝置 $($_.InstanceId)"; pnputil /remove-device "$($_.InstanceId)" | Out-Null }
    # 2. 從驅動程式存放區刪除這個驅動套件（oemNN.inf）。
    Get-WindowsDriver -Online -ErrorAction SilentlyContinue | Where-Object { $_.OriginalFileName -like '*\mttvdd.inf' } | ForEach-Object {
        Write-Host "刪除驅動套件 $($_.Driver)"; pnputil /delete-driver $_.Driver /uninstall /force | Out-Null }
    # 3. 刪除設定與登錄機碼。
    Remove-Item -Recurse -Force $ConfDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $RegKey -ErrorAction SilentlyContinue
    # 上一層若已經空了也一併刪掉（不是空的就保留）。
    foreach ($d in (Split-Path $ConfDir), (Split-Path $RegKey)) { if (-not (Get-ChildItem $d -ErrorAction SilentlyContinue)) { Remove-Item $d -ErrorAction SilentlyContinue } }
    Write-Host '已移除虛擬顯示器。'; Show-Status; Exit-Script 0
}

# 1. 驗證檔案：SHA-256 必須等於上面釘選的值，.cat 與 .dll 必須是有效的 SignPath Foundation 簽章。
$DriverDir = (Resolve-Path $DriverDir).Path
foreach ($f in $Pinned.Keys) {
    $p = Join-Path $DriverDir $f
    if (-not (Test-Path $p)) { Write-Host -ForegroundColor Red "找不到 $p"; Exit-Script 3 }
    $h = (Get-FileHash -Algorithm SHA256 $p).Hash.ToLower()
    if ($h -ne $Pinned[$f]) { Write-Host -ForegroundColor Red "$f 的 SHA-256 不符（$h）"; Exit-Script 3 }
}
foreach ($f in 'mttvdd.cat', 'MttVDD.dll') {
    $sig = Get-AuthenticodeSignature (Join-Path $DriverDir $f)
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -ne $Signer) { Write-Host -ForegroundColor Red "$f 的簽章無效：$($sig.Status) $($sig.SignerCertificate.Subject)"; Exit-Script 3 }
}
Write-Host '檔案雜湊與簽章：OK'

# 2. 設定：放在只有系統管理員能寫的 Program Files 下，並用登錄機碼 VDDPATH 指給驅動
#    （預設的 C:\VirtualDisplayDriver 任何使用者都能建立，不安全）。只開 1 台 1920×1080@60。
New-Item -ItemType Directory -Force $ConfDir | Out-Null
@'
<?xml version='1.0' encoding='utf-8'?>
<vdd_settings>
  <monitors><count>1</count></monitors>
  <gpu><friendlyname>default</friendlyname></gpu>
  <global><g_refresh_rate>60</g_refresh_rate></global>
  <resolutions><resolution><width>1920</width><height>1080</height><refresh_rate>60</refresh_rate></resolution></resolutions>
  <options><CustomEdid>false</CustomEdid><PreventSpoof>false</PreventSpoof><EdidCeaOverride>false</EdidCeaOverride>
    <HardwareCursor>true</HardwareCursor><SDR10bit>false</SDR10bit><HDRPlus>false</HDRPlus><logging>false</logging><debuglogging>false</debuglogging></options>
</vdd_settings>
'@ | Set-Content -Encoding UTF8 (Join-Path $ConfDir 'vdd_settings.xml')
foreach ($k in (Split-Path $RegKey), $RegKey) { if (-not (Test-Path $k)) { New-Item $k | Out-Null } }
Set-ItemProperty $RegKey -Name VDDPATH -Value $ConfDir

# 3. 安裝驅動：先放進驅動程式存放區；沒有裝置就建立一個（已有則只更新驅動＝修復）。
#    Windows 若跳出「要安裝這個裝置軟體嗎？發行者：SignPath Foundation」，請按「安裝」。
$inf = Join-Path $DriverDir 'MttVDD.inf'
pnputil /add-driver "$inf" /install | Write-Host
$dev = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.HardwareID -contains $HwId }
if (-not $dev) {
    Write-Host '建立虛擬顯示器裝置…'
    if ([SeagentVdd]::CreateDevice($HwId, $inf)) { Write-Warning '需要重新開機才能完成。' }
} else {
    $dev | ForEach-Object { pnputil /enable-device "$($_.InstanceId)" | Out-Null; pnputil /restart-device "$($_.InstanceId)" | Out-Null }
}

# 4. 等虛擬螢幕出現，然後把它放到所有實體螢幕外框的右下角（只有一個角相接），
#    主螢幕與其他螢幕完全不動。
$v = $null
for ($i = 0; $i -lt 30 -and -not $v; $i++) { Start-Sleep -Milliseconds 500; $v = Get-Screens | Where-Object { $_.Virtual } | Select-Object -First 1 }
if (-not $v) { Write-Warning '虛擬螢幕還沒出現（可能需要重新開機）。'; Show-Status; Exit-Script 4 }
$real = @(Get-Screens | Where-Object { $_.Attached -and -not $_.Virtual })
$x = ($real | ForEach-Object { $_.X + $_.W } | Measure-Object -Maximum).Maximum
$y = ($real | ForEach-Object { $_.Y + $_.H } | Measure-Object -Maximum).Maximum
$r = [SeagentVdd]::Place($v.Name, [int]$x, [int]$y, 1920, 1080, 60)
if ($r -ne 0) { Write-Warning "調整虛擬螢幕位置失敗（$r），它仍可使用。" }

# 5. 驗證：印出裝置、驅動版本與螢幕配置（虛擬螢幕 Virtual=True，主螢幕不變）。
Write-Host '安裝完成：'
Show-Status
Exit-Script 0
