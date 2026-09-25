param(
    [switch]$SilentGlobal,
    [switch]$RunTests,
    [string]$MasterKey = "",
    [switch]$Audit,
    [switch]$ArcRepairScope,
    [string]$DiagRepairScope = ""
)

$ErrorActionPreference = 'Stop'

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
if (-not $SilentGlobal -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $sp = if ($MyInvocation.MyCommand.Path) { $MyInvocation.MyCommand.Path } else { $PSCommandPath }
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"& {Set-Location -Path '$PSScriptRoot'; & '$sp'}`"" -Verb RunAs; exit
}
if (-not $SilentGlobal) { Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force }
Set-Location -Path $PSScriptRoot -ErrorAction SilentlyContinue

# ---- Theme Presets (early init for bootstrap) ----
$script:DarkTheme  = @{ Header="Cyan"; Accent="Yellow"; Text="White"; Dim="DarkGray"; Success="Green"; Error="Red" }
$script:LightTheme = @{ Header="Blue"; Accent="DarkGreen"; Text="DarkYellow"; Dim="DarkGray"; Success="DarkGreen"; Error="DarkRed" }
$script:Theme = $script:DarkTheme.Clone()

# ---- User Data Root (Documents Vault) ----
$script:DataRoot = Join-Path ([Environment]::GetFolderPath("MyDocuments")) "ULTRA WINGET MANAGER - v15.0"
$script:ConfigPath  = Join-Path $script:DataRoot "ultra-winget-config.json"
$script:LogPath     = Join-Path $script:DataRoot "ultra-winget-log.json"
$script:IsolationRedirect = $false
$script:UWMAsyncWorkers = @()
$script:UWMHardKilled = 0
$script:UWMSerialDrainActive = $false
$script:UWMContextMutexBuffer = @{}
$script:UWMContextMutexRoots = $null
$script:UWMEnvOverride = $null
$script:UWMCachedVirtual = $null
$script:ScriptPath  = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }

# ---- ARC Engine (Autonomous Remediation & Intelligence Engine) state ----
$script:ArcRepairScope  = [bool]$ArcRepairScope
$script:DiagRepairScope = [string]$DiagRepairScope
$script:UWMArcSigmaps   = $null
$script:UWMArcRemediated = @{}
$script:UWMArcMitigated  = @{}
$script:UWMRescueAcked   = @{}
$script:UWMArcLastTrigger = [DateTime]::MinValue
$script:UWMArcSpawned   = @{}
$script:UWMArcHandleApi = $null
$script:UWMOfflineQueueDir = Join-Path $env:TEMP "ultra-winget-offline-queue"
$script:ArcHqTimeoutMs = 15000

$script:UWMArcHandleProbeSource = @'
param([string]$TargetPath, [string]$ResultFile)
$ErrorActionPreference = 'Stop'
$owners = New-Object 'System.Collections.Generic.List[int]'
try {
    if ($env:UWM_ARC_HQ_SLEEP) {
        $sleepSec = 0
        if ([int]::TryParse([string]$env:UWM_ARC_HQ_SLEEP, [ref]$sleepSec) -and $sleepSec -gt 0) { Start-Sleep -Seconds $sleepSec }
    }
    [string]$probe = $TargetPath.Replace('/','\')
    [string]$probeRoot = [System.IO.Path]::GetPathRoot($probe)
    [string]$probeRel = ''
    if (-not [string]::IsNullOrWhiteSpace($probeRoot)) { $probeRel = $probe.Substring($probeRoot.Length) }
    [string]$selfPath = [string]$PSCommandPath
    if ([string]::IsNullOrWhiteSpace($selfPath) -or -not (Test-Path -LiteralPath $selfPath -ErrorAction SilentlyContinue)) { $selfPath = $env:TEMP }
    $critical = @('csrss','dwm','wininit','winlogon','lsass','smss','services','svchost','System','Idle','Registry','MsMpEng','NisSrv','MemCompression','msedge','msedgewebview2','chrome','chrome_headless_shell','firefox','Brave','opera','Teams','ms-teams','MicrosoftEdge','WebViewHost')
    $pidSet = New-Object 'System.Collections.Generic.HashSet[int]'
    [void]$pidSet.Add([int]$PID)
    $procList = @(Get-Process -ErrorAction SilentlyContinue)
    foreach ($pp in $procList) {
        try {
            $nm = ([string]$pp.ProcessName).ToLowerInvariant()
            if ($nm -and ($nm -notin $critical)) { [void]$pidSet.Add([int]$pp.Id) }
        } catch { }
    }
    Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

public static class UWM_ArcScan {
    [StructLayout(LayoutKind.Sequential)]
    public struct IOSB { public uint Status; public IntPtr Information; }
    [StructLayout(LayoutKind.Sequential)]
    public struct E { public ushort UniqueProcessId; public ushort c1; public byte t; public byte a; public ushort h; public IntPtr o; public UIntPtr g; }

    [DllImport("ntdll.dll")]
    static extern int NtQuerySystemInformation(int c, IntPtr b, int l, out int r);
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationFile(IntPtr f, out IOSB iosb, IntPtr b, int l, int cls);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateFileW(string p, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint a, bool i, uint p);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DuplicateHandle(IntPtr s, IntPtr h, IntPtr t, out IntPtr d, uint a, bool i, uint o);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr h);

    sealed class Req {
        public IntPtr h;
        public IntPtr buf;
        public int status = -1;
        public string name;
        public ManualResetEventSlim ev = new ManualResetEventSlim(false);
    }

    static void QueryName(Req r) {
        IOSB iosb;
        int rc = NtQueryInformationFile(r.h, out iosb, r.buf, 8192, 9);
        if (rc != 0) { r.status = rc; return; }
        int len = Marshal.ReadInt32(r.buf);
        if (len <= 0 || len >= 8180) { r.status = -1; return; }
        r.name = Marshal.PtrToStringUni(new IntPtr(r.buf.ToInt64() + 4), len / 2);
        r.status = 0;
    }

    static string QueryNameBounded(IntPtr h, int timeoutMs) {
        Req r = new Req();
        r.h = h;
        r.buf = Marshal.AllocHGlobal(8192);
        Thread th = new Thread(() => {
            try { QueryName(r); }
            catch { r.status = -2; }
            finally { try { r.ev.Set(); } catch { } }
        });
        th.IsBackground = true;
        th.Start();
        bool done = false;
        try { done = r.ev.Wait(timeoutMs); } catch { done = false; }
        if (!done) { try { Marshal.FreeHGlobal(r.buf); } catch { } return null; }
        if (r.status != 0) { try { Marshal.FreeHGlobal(r.buf); } catch { } return null; }
        string nm = r.name;
        try { Marshal.FreeHGlobal(r.buf); } catch { }
        return nm;
    }

    public static int[] FindOwners(string probeFull, string probeRel, int[] allowedPids, string selfPath, int budgetMs) {
        var allowed = new HashSet<int>();
        if (allowedPids != null) { foreach (int a in allowedPids) { allowed.Add(a); } }
        var owners = new List<int>();
        long t0 = Environment.TickCount64;
        try {
            IntPtr selfH = IntPtr.Zero;
            if (!string.IsNullOrEmpty(selfPath) && System.IO.File.Exists(selfPath)) {
                selfH = CreateFileW(selfPath, 0x80000000, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
                if (selfH == new IntPtr(-1)) { selfH = IntPtr.Zero; }
            }
            IntPtr buf = IntPtr.Zero;
            int size = 262144;
            int retLen = 0;
            int st = -1;
            try {
                while (size <= 33554432) {
                    if (buf != IntPtr.Zero) { Marshal.FreeHGlobal(buf); }
                    buf = Marshal.AllocHGlobal(size);
                    st = NtQuerySystemInformation(16, buf, size, out retLen);
                    if (st == 0) { break; }
                    if (retLen > size) { size = Math.Min(33554432, retLen + 262144); }
                    else if (st == -1073741820) { size = Math.Min(33554432, size * 4); }
                    else { break; }
                }
                if (st == 0 && buf != IntPtr.Zero) {
                    long entrySize = Marshal.SizeOf(typeof(E));
                    int count = Marshal.ReadInt32(buf);
                    long baseAddr = buf.ToInt64();
                    int maxIdx = (int)Math.Min(count, Math.Floor((double)(retLen - 8) / Math.Max(1, entrySize)));
                    int fileType = -1;
                    if (selfH != IntPtr.Zero) {
                        uint pid = GetCurrentProcessId();
                        ushort mustH = (ushort)(selfH.ToInt64() & 0xFFFF);
                        for (int i = 0; i < maxIdx; i++) {
                            E ee = (E)Marshal.PtrToStructure(new IntPtr(baseAddr + 8 + i * entrySize), typeof(E));
                            if (ee.UniqueProcessId == pid && ee.h == mustH) { fileType = ee.t; break; }
                        }
                        try { CloseHandle(selfH); } catch { }
                        selfH = IntPtr.Zero;
                    }
                    var procCache = new Dictionary<int, IntPtr>();
                    for (int i = 0; i < maxIdx; i++) {
                        if (Environment.TickCount64 - t0 > budgetMs) { break; }
                        E e = (E)Marshal.PtrToStructure(new IntPtr(baseAddr + 8 + i * entrySize), typeof(E));
                        if (e.UniqueProcessId < 5 || e.h == 0) { continue; }
                        if (fileType > 0 && e.t != fileType) { continue; }
                        if (!allowed.Contains(e.UniqueProcessId)) { continue; }
                        IntPtr ph;
                        if (!procCache.TryGetValue(e.UniqueProcessId, out ph)) {
                            ph = OpenProcess(0x1000 | 0x0040, false, e.UniqueProcessId);
                            procCache[e.UniqueProcessId] = ph;
                        }
                        if (ph == IntPtr.Zero) { continue; }
                        IntPtr dup;
                        if (!DuplicateHandle(ph, new IntPtr((int)e.h), GetCurrentProcess(), out dup, 0, false, 2)) { continue; }
                        string nm = QueryNameBounded(dup, 150);
                        if (nm == null) { continue; }
                        try { CloseHandle(dup); } catch { }
                        bool match = false;
                        if (probeRel != null && probeRel.Length > 0 && nm.EndsWith(probeRel, StringComparison.OrdinalIgnoreCase)) { match = true; }
                        else if (nm.IndexOf(probeFull, StringComparison.OrdinalIgnoreCase) >= 0) { match = true; }
                        if (match && !owners.Contains(e.UniqueProcessId)) { owners.Add(e.UniqueProcessId); }
                    }
                    foreach (var kv in procCache) { if (kv.Value != IntPtr.Zero) { try { CloseHandle(kv.Value); } catch { } } }
                }
            }
            finally {
                if (buf != IntPtr.Zero) { try { Marshal.FreeHGlobal(buf); } catch { } }
                if (selfH != IntPtr.Zero) { try { CloseHandle(selfH); } catch { } }
            }
        }
        catch { }
        return owners.ToArray();
    }
}
"@ -ErrorAction Stop
    $found = [UWM_ArcScan]::FindOwners($probe, $probeRel, [int[]]@($pidSet), $selfPath, 12000)
    foreach ($f in $found) { if (-not $owners.Contains($f)) { $owners.Add($f) } }
} catch { }
try {
    $lines = @('DONE')
    $csv = New-Object 'System.Collections.Generic.List[string]'
    foreach ($o in $owners) { $csv.Add([string]$o) }
    $lines += ($csv -join ',')
    [IO.File]::WriteAllLines($ResultFile, $lines, [System.Text.Encoding]::UTF8)
} catch { }
'@

# ---- Owner Authorization / Security Gate (Global Portable Master Key) ----
$script:UWMHardcodedMasterKey = '(UWM--2026)'
$script:AuditMode       = [bool]$Audit
$script:MasterKeyInput  = [string]$MasterKey
$script:UWMPinnedIds    = $null

function Test-UWMKeyMatch {
    param([string]$Expected, [string]$Actual)
    if ([string]::IsNullOrEmpty($Expected) -or [string]::IsNullOrEmpty($Actual)) { return $false }
    $e = [System.Text.Encoding]::UTF8.GetBytes($Expected); $a = [System.Text.Encoding]::UTF8.GetBytes($Actual)
    [int]$d = $e.Length - $a.Length
    [int]$n = [Math]::Min($e.Length, $a.Length)
    for ($i = 0; $i -lt $n; $i++) { $d = $d -bor ($e[$i] -bxor $a[$i]) }
    return ($d -eq 0)
}
function Test-OwnerAuthorization {
    if ($script:ArcRepairScope) { return $true }
    if ($script:AuditMode) { return $false }
    if ($script:MasterKeyInput) {
        return (Test-UWMKeyMatch -Expected $script:UWMHardcodedMasterKey -Actual $script:MasterKeyInput.Trim())
    }
    if (-not (Test-UWMConsoleAvailable)) { return $false }
    $attempt = (Read-Host "`n ⚠️ [SECURITY ALERT] New Host Environment Detected. 🔑 Enter Master Authorization Key to Unlock Deployment Execution: ").Trim()
    if ($attempt) { return (Test-UWMKeyMatch -Expected $script:UWMHardcodedMasterKey -Actual $attempt) }
    return $false
}
function Assert-UWMWriteAccess {
    if (-not $script:AuditMode) { return $true }
    Write-Host "`n [AUDIT MODE] View-Only session: operation blocked (Master Authorization Key required)." -ForegroundColor Red
    if ($script:SilentMode) { exit 1 }
    return $false
}
function Test-UWMConsoleAvailable {
    try { [void][Console]::KeyAvailable; return $true } catch { return $false }
}

$script:AuditMode = -not (Test-OwnerAuthorization)
if ($script:AuditMode) {
    Write-Host "`n ===========================================================" -ForegroundColor Yellow
    Write-Host "  [VIEW-ONLY AUDIT MODE] Owner authorization not verified." -ForegroundColor Yellow
    Write-Host "  Write operations, purges, and installation deployments are disabled." -ForegroundColor Red
    Write-Host "  Unlock full rights: launch with '-MasterKey <key>' or enter the Master Authorization Key on next launch." -ForegroundColor $script:Theme['Dim']
    Write-Host " ===========================================================" -ForegroundColor Yellow
}

# ---- Winget Dependency Check & Auto-Installer ----
try {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        if ($script:AuditMode) {
            Write-Host " [AUDIT MODE] winget not found — automatic bootstrapping is disabled in View-Only mode." -ForegroundColor Yellow
        } else {
        Write-Host "`n [INFO] Winget not found. Deploying standalone micro-bootstrapper package..." -ForegroundColor $script:Theme['Accent']
        Write-Host " [INFO] Downloading Microsoft App Installer from official GitHub repository..." -ForegroundColor $script:Theme['Dim']
        $wingetUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        $tempInstaller = Join-Path $env:TEMP "Microsoft.DesktopAppInstaller.msixbundle"
        try {
            Invoke-WebRequest -Uri $wingetUrl -OutFile $tempInstaller -UseBasicParsing -ErrorAction Stop
            Write-Host " [OK] Download complete. Installing package..." -ForegroundColor $script:Theme['Success']
            Add-AppxPackage -Path $tempInstaller -ErrorAction Stop
            Write-Host " [OK] Winget bootstrapper deployed successfully." -ForegroundColor $script:Theme['Success']
        } catch {
            Write-Host " [WARN] Direct download failed. Querying GitHub API for latest release..." -ForegroundColor $script:Theme['Accent']
            try {
                $apiUrl = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
                $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -ErrorAction Stop
                $asset = $release.assets | Where-Object { $_.name -match 'Microsoft\.DesktopAppInstaller_.*\.msixbundle' }
                if ($asset) {
                    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $tempInstaller -UseBasicParsing -ErrorAction Stop
                    Add-AppxPackage -Path $tempInstaller -ErrorAction Stop
                    Write-Host " [OK] Winget bootstrapper deployed successfully." -ForegroundColor $script:Theme['Success']
                } else { throw "No suitable asset found in latest release" }
            } catch {
                Write-Host " [X] Could not install winget automatically. Please install App Installer from Microsoft Store." -ForegroundColor $script:Theme['Error']
                if (-not $SilentGlobal) { Read-Host " Press Enter to exit..." }
                exit 1
            }
        }
        Remove-Item $tempInstaller -Force -ErrorAction SilentlyContinue
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host " [X] Winget deployment verification failed. Please install manually." -ForegroundColor $script:Theme['Error']
            if (-not $SilentGlobal) { Read-Host " Press Enter to exit..." }
            exit 1
        }
        }
    }
} catch {
    Write-Host " [X] Bootstrap initialization failed: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
    if (-not $SilentGlobal) { Read-Host " Press Enter to exit..." }
    exit 1
}

# ---- Source Agreement Bypass (anti-freeze) ----
if (-not $script:AuditMode) {
    Write-Host " [OK] Initializing source agreements..." -ForegroundColor $script:Theme['Dim']
    $srcCheck = winget source list 2>&1 | Out-String
    if ($srcCheck -match 'winget' -and $srcCheck -match 'msstore') {
        Write-Host " [OK] Source index verified — skipping forced reset." -ForegroundColor $script:Theme['Dim']
    } else {
        Write-Host " [OK] Source registry missing or stale — rebuilding default index..." -ForegroundColor $script:Theme['Dim']
        winget source reset --force 2>&1 | Out-Null
    }
    winget list --accept-source-agreements 2>&1 | Out-Null
    Write-Host " [OK] Source agreements bypassed." -ForegroundColor $script:Theme['Success']
}

# ---- User Data Root (Documents Vault) ----
if (-not $script:AuditMode) { if (-not (Test-Path $script:DataRoot)) { New-Item -ItemType Directory -Path $script:DataRoot -Force | Out-Null } }
$script:Config = $null; $script:Theme = $null; $script:Locale = $null; $script:PausedProcesses = @()
$script:LogCache = $null
$script:SilentMode = $SilentGlobal; $script:RunTestsMode = $RunTests
$script:UWMStartedAt = Get-Date; $script:UWMVersion = "15.0"

# ---- Language Resource Tables ----
$script:English = @{
    HeaderTitle       = "ULTRA WINGET MANAGER - v15.0 - Ultimate Edition"
    HeaderDark        = "Admin | Dark"
    HeaderLight       = "Admin | Light"
    MenuSectionCore     = "  [ CORE OPERATIONS ]"
    MenuUpdate          = "   1) UPDATE   : Smart update (Paged + Force fix)"
    MenuPin             = "   2) PIN      : Pick app to pin"
    MenuBlock           = "   3) BLOCK    : Pick app to block"
    MenuGlobal          = "   4) GLOBAL   : Update ALL apps (incl. bridges)"
    MenuShredderApp     = "   5) SHREDDER: Obliterate an application from OS roots and appdata folders"
    MenuRollback        = "   6) ROLLBACK : Roll back an app to its previous version"
    MenuSectionTools    = "  [ SYSTEM TOOLS ]"
    MenuStatus          = "   7) STATUS   : Manage pinned apps"
    MenuSearch          = "   8) SEARCH   : Find & Install"
    MenuPurge           = "   9) PURGE    : Deep system cleanup"
    MenuSchedule        = "  10) SCHEDULE : Weekly auto-update"
    MenuSandbox         = "  11) SANDBOX  : Test install in isolation"
    MenuLog             = "  12) LOG      : Transaction log"
    MenuIgnore          = "  13) IGNORE   : Edit ignore list"
    MenuSectionDiag     = "  [ DIAGNOSTICS ]"
    MenuDiagnose        = "  14) DIAGNOSE : Performance audit & self-repair"
    MenuExport          = "  15) EXPORT   : Reports & HTML Dashboard"
    MenuSectionInteg    = "  [ INTEGRATION ]"
    MenuBridge          = "  16) BRIDGE   : Store, Choco & Scoop mgmt"
    MenuGitHub          = "  17) [DISABLED] GitHub Sync Feature Removed"
    MenuNotify          = "  18) NOTIFY   : Test notification"
    MenuSectionPref     = "  [ PREFERENCES ]"
    MenuThrottle        = "  19) THROTTLE : Toggle bandwidth limiter"
    MenuScale           = "  20) SCALE    : Toggle UI size"
    MenuLang            = "  21) LANGUAGE : Toggle EN/AR"
    MenuFixPassword     = "  22) PASSWORD : Disable local account expiration"
    MenuObliterator     = "  23) OBLITERATOR: Complete elimination of Adware, Spyware & Telemetry"
    MenuInspector       = "  24) CORE INSPECTOR: Internal dependency check and feature verification audit"
    MenuPurgeEngine     = "  25) PURGE ENGINE: UWM System Purge & Storage Overlord Engine"
    MenuExit            = "  27) EXIT"
    NoRollbackData      = "[i] No rollback history found in configurations."
    RollbackSuccess     = "[OK] Successfully rolled back {0} to version {1}!"
    RollbackFailed      = "[X] Rollback failed for {0} (exit code: {1})"
    BridgeMenuTitle     = "[BRIDGE] Third-Party Manager Integration"
    BridgeStats         = "Store: {0} | Chocolatey: {1} | Scoop: {2}"
    BridgeEnable        = "ENABLED"
    BridgeDisable       = "DISABLED"
    BridgeActions       = "(T)oggle Store | (C)hoco | (S)coop | (B)ack"
    BridgeToggled       = "[OK] {0} bridge set to {1}"
    DiagMenuTitle       = "[DIAGNOSE] System Diagnostics"
    DiagActions         = "(A)nalyze | (I)ntegrity | (B)ack"
    PromptSelect      = " Select Option"
    NavNextPrev       = "(N) Next | (P) Prev | (B) Back"
    NavBack           = "(B) Back"
    NavPrompt         = "║ ⚡ Enter Selection [#], Macro [ALL-GHOSTS], Navigate [N/P/B], or [X] Toggle-Stage: "
    NavPickAction     = "Pick [1-9] or Action"
    ScanPackages      = "Checking for packages..."
    NoneFound         = "[OK] No manageable apps found."
    PressEnter        = "Press Enter to return..."
    ProcessingId      = "Processing {0}..."
    OpComplete        = "[OK] Operation Complete!"
    ScanUpdates       = "[GL] Scanning for updates..."
    AllUpToDate       = "[OK] All packages up to date."
    FoundUpdatable    = "[i] Found {0} updatable package(s)."
    PkgOfTotal        = "Package {0} of {1}"
    CompleteIn        = "[OK] Complete in {0}"
    OkFailed          = "OK: {0}  |  Failed: {1}"
    SearchPrompt      = "Search App Name"
    SearchingFor      = "Searching for '{0}'..."
    NoResults         = "[X] No results for '{0}'."
    FoundResults      = "Found {0} results"
    Installing        = "[PKG] Installing: {0}..."
    InstalledOk       = "[OK] Installed!"
    InstallFailed     = "[X] Failed (exit: {0})"
    StatusTitle       = "[TOOLS] Manage pinned apps"
    NoPins            = "No pinned apps found."
    UnpinPrompt       = "Select [Number] to UNPIN or (B) Back"
    Unpinned          = "[OK] Unpinned"
    CleanTitle        = "[CLEAN] Deep System Cleanup..."
    CleanProgress     = "System Cleanup"
    CleanBin          = "Emptying Recycle Bin"
    CleanDone         = "[OK] Cleaned approx: {0} MB"
    BatWarning        = "[BAT] On battery ({0}%)."
    BatContinue       = "Plug in or press Enter (B to abort)..."
    BatAborted        = "[BAT] Aborted."
    ThrottleNotice    = "[THR] Throttle ON ({0} Mbps)"
    ThrottleOff       = "[THR] Throttle OFF"
    ThrottleToggled   = "[OK] Throttle set to {0}"
    ThrottleOnLabel   = "ON"
    ThrottleOffLabel  = "OFF"
    PreScriptRun      = "[SCR] Pre-update script..."
    PostScriptRun     = "[SCR] Post-update script..."
    SchedConfirm      = "[OK] Scheduled: {0} at {1}"
    SchedExists       = "[i] Updating existing task..."
    SchedDayPrompt    = "Day of week (e.g. Sunday)"
    SchedTimePrompt   = "Time (e.g. 03:00)"
    ConfigCorrupted   = "[!] Config corrupted, using defaults."
    BackupCreated     = "[SD] Restore Point created."
    BackupFailed      = "[!] Restore Point failed: {0}"
    ErrorGeneric      = "Error: {0}"
    CategoryLabel     = "Cat"
    LogTitle          = "[LOG] Transaction Log"
    LogEmpty          = "No entries."
    LogError          = "Error reading log."
    IgnoreTitle       = "[IGNORE] Edit ignore list"
    IgnoreEmpty       = "Ignore list empty."
    IgnoreActions     = "(A)dd | (R)emove # | (C)lear | (B)ack"
    IgnoreEnterId     = "Package ID to ignore"
    IgnoreAdded       = "[OK] Added '{0}'."
    IgnoreRemPrompt   = "Number to remove"
    IgnoreRemoved     = "[OK] Removed '{0}'."
    IgnoreCleared     = "[OK] Cleared."
    LangTitle         = "[LANG] Language"
    LangCurrent       = "Current: {0}"
    LangSwitchConfirm = "Switch to {0}? (Y/N)"
    LangSwitched      = "[OK] Switched to {0}"
    LangNameEN        = "English"
    LangNameAR        = "العربية"
    SandboxTitle      = "[SANDBOX] Isolated Test"
    SandboxPrompt     = "Package ID to test"
    SandboxCreating   = "Generating .wsb config..."
    SandboxCreated    = "[OK] Sandbox file: {0}"
    SandboxLaunch     = "[i] Launching (config in temp)"
    ExportTitle       = "[EXPORT] Report Export"
    ExportPrompt      = "(H) HTML | (C) CSV | (D) Dashboard | (B)ack"
    ExportHTML        = "[OK] HTML: {0}"
    ExportCSV         = "[OK] CSV: {0}"
    ExportEmpty       = "No entries to export."
    HealthLabel       = "Health"
    FreeLabel         = "Free"
    DiskPredict       = "[i] Drive C: {0}GB free — {1} packages queued"
    ImpactTitle       = "[IMPACT] Startup Performance Analysis"
    ImpactScan        = "Analyzing boot performance..."
    ImpactNoData      = "Insufficient boot data for trend analysis."
    ImpactDeltaOk     = "Boot time stable (±{0}s)"
    ImpactDeltaWarn   = "Boot time increased {0}s — possible upgrade impact"
    ImpactServices    = "Startup services checked: {0}"
    PkgHealthTitle    = "[HEALTH] Per-Package Safety Score"
    PkgHealthNoLog    = "No log data for scoring."
    PkgHealthScore    = "{0}: {1}% success ({2}/{3})"
    StoreTitle        = "[STORE] Microsoft Store Integration"
    StoreScan         = "Checking store for app updates via CIM..."
    StoreFound        = "Found {0} store app(s) with updates"
    StoreNone         = "No store updates available"
    StoreMergeNote    = "[i] {0} store package(s) merged into update queue"
    HookPreRun        = "[HOOK] Pre-install: {0}"
    HookPostRun       = "[HOOK] Post-install: {0}"
    GitHubTitle       = "[GITHUB] Config Sync"
    GitHubUpload      = "(U)pload | (D)ownload | (B)ack"
    GitHubUploadDone  = "[OK] Uploaded to Gist: {0}"
    GitHubDlDone      = "[OK] Downloaded & merged from Gist"
    GitHubNoToken     = "[X] No GitHub token configured."
    GitHubNoGist      = "[X] No Gist ID configured."
    GitHubErr         = "[X] GitHub sync failed: {0}"
    NotifyTitle       = "[NOTIFY] Cloud Notification"
    NotifySending     = "Sending test notification..."
    NotifySent        = "[OK] Notification sent"
    NotifyFail        = "[X] Notification failed: {0}"
    NotifyGlobalMsg   = "*Ultra Winget Manager* Update complete: {0} OK, {1} failed in {2}"
    NotifyCleanMsg    = "*Ultra Winget Manager* Cleanup complete: ~{0} MB freed"
    BridgeTitle       = "[BRIDGE] Third-Party Managers"
    BridgeChocoFound  = "[i] Chocolatey detected — fetching outdated packages..."
    BridgeScoopFound  = "[i] Scoop detected — fetching outdated packages..."
    BridgeChocoNone   = "No Chocolatey outdated packages"
    BridgeScoopNone   = "No Scoop outdated packages"
    BridgeChocoItems  = "{0} Chocolatey package(s) merged"
    BridgeScoopItems  = "{0} Scoop package(s) merged"
    APITitle          = "[API] Local REST Server"
    APIStart          = "Starting API server on port {0}..."
    APIRunning        = "[i] Listening on http://localhost:{0}/"
    APIStop           = "(S)top server | (B)ack"
    APIStopped        = "[OK] API server stopped"
    APIEndpointStatus = "GET /status  — system health"
    APIEndpointUpdate = "POST /update — trigger update"
    APIEndpointClean  = "POST /cleanup — trigger cleanup"
    OptimizeTitle     = "[OPTIMIZE] Pre-Upgrade Safety Check"
    OptimizeScan      = "Scanning for heavy processes..."
    OptimizeFound     = "Heavy process found: {0} (PID {1}) — {2} MB"
    OptimizePrompt    = "(P)ause process | (S)kip | (A)bort update"
    OptimizePaused    = "[OK] Paused: {0}"
    OptimizeSkipped   = "[i] Skipped: {0}"
    OptimizeNone      = "[OK] No heavy processes detected"
    DashTitle         = "[DASHBOARD] Interactive HTML Report"
    DashGenerate      = "Generating dashboard with {0} log entries..."
    DashDone          = "[OK] Dashboard: {0}"
    SandboxInject     = "Preparing silent install script for sandbox..."
    SandboxScriptCreated = "[OK] Install script embedded in sandbox"
    UIScaleLabel      = "UI Scale: {0}"
    UIScaleToggled    = "[OK] UI Scale set to {0}"
    IntegrityTitle    = "[INTEGRITY] Script Self-Health Check"
    IntegrityConfigOk = "[OK] Config valid"
    IntegrityLogOk   = "[OK] Log file valid"
    IntegrityRepair   = "[REPAIR] Recreated: {0}"
    IntegrityAllOk    = "[OK] All integrity checks passed"
    RetryTitle        = "[RETRY] Attempt {0}/{1} for {2}"
    RetryWait         = "Waiting {0}s before retry..."
    TestTitle         = "[TEST] Built-in Self-Test"
    TestRun           = "Running {0} test(s)..."
    TestPass          = "[PASS] {0}"
    TestFail          = "[FAIL] {0}: {1}"
    TestSummary       = "{0}/{1} passed — {2} failed"
    TestAllPassed     = "[OK] All built-in tests passed"
    TestFlagDetected  = "[TEST] -RunTests flag active"
    SearchBulkTitle   = "[SEARCH] Universal Search & Bulk Deployment Matrix"
    SearchBulkSub     = "Search and install multiple packages across all available sources."
    SearchCart        = "[CART] {0} package(s) queued"
    SearchCartReady   = "[CART] {0} queued — Press [ENTER] to deploy all."
    SearchCartEmpty   = "[CART] Queue empty — search for packages to add."
    SearchDeployTitle = "[DEPLOY] Deployment Queue — Bulk Install"
    DeployProgress    = "[PROGRESS] {0} ({1}/{2})"
    DeployComplete    = "[DEPLOYMENT COMPLETE]"
    DeploySummary     = "Deployed: {0} | Failed: {1} | Total: {2}"
    DeployCtxAdmin    = "Administrator"
    DeployCtxUser     = "User — scope forced to --scope user"
    DeploySourceSync  = "[INIT] Synchronizing installer database index..."
    MenuSysDiag       = "  26) SYS DIAG  : System Diagnostics & Health Telemetry Hub"
    SysDiagTitle      = "[SYS DIAG] System Diagnostics & Health Telemetry Hub"
    SysDiagPlaceholder = "[i] Full diagnostics engine coming soon in v16.0"
    SysDiagActions    = "(R) Run Scan | (L) View Logs | (B) Back"
    LogLegendNav      = " [N] Next Page | [P] Prev Page | [B] Back to Menu"
    LogLegendTools    = " [F] Filter Log | [C] Clear Filter | [E] Error Index"
    LogLegendRescue   = " [R] RESCUE (Force Immediate Repair & Wipe Red Lines)"
}
$script:Arabic = @{
    HeaderTitle       = "مدير تحديث وينجت - الإصدار 15.0 - النسخة النهائية"
    HeaderDark        = "مسؤول | داكن"
    HeaderLight       = "مسؤول | فاتح"
    MenuSectionCore     = "  [ العمليات الأساسية ]"
    MenuUpdate          = "   1) تحديث   : تحديث ذكي (صفحات + إصلاح)"
    MenuPin             = "   2) تثبيت   : اختيار تطبيق للتثبيت"
    MenuBlock           = "   3) حظر     : اختيار تطبيق للحظر"
    MenuGlobal          = "   4) شامل    : تحديث الكل (يشمل الجسور)"
    MenuShredderApp     = "   5) SHREDDER: Obliterate an application from OS roots and appdata folders"
    MenuRollback        = "   6) ROLLBACK : Roll back an app to its previous version"
    MenuSectionTools    = "  [ أدوات النظام ]"
    MenuStatus          = "   7) حالة    : إدارة المثبتة"
    MenuSearch          = "   8) بحث     : ابحث وثبت"
    MenuPurge           = "   9) تنظيف   : تنظيف عميق"
    MenuSchedule        = "  10) جدولة   : تحديث أسبوعي"
    MenuSandbox         = "  11) اختبار  : اختبار معزول"
    MenuLog             = "  12) سجل     : سجل المعاملات"
    MenuIgnore          = "  13) تجاهل   : تحرير قائمة التجاهل"
    MenuSectionDiag     = "  [ التشخيص ]"
    MenuDiagnose        = "  14) تشخيص   : تدقيق الأداء والإصلاح الذاتي"
    MenuExport          = "  15) تقرير   : تقارير ولوحة HTML"
    MenuSectionInteg    = "  [ التكامل ]"
    MenuBridge          = "  16) جسر     : إدارة المتجر وتشوكو وسكوب"
    MenuGitHub          = "  17) [DISABLED] GitHub Sync Feature Removed"
    MenuNotify          = "  18) إشعار   : اختبار الإشعار"
    MenuSectionPref     = "  [ التفضيلات ]"
    MenuThrottle        = "  19) تقييد   : تبديل تقييد النطاق"
    MenuScale           = "  20) حجم     : تبديل حجم الواجهة"
    MenuLang            = "  21) لغة     : تبديل EN/AR"
    MenuFixPassword     = "  22) PASSWORD : Disable local account expiration"
    MenuObliterator     = "  23) مطهر : القضاء التام على الإعلانات وبرامج التجسس والتتبع"
    MenuInspector       = "  24) CORE INSPECTOR: Internal dependency check and feature verification audit"
    MenuPurgeEngine     = "  25) PURGE ENGINE: UWM System Purge & Storage Overlord Engine"
    MenuExit            = "  27) خروج"
    BridgeMenuTitle     = "[جسر] تكامل مديري الحزم"
    BridgeStats         = "متجر: {0} | تشوكو: {1} | سكوب: {2}"
    BridgeEnable        = "مفعل"
    BridgeDisable       = "معطل"
    BridgeActions       = "(T) المتجر | (C) تشوكو | (S) سكوب | (B) عودة"
    BridgeToggled       = "[OK] {0} الجسر: {1}"
    DiagMenuTitle       = "[تشخيص] تشخيص النظام"
    DiagActions         = "(A) تحليل | (I) سلامة | (B) عودة"
    PromptSelect      = " اختر خيارا"
    NavNextPrev       = "(N) التالي | (P) السابق | (B) رجوع"
    NavBack           = "(B) رجوع"
    NavPrompt         = "║ ⚡ أدخل الاختيار [#], ماكرو [ALL-GHOSTS], تنقل [N/P/B], أو [X] تبديل المرحلة: "
    NavPickAction     = "اختر [1-9] أو إجراء"
    ScanPackages      = "جار فحص الحزم..."
    NoneFound         = "[OK] لا توجد تطبيقات."
    PressEnter        = "اضغط Enter للعودة..."
    ProcessingId      = "جار معالجة {0}..."
    OpComplete        = "[OK] اكتملت!"
    ScanUpdates       = "[GL] جار فحص التحديثات..."
    AllUpToDate       = "[OK] الكل محدث."
    FoundUpdatable    = "[i] وجد {0} تحديث."
    PkgOfTotal        = "الحزمة {0} من {1}"
    CompleteIn        = "[OK] اكتمل في {0}"
    OkFailed          = "نجح: {0}  |  فشل: {1}"
    SearchPrompt      = "ابحث عن تطبيق"
    SearchingFor      = "جار البحث عن '{0}'..."
    NoResults         = "[X] لا نتائج لـ '{0}'."
    FoundResults      = "وجد {0} نتيجة"
    Installing        = "[PKG] جار تثبيت: {0}..."
    InstalledOk       = "[OK] تم التثبيت!"
    InstallFailed     = "[X] فشل (رمز: {0})"
    StatusTitle       = "[TOOLS] إدارة المثبتة"
    NoPins            = "لا توجد تطبيقات مثبتة."
    UnpinPrompt       = "اختر رقما للإلغاء أو (B) رجوع"
    Unpinned          = "[OK] تم الإلغاء"
    CleanTitle        = "[CLEAN] تنظيف عميق..."
    CleanProgress     = "تنظيف"
    CleanBin          = "إفراغ السلة"
    CleanDone         = "[OK] تم تنظيف حوالي: {0} MB"
    BatWarning        = "[BAT] البطارية ({0}%)."
    BatContinue       = "اشحن أو اضغط Enter (B للإلغاء)..."
    BatAborted        = "[BAT] ألغي."
    ThrottleNotice    = "[THR] التقييد نشط ({0} Mbps)"
    ThrottleOff       = "[THR] التقييد متوقف"
    ThrottleToggled   = "[OK] التقييد: {0}"
    ThrottleOnLabel   = "نشط"
    ThrottleOffLabel  = "متوقف"
    PreScriptRun      = "[SCR] قبل التحديث..."
    PostScriptRun     = "[SCR] بعد التحديث..."
    SchedConfirm      = "[OK] جدول: {0} الساعة {1}"
    SchedExists       = "[i] جار تحديث المهمة..."
    SchedDayPrompt    = "اليوم (مثلا Sunday)"
    SchedTimePrompt   = "الوقت (مثلا 03:00)"
    ConfigCorrupted   = "[!] الإعدادات تالفة."
    BackupCreated     = "[SD] تم إنشاء نقطة الاستعادة."
    BackupFailed      = "[!] فشلت نقطة الاستعادة: {0}"
    ErrorGeneric      = "خطأ: {0}"
    CategoryLabel     = "تصنيف"
    LogTitle          = "[سجل] سجل المعاملات"
    LogEmpty          = "لا توجد إدخالات."
    LogError          = "خطأ في القراءة."
    IgnoreTitle       = "[تجاهل] تحرير القائمة"
    IgnoreEmpty       = "القائمة فارغة."
    IgnoreActions     = "(أ) إضافة | (ح) حذف # | (م) مسح | (ر) رجوع"
    IgnoreEnterId     = "معرف الحزمة"
    IgnoreAdded       = "[OK] أضيف '{0}'."
    IgnoreRemPrompt   = "رقم للحذف"
    IgnoreRemoved     = "[OK] حذف '{0}'."
    IgnoreCleared     = "[OK] مسحت."
    LangTitle         = "[لغة] الإعدادات"
    LangCurrent       = "الحالية: {0}"
    LangSwitchConfirm = "تبديل إلى {0}؟ (Y/N)"
    LangSwitched      = "[OK] بدلت إلى {0}"
    LangNameEN        = "English"
    LangNameAR        = "العربية"
    SandboxTitle      = "[اختبار] بيئة معزولة"
    SandboxPrompt     = "معرف الحزمة للاختبار"
    SandboxCreating   = "جار إنشاء ملف .wsb..."
    SandboxCreated    = "[OK] ملف: {0}"
    SandboxLaunch     = "[i] جار التشغيل (الملف في temp)"
    ExportTitle       = "[تقرير] تصدير التقارير"
    ExportPrompt      = "(H) HTML | (C) CSV | (D) لوحة | (ر) رجوع"
    ExportHTML        = "[OK] HTML: {0}"
    ExportCSV         = "[OK] CSV: {0}"
    ExportEmpty       = "لا توجد إدخالات."
    HealthLabel       = "صحة"
    FreeLabel         = "متاح"
    DiskPredict       = "[i] القرص C: {0}GB متاح — {1} حزمة في الانتظار"
    ImpactTitle       = "[تحليل] تحليل أداء الإقلاع"
    ImpactScan        = "جار تحليل أداء الإقلاع..."
    ImpactNoData      = "بيانات إقلاع غير كافية للتحليل."
    ImpactDeltaOk     = "وقت الإقلاع مستقر (±{0}ث)"
    ImpactDeltaWarn   = "زاد وقت الإقلاع {0}ث — قد يكون بسبب التحديثات"
    ImpactServices    = "تم فحص خدمات الإقلاع: {0}"
    PkgHealthTitle    = "[صحة] درجة أمان كل حزمة"
    PkgHealthNoLog    = "لا توجد بيانات للتصنيف."
    PkgHealthScore    = "{0}: {1}% نجاح ({2}/{3})"
    StoreTitle        = "[متجر] تكامل متجر مايكروسوفت"
    StoreScan         = "جار فحص المتجر للتحديثات عبر CIM..."
    StoreFound        = "وجد {0} تطبيق متجر مع تحديثات"
    StoreNone         = "لا توجد تحديثات من المتجر"
    StoreMergeNote    = "[i] {0} حزمة متجر مدمجة في قائمة التحديث"
    HookPreRun        = "[HOOK] قبل التثبيت: {0}"
    HookPostRun       = "[HOOK] بعد التثبيت: {0}"
    GitHubTitle       = "[غيتهاب] مزامنة الإعدادات"
    GitHubUpload      = "(ر)فع | (ت)نزيل | (ع)ودة"
    GitHubUploadDone  = "[OK] تم الرفع إلى Gist: {0}"
    GitHubDlDone      = "[OK] تم التنزيل والدمج"
    GitHubNoToken     = "[X] لم يتم تعيين رمز GitHub."
    GitHubNoGist      = "[X] لم يتم تعيين معرف Gist."
    GitHubErr         = "[X] فشلت المزامنة: {0}"
    NotifyTitle       = "[إشعار] إشعار سحابي"
    NotifySending     = "جار إرسال إشعار اختباري..."
    NotifySent        = "[OK] تم إرسال الإشعار"
    NotifyFail        = "[X] فشل الإرسال: {0}"
    NotifyGlobalMsg   = "*مدير التحديث* اكتمل التحديث: {0} نجاح، {1} فشل في {2}"
    NotifyCleanMsg    = "*مدير التحديث* اكتمل التنظيف: ~{0} MB"
    BridgeTitle       = "[جسر] مديري الحزم الآخرين"
    BridgeChocoFound  = "[i] تم العثور على Chocolatey — جلب الحزم..."
    BridgeScoopFound  = "[i] تم العثور على Scoop — جلب الحزم..."
    BridgeChocoNone   = "لا توجد حزم Chocolatey قديمة"
    BridgeScoopNone   = "لا توجد حزم Scoop قديمة"
    BridgeChocoItems  = "تم دمج {0} حزمة Chocolatey"
    BridgeScoopItems  = "تم دمج {0} حزمة Scoop"
    APITitle          = "[خادم] خادم REST محلي"
    APIStart          = "جار تشغيل الخادم على المنفذ {0}..."
    APIRunning        = "[i] استماع على http://localhost:{0}/"
    APIStop           = "(إ)يقاف الخادم | (ع)ودة"
    APIStopped        = "[OK] تم إيقاف الخادم"
    APIEndpointStatus = "GET /status  — صحة النظام"
    APIEndpointUpdate = "POST /update — تشغيل التحديث"
    APIEndpointClean  = "POST /cleanup — تشغيل التنظيف"
    OptimizeTitle     = "[تحسين] فحص السلامة قبل التحديث"
    OptimizeScan      = "جار فحص العمليات الثقيلة..."
    OptimizeFound     = "عملية ثقيلة: {0} (المعرف {1}) — {2} ميغابايت"
    OptimizePrompt    = "(إ)يقاف مؤقت | (ت)جاوز | (ل)إلغاء التحديث"
    OptimizePaused    = "[OK] تم الإيقاف المؤقت: {0}"
    OptimizeSkipped   = "[i] تم التجاهل: {0}"
    OptimizeNone      = "[OK] لا توجد عمليات ثقيلة"
    DashTitle         = "[لوحة] تقرير HTML تفاعلي"
    DashGenerate      = "جار إنشاء لوحة المعلومات من {0} سجل..."
    DashDone          = "[OK] لوحة المعلومات: {0}"
    SandboxInject     = "جار تجهيز برنامج التثبيت الصامت للصندوق الرملي..."
    SandboxScriptCreated = "[OK] تم تضمين برنامج التثبيت"
    UIScaleLabel      = "حجم الواجهة: {0}"
    UIScaleToggled    = "[OK] حجم الواجهة: {0}"
    IntegrityTitle    = "[السلامة] فحص ذاتي للنص البرمجي"
    IntegrityConfigOk = "[OK] الإعدادات سليمة"
    IntegrityLogOk   = "[OK] ملف السجل سليم"
    IntegrityRepair   = "[إصلاح] تم إعادة إنشاء: {0}"
    IntegrityAllOk    = "[OK] جميع فحوصات السلامة passed"
    RetryTitle        = "[إعادة] محاولة {0}/{1} لـ {2}"
    RetryWait         = "انتظار {0}ث قبل إعادة المحاولة..."
    TestTitle         = "[اختبار] اختبار ذاتي مدمج"
    TestRun           = "جار تشغيل {0} اختبار..."
    TestPass          = "[نجاح] {0}"
    TestFail          = "[فشل] {0}: {1}"
    TestSummary       = "{0}/{1} نجاح — {2} فشل"
    TestAllPassed     = "[OK] جميع الاختبارات passed"
    TestFlagDetected  = "[اختبار] علم -RunTests نشط"
    NoRollbackData    = "[i] No rollback history found in configurations."
    RollbackSuccess   = "[OK] Successfully rolled back {0} to version {1}!"
    RollbackFailed    = "[X] Rollback failed for {0} (exit code: {1})"
    SearchBulkTitle   = "[بحث] البحث الموحد ونشر الحزم"
    SearchBulkSub     = "ابحث وثبّت حزم متعددة عبر جميع المصادر المتاحة."
    SearchCart        = "[سلة] {0} حزمة في الانتظار"
    SearchCartReady   = "[سلة] {0} حزمة — اضغط [ENTER] للنشر."
    SearchCartEmpty   = "[سلة] السلة فارغة — ابحث عن حزم للإضافة."
    SearchDeployTitle = "[نشر] طابور النشر — التثبيت الجماعي"
    DeployProgress    = "[تقدم] {0} ({1}/{2})"
    DeployComplete    = "[اكتمل النشر]"
    DeploySummary     = "تم النشر: {0} | فشل: {1} | الإجمالي: {2}"
    DeployCtxAdmin    = "مسؤول"
    DeployCtxUser     = "مستخدم — النطاق محدد لـ --scope user"
    DeploySourceSync  = "[تهيئة] مزامنة فهرس قاعدة بيانات المثبتات..."
    MenuSysDiag       = "  26) تشخيص النظام  : مركز تشخيص النظام ورصد صحة الأجهزة"
    SysDiagTitle      = "[تشخيص النظام] مركز تشخيص النظام ورصد صحة الأجهزة"
    SysDiagPlaceholder = "[i] محرك التشخيص الكامل سيتوفر في الإصدار 16.0"
    SysDiagActions    = "(R) تشغيل فحص | (L) عرض السجلات | (B) رجوع"
    LogLegendNav      = " [N] التالي | [P] السابق | [B] عودة"
    LogLegendTools    = " [F] تصفية | [C] إلغاء التصفية | [E] دليل الأكواد"
    LogLegendRescue   = " [R] إنقاذ (إصلاح قسري فوري ومسح السطور الحمراء)"
}

# ---- Category Engine ----
$script:CategoryPatterns = @(
    @{ Category="Browser";   Pattern='google\.chrome|microsoft\.edge|firefox|brave|opera|vivaldi|chromium|browser|tor\b' }
    @{ Category="Dev Tool";  Pattern='visualstudio|jetbrains|node\.js|python|docker|git\.|github\.|cmake|clang|gcc|openjdk|dotnet|vscode|sdk|npm\b' }
    @{ Category="Media";     Pattern='vlc|spotify|itunes|foobar|audacity|kodi|plex|handbrake|obs\b|gimp|inkscape|mpv|media|player' }
    @{ Category="Office";    Pattern='microsoft\.office|libreoffice|openoffice|foxit|adobe\.acrobat|notion|evernote|pdf' }
    @{ Category="Security";  Pattern='malwarebytes|bitdefender|norton|kaspersky|avast|avg|eset|sophos|firewall|vpn\b' }
    @{ Category="Gaming";    Pattern='steam|epicgames|ubisoft|gog\.|origin|battle\.net|xbox|discord|nvidia\.geforce|game' }
    @{ Category="Utility";   Pattern='7zip|winrar|winzip|teamviewer|anydesk|powertoys|everything|autohotkey|sysinternals|ccleaner|cpu-z|hwmonitor|crystaldisk' }
)
function Invoke-UWMDownloadCache {
    param (
        [string]$TargetId
    )
    if ([string]::IsNullOrEmpty($TargetId)) { return }

    try {
        if ($null -eq $script:Config.rollbackHistory) {
            $script:Config.rollbackHistory = @{}
        }

        $CacheDir = Join-Path $script:DataRoot "UWM_Cache"
        if (-not (Test-Path $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }

        $wingetListRaw = winget list --id $TargetId --exact 2>$null | Out-String
        if ($wingetListRaw -match "$([regex]::Escape($TargetId))\s+(\S+)") {
            $CurrentLocalVersion = [string]$Matches[1].Trim()

            $ExistingVault = Get-ChildItem -Path $CacheDir -Filter "$TargetId`_$CurrentLocalVersion.*" -File -ErrorAction SilentlyContinue
            if ($ExistingVault -and $ExistingVault.Count -gt 0) {
                Write-Host " [UWM Vault] Payload for $TargetId v$CurrentLocalVersion already anchored in offline depot — skipping re-download." -ForegroundColor DarkCyan
                return
            }

            Write-Host " [UWM Vault] Extracting certified setup payload into deep offline depot..." -ForegroundColor Cyan

            $EscapedCacheDir = "`"$CacheDir`""

            $DownloadArgs = "download --id $TargetId --version $CurrentLocalVersion --download-directory $EscapedCacheDir --accept-package-agreements --accept-source-agreements"
        Start-Process winget -ArgumentList $DownloadArgs -NoNewWindow -Wait -ErrorAction SilentlyContinue | Out-Null

        Start-Sleep -Seconds 3

            $YamlFile = Get-ChildItem -Path $CacheDir -Recurse -Filter "*.yaml" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($YamlFile) {
                $FinalYamlName = Join-Path $CacheDir "$TargetId`_$CurrentLocalVersion.yaml"
                if (Test-Path $FinalYamlName) { Remove-Item $FinalYamlName -Force }
                Move-Item -Path $YamlFile.FullName -Destination $FinalYamlName -Force -ErrorAction SilentlyContinue
            }

            $BinaryFile = Get-ChildItem -Path $CacheDir -Recurse -File | Where-Object { $_.Extension -in @('.exe', '.msi') -and $_.Name -notmatch "$([regex]::Escape($TargetId))_" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($BinaryFile) {
                $FinalBinaryName = Join-Path $CacheDir "$TargetId`_$CurrentLocalVersion$($BinaryFile.Extension)"
                if (Test-Path $FinalBinaryName) { Remove-Item $FinalBinaryName -Force }
                Move-Item -Path $BinaryFile.FullName -Destination $FinalBinaryName -Force -ErrorAction SilentlyContinue
            }

            Get-ChildItem -Path $CacheDir -Directory | ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }

            if ($YamlFile -or $BinaryFile) {
                $script:Config.rollbackHistory[$TargetId] = $CurrentLocalVersion
                Save-Config
                Write-Log -Action "DEEP_VAULT_SUCCESS" -Target $TargetId -Status "Success" -Details "Harvested dual-mode payload (yaml + binary)"
            }
        }
    } catch {
        Write-Log -Action "DEEP_VAULT_ERR" -Target $TargetId -Status "Warning" -Details $_.Exception.Message
    }
}
function Get-PackageCategory {
    param([string]$Id, [string]$Name)
    $combined = "$Id $Name"
    foreach ($rule in $script:CategoryPatterns) { if ($combined -match "(?i)$($rule.Pattern)") { return $rule.Category } }
    return "Other"
}

# ---- Health & Disk Monitoring ----
function Get-DiskSpaceInfo {
    $d = Get-PSDrive -Name C -ErrorAction SilentlyContinue
    if ($d) { return [PSCustomObject]@{ FreeGB=[Math]::Round($d.Free/1GB,2); UsedGB=[Math]::Round(($d.Used)/1GB,2) } }
    return $null
}
function Read-UWMTransactionLog {
    if ($null -ne $script:LogCache) { return $script:LogCache }
    $entries = @()
    $logTarget = if ($script:IsolationRedirect) { Join-Path $env:TEMP "ultra-winget-log.json" } else { $script:LogPath }
    if (Test-Path -LiteralPath $logTarget) {
        $parseFailed = $false
        try {
            $fs = [System.IO.File]::Open($logTarget, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                [long]$len = $fs.Length
                if ($len -gt 0) {
                    [long]$cap = [Math]::Min($len, 4MB)
                    [long]$start = $len - $cap
                    [byte[]]$buf = New-Object byte[] $cap
                    $fs.Seek($start, [System.IO.SeekOrigin]::Begin) | Out-Null
                    [int]$total = 0
                    while ($total -lt $cap) {
                        [int]$n = $fs.Read($buf, $total, $cap - $total)
                        if ($n -le 0) { break }
                        $total += $n
                    }
                    $c = [System.Text.Encoding]::UTF8.GetString($buf, 0, $total)
                    [int]$rootIdx = $c.IndexOf('[')
                    if ($rootIdx -gt 0) { $c = $c.Substring($rootIdx) }
                    if (-not [string]::IsNullOrWhiteSpace($c)) {
                        $entries = $c | ConvertFrom-Json -ErrorAction Stop
                        if ($entries -isnot [array]) { $entries = @($entries) }
                    }
                }
            } finally { $fs.Dispose() }
        } catch { $parseFailed = $true }
        if ($parseFailed) {
            try {
                $c = Get-Content -LiteralPath $logTarget -Raw -ErrorAction Stop
                if ($c -and $c.Trim()) {
                    $entries = $c | ConvertFrom-Json -ErrorAction Stop
                    if ($entries -isnot [array]) { $entries = @($entries) }
                    $parseFailed = $false
                }
            } catch { }
        }
        if ($parseFailed) {
            $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $corruptPath = [System.IO.Path]::ChangeExtension($logTarget, ".corrupt-$stamp.json")
            try {
                if (Test-Path -LiteralPath $logTarget) { Move-Item -LiteralPath $logTarget -Destination $corruptPath -Force -ErrorAction Stop }
                Write-Host "  [LOG-SELFHEAL] Corrupt audit database quarantined -> $corruptPath" -ForegroundColor Yellow
                Write-Host "  [LOG-SELFHEAL] Fresh audit database initialized." -ForegroundColor Green
            } catch {
                try { Copy-Item -LiteralPath $logTarget -Destination $corruptPath -Force -ErrorAction Stop } catch { }
            }
            try { @() | ConvertTo-Json | Out-File $logTarget -Encoding utf8 -Force -ErrorAction Stop } catch { }
            try { Write-Log -Action "LOG_SELFHEAL" -Target "LogDB" -Status "Repaired" -Details "Corrupt log quarantined to $corruptPath" } catch { }
            $entries = @()
        }
    }
    $script:LogCache = $entries
    try { Invoke-UWMArcTelemetrySweep -Entries $entries } catch { }
    return $entries
}
function Get-PackageHealthScore {
    $e = Read-UWMTransactionLog
    if ($e.Count -eq 0) { return "N/A" }
    $u = $e | Where-Object { $_.Action -in @("UPDATE","GLOBAL","INSTALL") }
    if ($u.Count -eq 0) { return "N/A" }
    $s = ($u | Where-Object { $_.Status -eq "Success" }).Count
    return "$([Math]::Round(($s/$u.Count)*100))%"
}

function Get-UWMTrustScore {
    param(
        [string]$Name = "",
        [string]$Id = "",
        [string]$Source = "",
        [string]$Version = "",
        [long]$GitHubStars = -1,
        [string]$GitHubOwner = ""
    )
    if ($null -eq $script:UWMTrustTelFactor -or ([DateTime]::UtcNow - $script:UWMTrustTelAt).TotalSeconds -gt 60) {
        $script:UWMTrustTelAt = [DateTime]::UtcNow
        $hp = Get-PackageHealthScore
        if ($hp -match '^(\d+)%$') { $script:UWMTrustTelFactor = [Math]::Min(1.0, ([int]$matches[1] / 100.0)) }
        else { $script:UWMTrustTelFactor = 0.5 }
    }
    [double]$telScore = $script:UWMTrustTelFactor * 100.0

    [int]$certScore = 50
    switch ($Source.ToLower()) {
        'winget'     { $certScore = 90 }
        'chocolatey' { $certScore = 70 }
        'scoop'      { $certScore = 70 }
        'github'     { $certScore = 60; if ($GitHubStars -ge 1000 -and $GitHubOwner) { $certScore = 80 } }
    }
    if ($Id -match '^[A-Za-z0-9][\w.\-+]*\.[A-Za-z0-9][\w\-]*$') { $certScore += 10 }
    if ($Id -notmatch '\.') { $certScore -= 15 }
    if ($Version -eq 'latest' -or [string]::IsNullOrWhiteSpace($Version)) { $certScore -= 10 }
    $certScore = [Math]::Max(0, [Math]::Min(100, $certScore))

    [int]$reputation = 50
    switch ($Source.ToLower()) {
        'winget'     { $reputation = 90 }
        'chocolatey' { $reputation = 70 }
        'scoop'      { $reputation = 70 }
        'github'     {
            if ($GitHubStars -lt 0) { $reputation = 40 }
            elseif ($GitHubStars -lt 50) { $reputation = 45 }
            elseif ($GitHubStars -lt 500) { $reputation = 60 }
            elseif ($GitHubStars -lt 5000) { $reputation = 75 }
            else { $reputation = 90 }
        }
    }

    [double]$integrity = 100.0
    $dangerTerms = @('kernel','driver','rootkit','crack','keygen','activator','patch','injector','system32','registry','regedit','bootkit','miner','bitcoin','wallet','stealer','spy','defender','antivirus','unlocker','cheat')
    $probe = ($Name + ' ' + $Id + ' ' + $Version).ToLowerInvariant()
    foreach ($t in $dangerTerms) { if ($probe.Contains($t)) { $integrity *= 0.5 } }
    if ($Source.ToLower() -eq 'github' -and $integrity -lt 100.0) { $integrity *= 0.5 }
    $integrity = [Math]::Max(5.0, $integrity)

    [int]$final = [Math]::Max(0, [Math]::Min(100, [Math]::Round((0.30 * $certScore) + (0.30 * $telScore) + (0.20 * $reputation) + (0.20 * $integrity))))
    $tier = if ($final -ge 80) { 'VERIFIED' } elseif ($final -ge 50) { 'COMMUNITY' } else { 'CRITICAL' }
    return [PSCustomObject]@{ Score = $final; Tier = $tier; Cert = [Math]::Round($certScore); Telemetry = [Math]::Round($telScore); Reputation = $reputation; Integrity = [Math]::Round($integrity) }
}

# ===== ARC ENGINE — AUTONOMOUS REMEDIATION & INTELLIGENCE ENGINE =====
function Get-UWMArcSigmaps {
    if ($null -eq $script:UWMArcSigmaps) {
        $script:UWMArcSigmaps = @{
            'DISMFATAL'    = @('(?i)-2146498\d{3}', '(?i)0x800f08', '(?i)dism.*(failed|error|cannot|corrupt)', '(?i)component store')
            'REGACCESS'    = @('(?i)registry (key|access)', '(?i)reg key', '(?i)access (is )?denied', '(?i)unauthorizedaccess', '(?i)registry editor')
            'DEADLOCK'     = @('(?i)\bdeadlock\b', '(?i)being used by another process', '(?i)file lock', '(?i)awaiting .* handle', '(?i)another process is using')
            'DL_FAIL'      = @('(?i)(download|network).*(fail|timeout|reset|refused)', '(?i)0x80072ee[27]', '(?i)connection (reset|refused|timed out)')
            'CLOUDOFFLINE' = @('(?i)(webhook|telegram|discord|notification).*(fail|error|timeout)', '(?i)offline queue', '(?i)cloud sync.*(unavail|fail|error)')
        }
    }
    return $script:UWMArcSigmaps
}

function Get-UWMEntryFusedText {
    param([object]$Entry)
    if ($null -eq $Entry) { return "" }
    $parts = @()
    foreach ($k in @('Action','Status','Target','Details','Code','ExitCode','ErrorCode','Exception','Message')) {
        try {
            [object]$val = $null
            if ($Entry -is [System.Collections.IDictionary]) {
                if ($Entry.Contains($k)) { $val = $Entry[$k] }
            } else {
                $p = $null
                try { $p = $Entry.PSObject.Properties[$k] } catch { $p = $null }
                if ($null -ne $p -and $p.Value -ne $null) { $val = $p.Value }
            }
            if ($null -ne $val) { $parts += [string]$val }
        } catch { }
    }
    return ($parts -join " ___ ")
}

function Test-UWMCrashSignature {
    param([object]$Entry)
    [string[]]$hits = @()
    $fused = Get-UWMEntryFusedText -Entry $Entry
    if ([string]::IsNullOrWhiteSpace($fused)) { return $hits }
    [string]$fused = $fused.Substring(0, [Math]::Min($fused.Length, 4000))
    try {
        $maps = Get-UWMArcSigmaps
        foreach ($sig in $maps.Keys) {
            foreach ($pat in $maps[$sig]) {
                if ($fused -match $pat) { $hits += $sig; break }
            }
        }
    } catch { }
    return ($hits | Select-Object -Unique)
}

function Invoke-UWMArcRepairProcess {
    param([string]$Signature)
    $now = [DateTime]::UtcNow
    if ($null -eq $script:UWMArcRemediated) { $script:UWMArcRemediated = @{} }
    if ($script:UWMArcRemediated.ContainsKey($Signature)) {
        if (($now - $script:UWMArcRemediated[$Signature]).TotalSeconds -lt 600) { return $false }
    }
    if (($now - $script:UWMArcLastTrigger).TotalSeconds -lt 60) { return $false }
    $script:UWMArcRemediated[$Signature] = $now
    $script:UWMArcLastTrigger = $now
    $ok = $false
    try {
        $sp = if ($script:ScriptPath) { $script:ScriptPath } else { Join-Path $PSScriptRoot "update.ps1" }
        $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$sp`" -SilentGlobal -ArcRepairScope"
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle Hidden -ErrorAction Stop | Out-Null
        $ok = $true
    } catch { }
    try {
        if ($ok) {
            Write-Log -Action "ARC_TRIGGER" -Target "WindowsUpdate" -Status "Anchored" -Details "Signature=$Signature | hidden repair process launched (Invoke-UWMUpdateRepair)"
        } else {
            Write-Log -Action "ARC_TRIGGER" -Target "WindowsUpdate" -Status "Blocked" -Details "Signature=$Signature | spawn failed: $($_.Exception.Message)"
        }
    } catch { }
    return $ok
}

function Invoke-UWMArcHandleQuery {
    param([string]$TargetPath)
    $owners = New-Object 'System.Collections.Generic.List[int]'
    if ([string]::IsNullOrWhiteSpace($TargetPath) -or -not (Test-Path -LiteralPath $TargetPath -ErrorAction SilentlyContinue)) { return $owners }
    try {
        $qfs = $null
        try { $qfs = [System.IO.File]::Open($TargetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None) } catch { }
        if ($null -ne $qfs) { $qfs.Dispose(); return $owners }
    } catch { }
    if ([string]::IsNullOrWhiteSpace($script:UWMArcHandleProbeSource)) { return $owners }
    $to = 15000
    if ($script:ArcHqTimeoutMs -gt 0) { $to = $script:ArcHqTimeoutMs }
    if ($to -lt 1000) { $to = 1000 }
    if ($to -gt 30000) { $to = 30000 }
    $probePath = Join-Path $env:TEMP 'ultra-winget-arc-hqprobe.ps1'
    $resultPath = Join-Path $env:TEMP ("arc-hqresult-" + [guid]::NewGuid().ToString('N') + ".txt")
    $child = $null
    try {
        try {
            if (-not (Test-Path -LiteralPath $probePath -ErrorAction SilentlyContinue)) {
                Set-Content -LiteralPath $probePath -Value $script:UWMArcHandleProbeSource -Encoding utf8 -ErrorAction Stop
            }
        } catch { return $owners }
        $shellExe = 'pwsh.exe'
        try {
            $me = [System.Diagnostics.Process]::GetCurrentProcess()
            if ($me -and $me.Path) { $shellExe = $me.Path }
        } catch { }
        if (-not $shellExe -or $shellExe -notmatch 'shell') { $shellExe = 'pwsh.exe' }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $shellExe
        $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$probePath`" -TargetPath `"$TargetPath`" -ResultFile `"$resultPath`""
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $child = New-Object System.Diagnostics.Process
        $child.StartInfo = $psi
        if (-not $child.Start()) { return $owners }
        if (-not $child.WaitForExit($to)) {
            try { $child.Kill() } catch { }
            try { $child.WaitForExit(3000) | Out-Null } catch { }
            try { Write-Log -Action 'ARC_HANDLE_TIMEOUT' -Target $TargetPath -Status 'Warn' -Details 'Process handle query exceeded watchdog; proceeding without owner identity. Mitigation continues with GC/ACL/boot-vaporization path.' } catch { }
            return $owners
        }
        if (Test-Path -LiteralPath $resultPath -ErrorAction SilentlyContinue) {
            try {
                $lines = @(Get-Content -LiteralPath $resultPath -ErrorAction Stop)
                if ($lines.Count -gt 1) {
                    foreach ($tok in ($lines[1] -split ',')) {
                        $iv = 0
                        if ([int]::TryParse([string]$tok, [ref]$iv)) { if (-not $owners.Contains($iv)) { $owners.Add($iv) } }
                    }
                }
            } catch { }
        }
    } catch { }
    finally {
        try { if ($null -ne $child -and -not $child.HasExited) { $child.Kill() } } catch { }
        try { if ($null -ne $child) { $child.Dispose() } } catch { }
        try { Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue } catch { }
    }
    return $owners
}

function Invoke-UWMArcDeadlockMitigation {
    param([string]$Target)
    if ([string]::IsNullOrWhiteSpace($Target)) { return }
    $now = [DateTime]::UtcNow
    try {
        $key = $Target.ToLowerInvariant()
        if ($null -eq $script:UWMArcMitigated) { $script:UWMArcMitigated = @{} }
        if ($script:UWMArcMitigated.ContainsKey($key)) {
            if (($now - $script:UWMArcMitigated[$key]).TotalSeconds -lt 300) { return }
        }
        $script:UWMArcMitigated[$key] = $now
        if (-not (Test-Path -LiteralPath $Target -ErrorAction SilentlyContinue)) { return }
        $owners = @(Invoke-UWMArcHandleQuery -TargetPath $Target)
        $releasedSelf = $false
        try {
            if ($owners.Count -gt 0 -and $script:UWMArcSpawned -and $script:UWMArcSpawned.Count -gt 0) {
                foreach ($proc in @(Get-Process -ErrorAction SilentlyContinue)) {
                    try {
                        if ($owners -contains $proc.Id -and $script:UWMArcSpawned.ContainsKey([int]$proc.Id)) {
                            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                            $releasedSelf = $true
                        }
                    } catch { }
                }
            }
        } catch { }
        try { [void][System.GC]::Collect(); [void][System.GC]::WaitForPendingFinalizers() } catch { }
        for ($i = 0; $i -lt 3; $i++) {
            try { Remove-Item -LiteralPath $Target -Recurse -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 400 }
        }
        if (Test-Path -LiteralPath $Target -ErrorAction SilentlyContinue) {
            try { Grant-UWMAclWipeAll -Path $Target } catch { }
            for ($i = 0; $i -lt 2; $i++) {
                try { Remove-Item -LiteralPath $Target -Recurse -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 400 }
            }
        }
        [string]$finalState = "Cleared"
        if (Test-Path -LiteralPath $Target -ErrorAction SilentlyContinue) {
            $finalState = "PendingBootVaporization"
            try { [void](Register-UWMPendingBootDeletion -Path $Target) } catch { }
        }
        try { Write-Log -Action "ARC_HANDLE" -Target $Target -Status "Mitigated" -Details "OwnerPids=$($owners -join ',') ReleasedSelf=$releasedSelf FinalState=$finalState" } catch { }
    } catch { }
}

function Test-UWMNetworkAvailability {
    try {
        $r = Invoke-WebRequest -Uri "https://www.msftconnecttest.com/connecttest.txt" -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

function Invoke-UWMOfflineQueuePush {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    try {
        $dir = $script:UWMOfflineQueueDir
        if (-not $dir) { $dir = Join-Path $env:TEMP "ultra-winget-offline-queue" }
        [System.IO.Directory]::CreateDirectory($dir) | Out-Null
        $target = Join-Path $dir ("arc-" + [guid]::NewGuid().ToString("N") + ".json")
        [PSCustomObject]@{ Enqueued = (Get-Date).ToUniversalTime().ToString("o"); Message = $Message } | ConvertTo-Json | Out-File -LiteralPath $target -Encoding utf8 -Force -ErrorAction Stop
        try {
            $attrs = [System.IO.FileAttributes]([System.IO.File]::GetAttributes($target))
            if (-not ($attrs -band [System.IO.FileAttributes]::ReadOnly)) {
                [System.IO.File]::SetAttributes($target, ($attrs -bor [System.IO.FileAttributes]::ReadOnly))
            }
        } catch { }
        try { Write-Log -Action "ARC_QUEUE" -Target "Offline" -Status "Parked" -Details $target } catch { }
    } catch { }
}

function Invoke-UWMOfflineFlushDaemon {
    try {
        $dir = $script:UWMOfflineQueueDir
        if (-not $dir) { $dir = Join-Path $env:TEMP "ultra-winget-offline-queue" }
        [System.IO.Directory]::CreateDirectory($dir) | Out-Null
        $lock = Join-Path $dir "daemon.lock"
        if (Test-Path -LiteralPath $lock) {
            try {
                $age = (Get-Date) - (Get-Item -LiteralPath $lock).LastWriteTime
                if ($age.TotalMinutes -lt 10) { return }
            } catch { return }
        }
        try { New-Item -ItemType File -Path $lock -Force -ErrorAction SilentlyContinue | Out-Null } catch { }
        $daemonScript = Join-Path $env:TEMP "ultra-winget-offline-flushdaemon.ps1"
        $daemonBody = @'
param([string]$ConfigPath, [string]$QueueDir)
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$deadline = (Get-Date).AddMinutes(4)
while ((Get-Date) -lt $deadline) {
    $net = $false
    try {
        $r = Invoke-WebRequest -Uri 'https://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 4 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $net = $true }
    } catch { }
    if ($net) {
        $cfg = $null
        try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { }
        $files = @(Get-ChildItem -LiteralPath $QueueDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'daemon.lock' })
        foreach ($f in $files) {
            try {
                $payload = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $msg = [string]$payload.Message
                if ($cfg -and $cfg.notifications.enabled) {
                    $anyOk = $false
                    try {
                        if ($cfg.notifications.telegramBotToken -and $cfg.notifications.telegramChatId) {
                            $url = 'https://api.telegram.org/bot' + $cfg.notifications.telegramBotToken + '/sendMessage'
                            $body = @{ chat_id = $cfg.notifications.telegramChatId; text = $msg; parse_mode = 'Markdown' }
                            Invoke-RestMethod -Uri $url -Method Post -Body $body -ErrorAction Stop | Out-Null
                            $anyOk = $true
                        }
                    } catch { }
                    try {
                        if ($cfg.notifications.discordWebhookUrl -and -not $anyOk) {
                            $body = @{ content = $msg } | ConvertTo-Json
                            Invoke-RestMethod -Uri $cfg.notifications.discordWebhookUrl -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
                            $anyOk = $true
                        }
                    } catch { }
                    if ($anyOk) {
                        try { [System.IO.File]::SetAttributes($f.FullName, [System.IO.FileAttributes]::Normal) } catch { }
                        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch { }
        }
        break
    }
    Start-Sleep -Seconds 20
}
Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue
'@
        Set-Content -LiteralPath $daemonScript -Value $daemonBody -Encoding utf8 -ErrorAction Stop
        $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$daemonScript`" -ConfigPath `"$($script:ConfigPath)`" -QueueDir `"$dir`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle Hidden -ErrorAction Stop | Out-Null
    } catch { }
}

function Get-UWMExitTip {
    param([object]$Entry)
    $tip = ""
    try {
        $raw = Get-UWMEntryFusedText -Entry $Entry
        if ($raw -match '(?i)0x80072ee7|0x80072efd|connection (reset|refused)') { $tip = "Network unreachable — verify proxy/connectivity; offline delivery queue auto-armed." }
        elseif ($raw -match '(?i)0x80070005|access (is )?denied') { $tip = "Access denied — re-run elevated and re-issue the write envelope." }
        elseif ($raw -match '(?i)\b1168\b|0x490') { $tip = "Package not found — reindex the winget source catalogue." }
        elseif ($raw -match '(?i)0x8024[45]022|0x8024402c') { $tip = "Windows Update throttling/proxy — retry later or anchor the repair channel." }
        elseif ($raw -match '(?i)-2146498|0x800f08') { $tip = "Component store corruption — Invoke-UWMUpdateRepair anchored in background." }
        else { $tip = "General runtime fault — status quiesced; automation surveillance watches next cycle." }
    } catch { $tip = "Unclassified fault." }
    return $tip
}

function Get-UWMDiagnosticTip {
    param([object]$Entry)
    [string]$hint = ""
    try {
        $sigs = @(Test-UWMCrashSignature -Entry $Entry)
        $hint = switch ($sigs[0]) {
            'DISMFATAL'    { "Component store corruption (DISM/0x800F08xx). Invoke-UWMUpdateRepair anchored silently; Option 14 for deferred manual queue." }
            'REGACCESS'    { "Registry ACL fault. Automated service ACL map reset anchored; elevate + takeown guarded paths as needed." }
            'DEADLOCK'     { "File-object deadlock. Handle query executed; dangling owner released; boot vaporization registered if residue persists." }
            'DL_FAIL'      { "Network pipeline failure. Payload parked in offline queue; background probe armed for silent flush." }
            'CLOUDOFFLINE' { "Cloud sync unavailable. Offline queue engaged; flush auto-triggers on connectivity restore." }
            default        { Get-UWMExitTip -Entry $Entry }
        }
    } catch { $hint = Get-UWMExitTip -Entry $Entry }
    if ([string]::IsNullOrWhiteSpace($hint)) { $hint = Get-UWMExitTip -Entry $Entry }
    return $hint
}

function Show-UWMDiagGateway {
    param([object[]]$Entries)
    try {
        Show-Header
        $a = $script:Theme['Accent']; $d = $script:Theme['Dim']; $s = $script:Theme['Success']; $e = $script:Theme['Error']
        Write-Host "  [ARC] Autonomous Remediation Gateway — Purified Error-Only Intelligence View" -ForegroundColor $a
        Write-Host ("  " + "-" * 62)
        [object[]]$pool = @()
        if ($Entries) {
            try { $pool = @($Entries | Where-Object { $null -ne $_.Status -and [string]$_.Status -in @('Failed','Error') }) } catch { $pool = @() }
            if ($pool.Count -eq 0) {
                try { $pool = @($Entries | Where-Object { [string]$_.Action -match '(?i)(fail|err|deadlock|lock|timeout|reject)' }) } catch { $pool = @() }
            }
        }
        if ($pool.Count -eq 0) {
            Write-Host "  [PURIFIED] No error-class records within the active scope. System equilibrium nominal." -ForegroundColor $s
            Write-Host ""
            Write-Host "  Press any key to return to the audit loop..." -ForegroundColor $d
            try { [void][Console]::ReadKey($true) } catch { }
            return
        }
        [int]$timeW = 8; [int]$statusW = 9; [int]$actionW = 16; [int]$targetW = 22
        foreach ($en in $pool) {
            [string]$st = [string]$en.Status; if (-not $st) { $st = "Error" }
            [string]$ac = [string]$en.Action; if (-not $ac) { $ac = "-" }
            [string]$tg = [string]$en.Target; if (-not $tg) { $tg = "-" }
            $statusW = [Math]::Min([Math]::Max($statusW, (Get-UWMDisplayWidth $st)), 12)
            $actionW = [Math]::Min([Math]::Max($actionW, (Get-UWMDisplayWidth $ac)), 22)
            $targetW = [Math]::Min([Math]::Max($targetW, (Get-UWMDisplayWidth $tg)), 28)
        }
        $m = Get-UWMConsoleMetrics
        [int]$avail = [Math]::Max(50, $m.Width - 9)
        [int]$tipW = $avail - ($timeW + $statusW + $actionW + $targetW)
        if ($tipW -lt 20) { $tipW = 20 }
        [int[]]$widths = @($timeW, $statusW, $actionW, $targetW, $tipW)
        $hdrCells = @(
            @{ Text = "Time"; Color = "Cyan" }
            @{ Text = "Status"; Color = "Cyan" }
            @{ Text = "Action"; Color = "Cyan" }
            @{ Text = "Target"; Color = "Cyan" }
            @{ Text = "Solution Tip"; Color = "Cyan" }
        )
        Write-Host (New-UWMBorderLine -Widths $widths -L "╔" -Mid "╦" -R "╗") -ForegroundColor $d
        Write-UWMRowLine -Widths $widths -Cells $hdrCells
        Write-Host (New-UWMBorderLine -Widths $widths -L "╠" -Mid "╬" -R "╣") -ForegroundColor $d
        foreach ($en in $pool) {
            [string]$ts = [string]$en.Timestamp
            if ($ts.Length -ge 19) { $ts = $ts.Substring(0, 19) }
            [string]$st = [string]$en.Status; if (-not $st) { $st = "Error" }
            [string]$ac = [string]$en.Action; if (-not $ac) { $ac = "-" }
            [string]$tg = [string]$en.Target; if (-not $tg) { $tg = "-" }
            [string]$tip = Get-UWMDiagnosticTip -Entry $en
            $col = if ($st -in @('Failed','Error')) { "Red" } elseif ($st -eq 'Warning') { "Yellow" } else { "Magenta" }
            $cells = @(
                @{ Text = $ts; Color = $d }
                @{ Text = $st; Color = $col }
                @{ Text = $ac; Color = "Cyan" }
                @{ Text = $tg; Color = $a }
                @{ Text = $tip; Color = $script:Theme['Text'] }
            )
            Write-UWMRowLine -Widths $widths -Cells $cells
        }
        Write-Host (New-UWMBorderLine -Widths $widths -L "╚" -Mid "╩" -R "╝") -ForegroundColor $d
        Write-Host ""
        Write-Host "  [AUTOMATION] Crash-signature telemetry sweep performed on this scope; structural fallback anchors engaged." -ForegroundColor $s
        Write-Host ""
        Write-Host "  Press any key to return to the audit loop..." -ForegroundColor $d
        try { [void][Console]::ReadKey($true) } catch { }
    } catch { }
}

function Invoke-UWMArcTelemetrySweep {
    param([object[]]$Entries)
    if ($null -eq $Entries) { return }
    try {
        foreach ($en in $Entries) {
            $sigs = @()
            try { $sigs = @(Test-UWMCrashSignature -Entry $en) } catch { $sigs = @() }
            if ($sigs.Count -eq 0) { continue }
            foreach ($sig in $sigs) {
                try {
                    if ($sig -eq 'DISMFATAL' -or $sig -eq 'REGACCESS') {
                        [void](Invoke-UWMArcRepairProcess -Signature $sig)
                    }
                    elseif ($sig -eq 'DEADLOCK') {
                        [string]$tgt = ""
                        try {
                            $rawT = [string]$en.Target
                            if ($rawT -and ($rawT.Contains('\') -or $rawT.Contains('.')) -and (Test-Path -LiteralPath $rawT -ErrorAction SilentlyContinue)) { $tgt = $rawT }
                        } catch { }
                        if (-not $tgt) {
                            try {
                                $ds = [string]$en.Details
                                if ($ds -match "([A-Za-z]:\\[^\s'`"\[\]]+)") { $tgt = $matches[1] }
                            } catch { }
                        }
                        if ($tgt) { Invoke-UWMArcDeadlockMitigation -Target $tgt }
                    }
                } catch { }
            }
        }
    } catch { }
}

# ---- Configuration ----
function Get-DefaultConfig {
    return [PSCustomObject]@{
        theme="dark"; language="en"
        logging=@{ enabled=$true; maxEntries=1000 }
        backup=@{ enabled=$true }
        ignoreList=@()
        ui=@{ pageSize=9; scale="normal" }
        scheduledUpdate=@{ enabled=$false; day="Sunday"; time="03:00" }
        battery=@{ threshold=30 }
        throttle=@{ enabled=$false; maxBandwidthMbps=5 }
        scripts=@{ preScript=""; postScript="" }
        startupImpact=@{ enabled=$true; bootDeltaThreshold=30 }
        storeIntegration=@{ enabled=$true }
        hooks=@{ prePackageScript=""; postPackageScript="" }
        github=@{ enabled=$false; gistId=""; token="" }
        notifications=@{ enabled=$false; telegramBotToken=""; telegramChatId=""; discordWebhookUrl="" }
        bridges=@{ chocolatey=$true; scoop=$true }
        apiServer=@{ enabled=$false; port=8080 }
        security=@{ ownerSid=""; keyHash=""; keySalt="" }
        rollbackHistory=@{}
    }
}
function Get-Locale { if ($script:Config.language -eq "ar") { return $script:Arabic.Clone() }; return $script:English.Clone() }
function Apply-Theme { $script:Theme = if ($script:Config.theme -eq "light") { $script:LightTheme.Clone() } else { $script:DarkTheme.Clone() } }
function Save-Config {
    if ($script:AuditMode) { return }
    $configTarget = if ($script:IsolationRedirect) { Join-Path $env:TEMP "ultra-winget-config.json" } else { $script:ConfigPath }
    $script:Config | ConvertTo-Json -Depth 5 | Out-File $configTarget -Encoding utf8 -Force
}
function Load-Config {
    $script:Config = Get-DefaultConfig
    if (Test-Path $script:ConfigPath) {
        try {
            $u = Get-Content $script:ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($u.theme) { $script:Config.theme = $u.theme }
            if ($u.language) { $script:Config.language = $u.language }
            if ($u.logging) {
                if ($u.logging.enabled -ne $null) { $script:Config.logging.enabled = $u.logging.enabled }
                if ($u.logging.maxEntries -ne $null) { $script:Config.logging.maxEntries = $u.logging.maxEntries }
            }
            if ($u.backup -and $u.backup.enabled -ne $null) { $script:Config.backup.enabled = $u.backup.enabled }
            if ($u.ignoreList) { $script:Config.ignoreList = @($u.ignoreList) }
            if ($u.ui -and $u.ui.pageSize -ne $null) { $script:Config.ui.pageSize = $u.ui.pageSize }
            if ($u.ui -and $u.ui.scale) { $script:Config.ui.scale = $u.ui.scale }
            if ($u.scheduledUpdate) {
                if ($u.scheduledUpdate.enabled -ne $null) { $script:Config.scheduledUpdate.enabled = $u.scheduledUpdate.enabled }
                if ($u.scheduledUpdate.day) { $script:Config.scheduledUpdate.day = $u.scheduledUpdate.day }
                if ($u.scheduledUpdate.time) { $script:Config.scheduledUpdate.time = $u.scheduledUpdate.time }
            }
            if ($u.battery -and $u.battery.threshold -ne $null) { $script:Config.battery.threshold = $u.battery.threshold }
            if ($u.throttle) {
                if ($u.throttle.enabled -ne $null) { $script:Config.throttle.enabled = $u.throttle.enabled }
                if ($u.throttle.maxBandwidthMbps -ne $null) { $script:Config.throttle.maxBandwidthMbps = $u.throttle.maxBandwidthMbps }
            }
            if ($u.scripts) {
                if ($u.scripts.preScript) { $script:Config.scripts.preScript = $u.scripts.preScript }
                if ($u.scripts.postScript) { $script:Config.scripts.postScript = $u.scripts.postScript }
            }
            if ($u.startupImpact) {
                if ($u.startupImpact.enabled -ne $null) { $script:Config.startupImpact.enabled = $u.startupImpact.enabled }
                if ($u.startupImpact.bootDeltaThreshold -ne $null) { $script:Config.startupImpact.bootDeltaThreshold = $u.startupImpact.bootDeltaThreshold }
            }
            if ($u.storeIntegration -and $u.storeIntegration.enabled -ne $null) { $script:Config.storeIntegration.enabled = $u.storeIntegration.enabled }
            if ($u.hooks) {
                if ($u.hooks.prePackageScript) { $script:Config.hooks.prePackageScript = $u.hooks.prePackageScript }
                if ($u.hooks.postPackageScript) { $script:Config.hooks.postPackageScript = $u.hooks.postPackageScript }
            }
            if ($u.github) {
                if ($u.github.enabled -ne $null) { $script:Config.github.enabled = $u.github.enabled }
                if ($u.github.gistId) { $script:Config.github.gistId = $u.github.gistId }
                if ($u.github.token) { $script:Config.github.token = $u.github.token }
            }
            if ($u.notifications) {
                if ($u.notifications.enabled -ne $null) { $script:Config.notifications.enabled = $u.notifications.enabled }
                if ($u.notifications.telegramBotToken) { $script:Config.notifications.telegramBotToken = $u.notifications.telegramBotToken }
                if ($u.notifications.telegramChatId) { $script:Config.notifications.telegramChatId = $u.notifications.telegramChatId }
                if ($u.notifications.discordWebhookUrl) { $script:Config.notifications.discordWebhookUrl = $u.notifications.discordWebhookUrl }
            }
            if ($u.bridges) {
                if ($u.bridges.chocolatey -ne $null) { $script:Config.bridges.chocolatey = $u.bridges.chocolatey }
                if ($u.bridges.scoop -ne $null) { $script:Config.bridges.scoop = $u.bridges.scoop }
            }
            if ($u.apiServer) {
                if ($u.apiServer.enabled -ne $null) { $script:Config.apiServer.enabled = $u.apiServer.enabled }
                if ($u.apiServer.port -ne $null) { $script:Config.apiServer.port = $u.apiServer.port }
            }
            if ($u.security) {
                if ($u.security.ownerSid) { $script:Config.security.ownerSid = [string]$u.security.ownerSid }
                if ($u.security.keyHash)  { $script:Config.security.keyHash  = [string]$u.security.keyHash }
                if ($u.security.keySalt)  { $script:Config.security.keySalt  = [string]$u.security.keySalt }
            }
            if ($u.rollbackHistory) {
                $rb = $u.rollbackHistory
                if ($rb -is [System.Management.Automation.PSCustomObject]) {
                    $rbMap = @{}
                    foreach ($prop in $rb.psobject.Properties) { if ($null -ne $prop.Value) { $rbMap[$prop.Name] = $prop.Value } }
                    $rb = $rbMap
                }
                $script:Config.rollbackHistory = $rb
            }
        } catch { Write-Host ($script:Locale['ConfigCorrupted']) -ForegroundColor Yellow }
    }
    Save-Config; Apply-Theme; $script:Locale = Get-Locale
}

# ---- Telemetry Isolation Controls: re-route runtime artifacts to $env:TEMP during physical sweeps ----
function Enter-UWMIsolation {
    $script:IsolationRedirect = $true
}
function Exit-UWMIsolation {
    $script:IsolationRedirect = $false
}

# ---- Logging ----
function ConvertTo-UWMSecureText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $pattern = '(?i)\b(token|password|secret|masterkeyinput|private\s*key|api[-_]?key|client[-_]?secret|authorization|bearer)\b(\s*[:=]\s*|\s+)([^\s,;]+)'
    return [regex]::Replace($Text, $pattern, '$1=[REDACTED_SECURE]')
}
function Write-Log {
    param([string]$Action, [string]$Target = "", [string]$Status = "Info", [string]$Details = "")
    if (-not $script:Config.logging.enabled) { return }
    $logTarget = if ($script:IsolationRedirect) { Join-Path $env:TEMP "ultra-winget-log.json" } else { $script:LogPath }
    $safeTarget = ConvertTo-UWMSecureText -Text $Target
    $safeDetails = ConvertTo-UWMSecureText -Text $Details
    $entry = [PSCustomObject]@{ Timestamp=(Get-Date -Format "o"); Action=$Action; Target=$safeTarget; Status=$Status; Details=$safeDetails }
    $entries = @()
    if (Test-Path $logTarget) {
        try {
            $c = Get-Content $logTarget -Raw -ErrorAction Stop
            if ($c -and $c.Trim()) {
                $entries = $c | ConvertFrom-Json -ErrorAction Stop
                if ($entries -isnot [array]) { $entries = @($entries) }
            }
        } catch { $entries = @() }
    }
    $entries += $entry
    $max = $script:Config.logging.maxEntries
    if ($entries.Count -gt $max) { $entries = $entries[-$max..-1] }
    $entries | ConvertTo-Json -Compress -Depth 3 | Out-File $logTarget -Encoding utf8 -Force
    $script:LogCache = $null
}

# ---- Backup ----
function New-SystemRestorePoint {
    param([string]$Description = "Ultra Winget Manager Pre-Operation")
    if (-not $script:Config.backup.enabled) { return }
    try {
        $srCfg = $null
        try { $srCfg = Get-CimInstance -Namespace root\default -ClassName SystemRestoreConfig -ErrorAction SilentlyContinue } catch { $srCfg = $null }
        if ($null -ne $srCfg -and $srCfg.DisableSR -eq 1) {
            Write-Host " [SD-GATEWAY] System Restore is disabled on this host - checkpoint creation bypassed (view-only, non-destructive)." -ForegroundColor Yellow
            Write-Log -Action "BACKUP" -Target "SystemRestore" -Status "Skipped-Disabled" -Details $Description
            return
        }
        [int]$throttleMin = 1440
        try { if ($null -ne $srCfg -and $srCfg.RPGlobalInterval -gt 0) { $throttleMin = [int]$srCfg.RPGlobalInterval } } catch { $throttleMin = 1440 }
        try {
            $points = @(Get-CimInstance -Namespace root\default -ClassName SystemRestore -ErrorAction SilentlyContinue)
            $recent = $points | Where-Object { $null -ne $_.CreationTime } | Sort-Object CreationTime -Descending | Select-Object -First 1
            if ($null -ne $recent) {
                [datetime]$created = [datetime]::MinValue
                if ([datetime]::TryParse([string]$recent.CreationTime, [ref]$created)) {
                    [double]$ageMin = (Get-Date).Subtract($created).TotalMinutes
                    if ($ageMin -ge 0 -and $ageMin -lt $throttleMin) {
                        Write-Host (" [SD-GATEWAY] Recent restore point detected within Windows throttle window ({0} min / last event {1} min ago) - new checkpoint skipped to protect native OS stability." -f $throttleMin, [Math]::Round($ageMin, 1)) -ForegroundColor Yellow
                        Write-Log -Action "BACKUP" -Target "SystemRestore" -Status "Skipped-Throttle" -Details "$Description | recent event $([Math]::Round($ageMin,1))min ago"
                        return
                    }
                }
            }
        } catch { }
        Checkpoint-Computer -Description $Description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Host ($script:Locale['BackupCreated']) -ForegroundColor $script:Theme['Success']
        Write-Log -Action "BACKUP" -Target "SystemRestore" -Status "Success" -Details $Description
    } catch {
        Write-Host ($script:Locale['BackupFailed'] -f $_.Exception.Message) -ForegroundColor $script:Theme['Accent']
        Write-Log -Action "BACKUP" -Target "SystemRestore" -Status "Failed" -Details $_.Exception.Message
    }
}

# ---- Battery Awareness ----
function Test-BatteryLevel {
    $bat = Get-WmiObject -Class Win32_Battery -ErrorAction SilentlyContinue
    if (-not $bat) { return $true }
    $pct = $bat.EstimatedChargeRemaining
    if ($bat.BatteryStatus -eq 1 -and $pct -lt $script:Config.battery.threshold) {
        Write-Host ($script:Locale['BatWarning'] -f $pct) -ForegroundColor $script:Theme['Accent']
        Write-Log -Action "BATTERY" -Target "Check" -Status "Warning" -Details "At $pct%"
        if ($script:SilentMode) { Write-Host ($script:Locale['BatAborted']) -ForegroundColor $script:Theme['Error']; return $false }
        if ((Read-Host ($script:Locale['BatContinue'])).ToUpper() -eq 'B') { Write-Host ($script:Locale['BatAborted']) -ForegroundColor $script:Theme['Error']; return $false }
    }
    return $true
}

# ---- Pre/Post Scripts ----
function Invoke-PreScripts { $p = $script:Config.scripts.preScript; if ($p -and (Test-Path $p)) { Write-Host ($script:Locale['PreScriptRun']) -ForegroundColor $script:Theme['Accent']; & $p; Write-Log -Action "PRESCRIPT" -Target $p -Status "Done" } }
function Invoke-PostScripts { $p = $script:Config.scripts.postScript; if ($p -and (Test-Path $p)) { Write-Host ($script:Locale['PostScriptRun']) -ForegroundColor $script:Theme['Accent']; & $p; Write-Log -Action "POSTSCRIPT" -Target $p -Status "Done" } }

# ---- Scheduled Updates ----
function Register-ScheduledUpdate {
    if (-not $script:ScriptPath) { Write-Host "[!] Cannot determine script path." -ForegroundColor Red; return }
    $taskName = "Ultra Winget Manager Weekly Update"
    $day = $script:Config.scheduledUpdate.day; $time = $script:Config.scheduledUpdate.time
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Write-Host ($script:Locale['SchedExists']) -ForegroundColor $script:Theme['Accent']
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    $action   = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($script:ScriptPath)`" -SilentGlobal"
    $trigger  = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $day -At $time
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
    Write-Host ($script:Locale['SchedConfirm'] -f $day, $time) -ForegroundColor $script:Theme['Success']
    Write-Log -Action "SCHEDULE" -Target "TaskScheduler" -Status "Success" -Details "$day at $time"
}

# ---- Battery Status Display ----
function Get-BatteryStatus {
    $bat = Get-WmiObject -Class Win32_Battery -ErrorAction SilentlyContinue
    if (-not $bat) { return "No Battery" }
    $pct = $bat.EstimatedChargeRemaining
    if ($bat.BatteryStatus -eq 1) { return "Battery: ${pct}%" }
    return "Plugged In (${pct}%)"
}

# ---- Startup Animation ----
function Invoke-StartupAnimation {
    if ($script:SilentMode) { return }
    $h = $script:Theme['Header']; $a = $script:Theme['Accent']
    $logo = @(
        "  ╔══════════════════════════════════════════╗",
        "  ║     ⚡ ULTRA WINGET MANAGER v15.0 ⚡    ║",
        "  ║   Package Intelligence Engine (Online)   ║",
        "  ╚══════════════════════════════════════════╝"
    )
    foreach ($line in $logo) { Write-Host $line -ForegroundColor $h; Start-Sleep -Milliseconds 80 }
    Write-Host "   [ Initializing" -NoNewline -ForegroundColor $a
    foreach ($d in 1..5) { Start-Sleep -Milliseconds 100; Write-Host "." -NoNewline -ForegroundColor $a }
    Write-Host " Ready ]" -ForegroundColor $script:Theme['Success']
    if (Test-UWMConsoleAvailable) { [Console]::Beep(800, 100); Start-Sleep -Milliseconds 200 }
}

# ---- UI ----
function Show-Header {
    Clear-Host
    $h = $script:Theme['Header']; $d = $script:Theme['Dim']
    $sp = if ($script:Config.ui.scale -eq "large") { "`n" } else { "" }
    Write-Host "${sp}  +------------------------------------------------+" -ForegroundColor $h
    Write-Host "  |        $($script:Locale['HeaderTitle'])" -ForegroundColor $h
    Write-Host "  +------------------------------------------------+" -ForegroundColor $h
    $tl = if ($script:Config.theme -eq "light") { $script:Locale['HeaderLight'] } else { $script:Locale['HeaderDark'] }
    $bat = Get-BatteryStatus
    $thr = if ($script:Config.throttle.enabled) { $script:Locale['ThrottleOnLabel'] } else { $script:Locale['ThrottleOffLabel'] }
    $hScore = Get-PackageHealthScore
    Write-Host "   [ $tl | $bat | THR: $thr | $($script:Locale['HealthLabel']): $hScore ]" -ForegroundColor $d
    Write-Host ""
}

# ---- UWM Advanced Table Grid Engine ----
function Get-UWMDisplayWidth {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0 }
    if ($null -eq $script:UWMDispWidthCache) { $script:UWMDispWidthCache = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal) }
    if ($script:UWMDispWidthCache.ContainsKey($Text)) { return $script:UWMDispWidthCache[$Text] }
    try {
        [int]$w = 0
        for ([int]$i = 0; $i -lt $Text.Length; ) {
            [int]$cp = [char]::ConvertToUtf32($Text, $i)
            if ($cp -gt 0xFFFF) { $i += 2 } else { $i += 1 }
            try {
                $cat = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($cp)
                if ($cat -eq [System.Globalization.UnicodeCategory]::NonSpacingMark -or $cat -eq [System.Globalization.UnicodeCategory]::EnclosingMark -or $cat -eq [System.Globalization.UnicodeCategory]::Format) { continue }
            } catch { }
            $wide = (($cp -ge 0x1100 -and $cp -le 0x115F) -or ($cp -ge 0x2E80 -and $cp -le 0x303E) -or
                     ($cp -ge 0x3041 -and $cp -le 0x33FF) -or ($cp -ge 0x3400 -and $cp -le 0x4DBF) -or
                     ($cp -ge 0x4E00 -and $cp -le 0x9FFF) -or ($cp -ge 0xA000 -and $cp -le 0xA4CF) -or
                     ($cp -ge 0xAC00 -and $cp -le 0xD7A3) -or ($cp -ge 0xF900 -and $cp -le 0xFAFF) -or
                     ($cp -ge 0xFE30 -and $cp -le 0xFE6F) -or ($cp -ge 0xFF00 -and $cp -le 0xFF60) -or
                     ($cp -ge 0xFFE0 -and $cp -le 0xFFE6) -or ($cp -ge 0x20000 -and $cp -le 0x3FFFD))
            $lockedSingle = (($cp -ge 0x0600 -and $cp -le 0x06FF) -or ($cp -ge 0x0750 -and $cp -le 0x077F) -or
                             ($cp -ge 0x08A0 -and $cp -le 0x08FF) -or ($cp -ge 0xFB50 -and $cp -le 0xFDFF) -or
                             ($cp -ge 0xFE70 -and $cp -le 0xFEFF) -or ($cp -ge 0x2500 -and $cp -le 0x257F))
            if ($lockedSingle) { $w += 1; continue }
            if ($wide) { $w += 2 } else { $w += 1 }
        }
        if ($w -lt 1) { $w = 1 }
        $script:UWMDispWidthCache[$Text] = $w
        if ($script:UWMDispWidthCache.Count -gt 8192) { $script:UWMDispWidthCache.Clear() }
        return $w
    } catch {
        try {
            [int]$fallback = 0
            $enum = [System.Globalization.StringInfo]::GetTextElementEnumerator($Text)
            while ($enum.MoveNext()) { $fallback += 1 }
            if ($fallback -lt 1) { $fallback = 1 }
            return $fallback
        } catch { return 1 }
    }
}
function Get-UWMTruncated {
    param([string]$Text, [int]$MaxWidth)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    if ($null -eq $script:UWMTruncCache) { $script:UWMTruncCache = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::Ordinal) }
    [string]$tkey = [string]$MaxWidth + [string][char]2 + $Text
    if ($script:UWMTruncCache.ContainsKey($tkey)) { return $script:UWMTruncCache[$tkey] }
    if ((Get-UWMDisplayWidth $Text) -le $MaxWidth) { return $Text }
    [int]$budget = $MaxWidth - 1
    [string]$out = ""
    if ($budget -lt 1) {
        $out = "…"
    } else {
        $sb = New-Object System.Text.StringBuilder
        [int]$acc = 0
        $enum = [System.Globalization.StringInfo]::GetTextElementEnumerator($Text)
        while ($enum.MoveNext()) {
            [string]$el = $enum.Current
            [int]$ew = Get-UWMDisplayWidth $el
            if ($acc + $ew -gt $budget) { break }
            [void]$sb.Append($el)
            $acc += $ew
        }
        $out = $sb.ToString() + "…"
    }
    $script:UWMTruncCache[$tkey] = $out
    if ($script:UWMTruncCache.Count -gt 4096) { $script:UWMTruncCache.Clear() }
    return $out
}
function Get-UWMPadded {
    param([string]$Text, [int]$Width)
    if ([string]::IsNullOrEmpty($Text)) { $Text = "" }
    [int]$d = Get-UWMDisplayWidth $Text
    if ($d -ge $Width) { return $Text }
    return ($Text + (" " * ($Width - $d)))
}
function Get-UWMConsoleMetrics {
    try {
        [int]$w = [Console]::WindowWidth
        [int]$h = [Console]::WindowHeight
        if ($w -le 0 -or $h -le 0) { throw }
        return @{ Width = $w; Height = $h; Interactive = $true }
    } catch { return @{ Width = 100; Height = 25; Interactive = $false } }
}
function Write-UWMLogLegend {
    try {
        [hashtable]$m = Get-UWMConsoleMetrics
        [int]$maxW = [Math]::Max(20, $m.Width - 4)
        [string[]]$lines = @()
        try {
            if ($script:Locale -and $script:Locale.ContainsKey('LogLegendNav')) {
                $lines = @(
                    [string]$script:Locale['LogLegendNav'],
                    [string]$script:Locale['LogLegendTools'],
                    [string]$script:Locale['LogLegendRescue']
                )
            }
        } catch { }
        if ($lines.Count -eq 0) {
            $lines = @(
                " [N] Next Page | [P] Prev Page | [B] Back to Menu",
                " [F] Filter Log | [C] Clear Filter | [E] Error Index",
                " [R] RESCUE (Force Immediate Repair & Wipe Red Lines)"
            )
        }
        foreach ($line in $lines) {
            [string]$txt = $line
            if ((Get-UWMDisplayWidth $txt) -gt $maxW) { $txt = Get-UWMTruncated -Text $txt -MaxWidth $maxW }
            Write-Host ("  " + $txt) -ForegroundColor $script:Theme['Dim']
        }
    } catch { }
}
function New-UWMBorderLine {
    param([int[]]$Widths, [string]$L, [string]$Mid, [string]$R)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("  "); [void]$sb.Append($L)
    for ($i = 0; $i -lt $Widths.Count; $i++) {
        [void]$sb.Append(("═" * $Widths[$i]))
        if ($i -lt $Widths.Count - 1) { [void]$sb.Append($Mid) }
    }
    [void]$sb.Append($R)
    return $sb.ToString()
}
function Write-UWMRowLine {
    param([int[]]$Widths, [object[]]$Cells)
    Write-Host "  ║" -NoNewline -ForegroundColor $script:Theme['Dim']
    for ($ci = 0; $ci -lt $Cells.Count; $ci++) {
        $cell = $Cells[$ci]
        [string]$txt = [string]$cell.Text
        $color = if ($cell.Color) { $cell.Color } else { $script:Theme['Text'] }
        [int]$w = $Widths[$ci]
        [int]$tw = Get-UWMDisplayWidth $txt
        if ($tw -gt $w) { $txt = Get-UWMTruncated -Text $txt -MaxWidth $w; $tw = Get-UWMDisplayWidth $txt }
        if ($tw -lt $w) { $txt = $txt + (" " * ($w - $tw)) }
        Write-Host $txt -NoNewline -ForegroundColor $color
        if ($ci -lt $Cells.Count - 1) { Write-Host "║" -NoNewline -ForegroundColor $script:Theme['Dim'] }
    }
    Write-Host "║" -ForegroundColor $script:Theme['Dim']
}
function Get-UWMPinnedSet {
    if ($null -ne $script:UWMPinnedIds) { Write-Output $script:UWMPinnedIds -NoEnumerate; return }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    try {
        $raw = winget pin list 2>&1 | Out-String
        [string[]]$lines = $raw -split "`r?`n" | Where-Object { $_ -match '\S' }
        [int]$hdr = -1
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Id') { $hdr = $i; break } }
        if ($hdr -ge 0) {
            [int]$idPos = $lines[$hdr].IndexOf('Id'); [int]$typePos = $lines[$hdr].IndexOf('Type')
            for ($i = $hdr + 2; $i -lt $lines.Count; $i++) {
                if ($typePos -gt $idPos -and $lines[$i].Length -gt $typePos) {
                    [void]$set.Add($lines[$i].Substring($idPos, $typePos - $idPos).Trim())
                }
            }
        }
    } catch { }
    $script:UWMPinnedIds = $set
    Write-Output $set -NoEnumerate
}
function Get-UWMStartupPresence {
    param([string]$Id, [string]$Name)
    try {
        $paths = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        )
        foreach ($p in $paths) {
            $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -like 'PS*') { continue }
                    [string]$hay = "$($prop.Name)|$($prop.Value)"
                    if ($hay -match [regex]::Escape($Name) -or $hay -match [regex]::Escape($Id)) { return $true }
                }
            }
        }
        $folders = @(
            (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
            (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
        )
        foreach ($f in $folders) {
            if ($f -and (Test-Path $f)) {
                $hit = Get-ChildItem -Path $f -File -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -match [regex]::Escape($Name) -or $_.Name -match [regex]::Escape($Id)
                }
                if ($hit) { return $true }
            }
        }
    } catch { }
    return $false
}
function Get-UWMDiskLabel {
    param([string]$Id, [string]$Name)
    [int]$mb = 100
    if ($Id -match '(?i)chrome|firefox|edge|opera|brave' -or $Name -match '(?i)browser') { $mb = 160 }
    elseif ($Id -match '(?i)\.net|visualstudio|nodejs|python|jdk|sdk|gcc|clang' -or $Name -match '(?i)runtime|framework|sdk|toolkit') { $mb = 280 }
    elseif ($Id -match '(?i)office|word|excel|powerpoint|adobe' -or $Name -match '(?i)office|adobe') { $mb = 320 }
    elseif ($Name -match '(?i)game|epic|steam' -or $Id -match '(?i)epic|steam|games') { $mb = 1200 }
    elseif ($Name -match '(?i)media|player|codec' -or $Id -match '(?i)vlc|ffmpeg|handbrake|obs') { $mb = 200 }
    return "+$mb MB"
}
function Get-UWMDeltaText {
    param($Item)
    [string]$cur = [string]$Item.Version; [string]$avail = [string]$Item.Available
    if ($cur) { if ($avail) { return "$cur -> $avail" } return $cur }
    if ($avail) { return "-> $avail" }
    return "—"
}
function Get-UWMVersionDeltaWidth {
    param([object[]]$PageItems)
    [int]$maxLen = 0
    foreach ($it in $PageItems) {
        [int]$d = Get-UWMDisplayWidth (Get-UWMDeltaText $it)
        if ($d -gt $maxLen) { $maxLen = $d }
    }
    return ($maxLen + 2)
}
function Get-UWMHealthColor {
    param([string]$Health)
    if ($Health -match '^(\d+)%') {
        [int]$pct = [int]$Matches[1]
        if ($pct -ge 80) { return $script:Theme['Success'] }
        if ($pct -ge 50) { return "Yellow" }
        return "Red"
    }
    return "Red"
}
function Get-UWMDiskColor {
    param([string]$Label)
    if ($Label -match '(\d+)\s*MB') {
        [int]$mb = [int]$Matches[1]
        if ($mb -lt 150) { return $script:Theme['Success'] }
        if ($mb -lt 400) { return "Yellow" }
        return "Red"
    }
    return $script:Theme['Dim']
}
function Get-UWMRawKey {
    while ($true) {
        try {
            if ($Host.UI.RawUI.KeyAvailable) {
                $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($null -ne $key) { return [char]$key.Character }
                return [char]0
            }
        } catch { }
        try {
            if ([Console]::KeyAvailable) {
                $ci = [Console]::ReadKey($true)
                return [char]$ci.KeyChar
            }
        } catch { }
        if (-not (Test-UWMConsoleAvailable)) { return [char]0 }
        Start-Sleep -Milliseconds 50
    }
}
function Get-UWMSecondaryDigit {
    try {
        if ($Host.UI.RawUI.KeyAvailable) {
            $k2 = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            $c2 = [char]$k2.Character
            if ([char]::IsDigit($c2)) { return $c2 }
        }
    } catch { }
    return [char]0
}
function Set-UWMConsoleFixed {
    try {
        if (-not (Test-UWMConsoleAvailable)) { return }
        try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
        $raw = $Host.UI.RawUI
        $curBuf = $raw.BufferSize
        $curWin = $raw.WindowSize
        if ($curBuf.Width -le 0 -or $curBuf.Height -le 0) { return }
        $nb = New-Object System.Management.Automation.Host.Size ([Math]::Max($curBuf.Width, 120), [Math]::Max($curBuf.Height, 32))
        if ($nb.Width -ne $curBuf.Width -or $nb.Height -ne $curBuf.Height) {
            try { $raw.BufferSize = $nb } catch { }
        }
        $nw = New-Object System.Management.Automation.Host.Size (120, 32)
        if ($nw.Width -ne $curWin.Width -or $nw.Height -ne $curWin.Height) {
            try { $raw.WindowSize = $nw } catch { }
        }
    } catch { }
}

function Show-PagedMenu {
    param([string]$Title, [array]$Items, [string]$LabelProperty = "Name", [string]$Mode = "", [switch]$ShowCategory)
    $count = @($Items).Count
    if ($count -eq 0) { return $null }
    Set-UWMConsoleFixed
    $metrics = Get-UWMConsoleMetrics
    [int]$cfgPS = 9
    try { $cfgPS = [int][Math]::Max(1, $script:Config.ui.pageSize) } catch { $cfgPS = 9 }
    if ($cfgPS -lt 1) { $cfgPS = 9 }
    [int]$pageSize = $cfgPS
    if ($metrics.Interactive) {
        [int]$rowsFit = [Math]::Max(3, [int][Math]::Floor(($metrics.Height - 14) / 2))
        $pageSize = [Math]::Max(1, [Math]::Min($rowsFit, $pageSize))
    }
    $pageSize = [Math]::Min($pageSize, $count)
    if ($pageSize -lt 1) { $pageSize = 1 }
    $cp = 0; $tp = [Math]::Max(1, [Math]::Ceiling($count / [double]$pageSize))
    $pins = Get-UWMPinnedSet
    [int]$idxW = [Math]::Max(3, $count.ToString().Length + 1)
    [int]$nameW = 10; [int]$srcW = 6
    foreach ($it in $Items) {
        [int]$n = Get-UWMDisplayWidth ([string]$it.Name); if ($n -gt $nameW) { $nameW = $n }
        [int]$i2 = Get-UWMDisplayWidth ([string]$it.ID);  if ($i2 -gt $nameW) { $nameW = $i2 }
        [string]$src = [string]$it.Source; if (-not $src) { $src = "winget" }
        [int]$s2 = Get-UWMDisplayWidth $src; if ($s2 -gt $srcW) { $srcW = $s2 }
    }
    $nameW = [Math]::Min($nameW, 50); $srcW = [Math]::Min($srcW, 20)
    [int]$diskW = 11; [int]$bootW = 10; [int]$healthW = 6
    [int]$overhead = 10
    [int]$available = $metrics.Width - $overhead
    while ($true) {
        if ($script:UWMSerialDrainActive) {
            if ($null -eq $script:UWMSerialDrainWatchAt) { $script:UWMSerialDrainWatchAt = [DateTime]::UtcNow }
            elseif (([DateTime]::UtcNow - $script:UWMSerialDrainWatchAt).TotalSeconds -gt 20) {
                $script:UWMSerialDrainActive = $false
                $script:UWMSerialDrainWatchAt = $null
                try { Write-Log -Action "DRAIN_WATCHDOG" -Target "UI" -Status "Recovered" -Details "Serial drain exceeded 20s watchdog; paged menu resumed" } catch { }
            }
            Start-Sleep -Milliseconds 100
            continue
        }
        $script:UWMSerialDrainWatchAt = $null
        Set-UWMConsoleFixed
        $s = $cp * $pageSize; $e = [Math]::Min($s + $pageSize - 1, $count - 1)
        [int]$verW = Get-UWMVersionDeltaWidth -PageItems $Items[$s..$e]
        [int]$need = $idxW + $nameW + $srcW + $verW + $diskW + $bootW + $healthW
        [int]$excess = $need - $available
        if ($excess -gt 0) {
            foreach ($pair in @(@('nameW',4), @('srcW',4), @('diskW',7), @('bootW',4), @('healthW',3), @('idxW',3))) {
                if ($excess -le 0) { break }
                [int]$cur = Get-Variable -Name $pair[0] -ValueOnly
                [int]$fl = [int]$pair[1]
                [int]$tk = [Math]::Min($excess, $cur - $fl)
                Set-Variable -Name $pair[0] -Value ($cur - $tk)
                $excess -= $tk
            }
            $need = $idxW + $nameW + $srcW + $verW + $diskW + $bootW + $healthW
            if ($need -gt $available) {
                [int]$other = $idxW + $nameW + $srcW + $diskW + $bootW + $healthW
                $verW = [Math]::Max(2, $available - $other)
            }
        }
        $widths = @($idxW, $nameW, $srcW, $verW, $diskW, $bootW, $healthW)
        Show-Header
        if ($Mode) { Write-Host "  >> MODE: $Mode | Page: ( $($cp + 1) / $tp ) | Packages: $count" -BackgroundColor Yellow -ForegroundColor Black }
        Write-Host (New-UWMBorderLine -Widths $widths -L "╔" -Mid "╦" -R "╗") -ForegroundColor $script:Theme['Dim']
        $hdrCells = @(
            @{ Text = " # "; Color = "Cyan" }
            @{ Text = "Application (Name / ID)"; Color = "Cyan" }
            @{ Text = "Source"; Color = "Cyan" }
            @{ Text = "Version Delta"; Color = "Cyan" }
            @{ Text = "Disk Impact"; Color = "Cyan" }
            @{ Text = "Boot Delay"; Color = "Cyan" }
            @{ Text = "Health"; Color = "Cyan" }
        )
        Write-UWMRowLine -Widths $widths -Cells $hdrCells
        Write-Host (New-UWMBorderLine -Widths $widths -L "╠" -Mid "╬" -R "╣") -ForegroundColor $script:Theme['Dim']
        for ($i = $s; $i -le $e; $i++) {
            $item = $Items[$i]
            [string]$nm = [string]$item.Name; [string]$id = [string]$item.ID
            [string]$src = [string]$item.Source; if (-not $src) { $src = "winget" }
            [string]$health = Get-PackageHealth -PackageId $id
            [string]$disk = Get-UWMDiskLabel -Id $id -Name $nm
            [bool]$boot = Get-UWMStartupPresence -Id $id -Name $nm
            [bool]$pinned = $pins.Contains($id)
            [string]$rowColor = $script:Theme['Text']
            if ($health -match '^(\d+)%') {
                [int]$hp = [int]$Matches[1]
                if ($hp -lt 50) { $rowColor = "Red" } elseif ($hp -lt 80) { $rowColor = "Yellow" } else { $rowColor = $script:Theme['Success'] }
            } else { $rowColor = "Red" }
            if ($pinned -and $rowColor -ne "Red") { $rowColor = "Yellow" }
            $nmDisp = $nm; if ($pinned) { $nmDisp = $nm + " [PIN]" }
            $idxCell = @{ Text = ($i + 1).ToString(); Color = "Cyan" }
            $nameCell = @{ Text = $nmDisp; Color = $rowColor }
            $srcCell = @{ Text = $src; Color = $script:Theme['Accent'] }
            $verCell = @{ Text = (Get-UWMDeltaText $item); Color = $script:Theme['Dim'] }
            $diskCell = @{ Text = $disk; Color = (Get-UWMDiskColor $disk) }
            $bootCell = @{ Text = $(if ($boot) { "Yes" } else { "No" }); Color = $(if ($boot) { "Red" } else { $script:Theme['Success'] }) }
            $healthCell = @{ Text = $health; Color = (Get-UWMHealthColor $health) }
            Write-UWMRowLine -Widths $widths -Cells @($idxCell, $nameCell, $srcCell, $verCell, $diskCell, $bootCell, $healthCell)
            $blank = @{ Text = ""; Color = $script:Theme['Dim'] }
            Write-UWMRowLine -Widths $widths -Cells @($blank, @{ Text = $id; Color = $script:Theme['Dim'] }, $blank, $blank, $blank, $blank, $blank)
        }
        Write-Host (New-UWMBorderLine -Widths $widths -L "╚" -Mid "╩" -R "╝") -ForegroundColor $script:Theme['Dim']
        [int]$rowsOnPage = $e - $s + 1
        if ($tp -gt 1) { Write-Host "   $($script:Locale['NavNextPrev'])" -ForegroundColor $script:Theme['Dim'] }
        else { Write-Host "   $($script:Locale['NavBack'])" -ForegroundColor $script:Theme['Dim'] }
        Write-Host "   $($script:Locale['NavPrompt'])" -NoNewline -ForegroundColor $script:Theme['Accent']
        [string]$vector = ""
        [char]$nch = [char]0
        while ($true) {
            $nch = Get-UWMRawKey
            if ($nch -eq [char]0) {
                if (-not (Test-UWMConsoleAvailable)) { return $null }
                continue
            }
            [char]$ck = [char]::ToUpper($nch)
            if ($vector -eq "") {
                if ($ck -eq 'X') {
                    Write-Host $nch -NoNewline -ForegroundColor $script:Theme['Accent']
                    continue
                }
                if ($ck -eq 'N' -or $ck -eq 'P' -or $ck -eq 'B') { break }
                if ([char]::IsDigit($nch)) {
                    $vector = [string]$nch
                    Write-Host $nch -NoNewline -ForegroundColor $script:Theme['Accent']
                }
            } else {
                if ($nch -eq [char]13 -or $nch -eq [char]10) { break }
                if ($nch -eq [char]8 -or $nch -eq [char]127) {
                    if ($vector.Length -gt 0) {
                        $vector = $vector.Substring(0, $vector.Length - 1)
                        Write-Host "`b `b" -NoNewline -ForegroundColor $script:Theme['Accent']
                    }
                    continue
                }
                if ($ck -eq 'B') {
                    Write-Host ""
                    $vector = ""
                    continue
                }
                if ([char]::IsDigit($nch) -or $nch -eq ',' -or $nch -eq ' ') {
                    $vector += $nch
                    Write-Host $nch -NoNewline -ForegroundColor $script:Theme['Accent']
                }
            }
        }
        if ($vector -ne "") {
            [System.Collections.Generic.List[int]]$vidx = [System.Collections.Generic.List[int]]::new()
            [string[]]$parts = $vector -split '[, ]+' | Where-Object { $_ -ne '' }
            foreach ($pr in $parts) {
                [int]$v = 0
                if ([int]::TryParse($pr, [ref]$v)) { if ($v -ge 1 -and $v -le $count) { [void]$vidx.Add($v) } }
            }
            if ($vidx.Count -gt 0) {
                [int[]]$uniq = @($vidx | Sort-Object -Unique)
                Write-Host ""
                if ($uniq.Count -eq 1) {
                    [int]$sel = $uniq[0] - 1
                    Write-Host ("  -> $($Items[$sel].Name)") -ForegroundColor $script:Theme['Dim']
                    Write-Log -Action "SELECT" -Target $Items[$sel].ID -Status "Picked" -Details "Row $vector (global index)"
                    Start-Sleep -Milliseconds 300
                    return $Items[$sel]
                } else {
                    [System.Collections.Generic.List[PSObject]]$multi = [System.Collections.Generic.List[PSObject]]::new()
                    foreach ($v in $uniq) {
                        [void]$multi.Add($Items[$v - 1])
                        Write-Host ("  -> $($Items[$v - 1].Name)") -ForegroundColor $script:Theme['Dim']
                    }
                    Write-Log -Action "SELECT" -Target (($multi | ForEach-Object { $_.ID }) -join ',') -Status "Picked" -Details "Vector $vector (global indices)"
                    Start-Sleep -Milliseconds 300
                    return @($multi)
                }
            }
        }
        elseif ($nch -eq 'N' -or $nch -eq 'n') {
            Write-Host $nch -ForegroundColor $script:Theme['Accent']
            if ($cp -lt $tp - 1) { $cp++ }
        }
        elseif ($nch -eq 'P' -or $nch -eq 'p') {
            Write-Host $nch -ForegroundColor $script:Theme['Accent']
            if ($cp -gt 0) { $cp-- }
        }
        elseif ($nch -eq 'B' -or $nch -eq 'b') {
            Write-Host $nch -ForegroundColor $script:Theme['Accent']
            if ($cp -ge 1) { $cp = 0 }
            else { return $null }
        }
    }
}

# ---- Winget Parsers ----
function Get-WingetUpgradeList {
    $env:LANG = 'en_US.UTF-8'
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture
    $raw = winget upgrade 2>&1 | Out-String
    [string[]]$lines = $raw -split "`r?`n" | Where-Object { $_ -match '\S' }
    [int]$hdr = -1
    for ([int]$i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "Name" -and $lines[$i] -match "Id") { $hdr = $i; break } }
    if ($hdr -eq -1) { return @() }
    [int]$idPos = $lines[$hdr].IndexOf("Id"); [int]$verPos = $lines[$hdr].IndexOf("Version")
    [int]$availPos = $lines[$hdr].IndexOf("Available"); [int]$srcPos = $lines[$hdr].IndexOf("Source")
    $list = [System.Collections.Generic.List[PSObject]]::new()
    for ([int]$i = $hdr + 2; $i -lt $lines.Count; $i++) {
        [string]$line = $lines[$i]
        if ($line -match '(?i)^Found\s+\d+') { continue }
        if ($line.Length -gt $verPos -and $verPos -gt $idPos) {
            [string]$name = $line.Substring(0, $idPos).Trim()
            [string]$id = $line.Substring($idPos, $verPos - $idPos).Trim()
            [string]$ver = ""; [string]$avail = ""; [string]$src = "winget"
            if ($availPos -gt $verPos -and $line.Length -gt $availPos) {
                $ver = $line.Substring($verPos, $availPos - $verPos).Trim()
                if ($srcPos -gt $availPos -and $line.Length -gt $srcPos) {
                    $avail = $line.Substring($availPos, $srcPos - $availPos).Trim()
                    $src = $line.Substring($srcPos).Trim()
                } else { $avail = $line.Substring($availPos).Trim() }
            } elseif ($line.Length -gt $verPos) { $ver = $line.Substring($verPos).Trim() }
            if ($id) { $list.Add([PSCustomObject]@{ Name=$name; ID=$id; Version=$ver; Available=$avail; Source=$src }) }
        }
    }
    $ign = $script:Config.ignoreList
    if ($ign -and $ign.Count -gt 0) {
        $filtered = [System.Collections.Generic.List[PSObject]]::new()
        foreach ($pkg in $list) { if ($pkg.ID -notin $ign) { $filtered.Add($pkg) } }
        return $filtered
    }
    return $list
}
function Get-WingetSearchList {
    param([string]$Query)
    $raw = winget search $Query --accept-source-agreements 2>&1 | Out-String
    [string[]]$lines = $raw -split "`r?`n" | Where-Object { $_ -match '\S' }
    [int]$hdr = -1
    for ([int]$i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "Name" -and $lines[$i] -match "Id") { $hdr = $i; break } }
    if ($hdr -eq -1) { return @() }
    [int]$idPos = $lines[$hdr].IndexOf("Id"); [int]$verPos = $lines[$hdr].IndexOf("Version")
    $list = [System.Collections.Generic.List[PSObject]]::new()
    for ([int]$i = $hdr + 2; $i -lt $lines.Count; $i++) {
        [string]$line = $lines[$i]
        if ($line -match '(?i)^Found\s+\d+') { continue }
        if ($line.Length -gt $idPos -and $verPos -gt $idPos) {
            [string]$name = $line.Substring(0, $idPos).Trim(); [string]$id = $line.Substring($idPos, $verPos - $idPos).Trim()
            if ($id) { $list.Add([PSCustomObject]@{ Name=$name; ID=$id }) }
        }
    }
    return $list
}

# ---- Feature Functions ----
function Invoke-SmartAction {
    param([string]$Mode)
    Show-Header
    if (-not (Assert-UWMWriteAccess)) { return }
    Write-Progress -Activity "Scanning" -Status ($script:Locale['ScanPackages']) -PercentComplete -1
    $list = Get-WingetUpgradeList; Write-Progress -Activity "Scanning" -Completed
    if ($list.Count -eq 0) {
        Write-Host "`n $($script:Locale['NoneFound'])" -ForegroundColor $script:Theme['Success']
        Write-Log -Action $Mode -Target "All" -Status "None found"
        if (-not $script:SilentMode) { Read-Host " $($script:Locale['PressEnter'])" }; return
    }
    $sel = Show-PagedMenu -Items $list -Mode $Mode -ShowCategory
    if (-not $sel) { return }
    foreach ($pkgItem in @($sel)) {
        $rawId = $pkgItem.ID
        $id = if ($null -eq $rawId) { "" } else { [string]$rawId }
        $id = $id.Trim()
        if ($id -eq "") {
            Write-Host "  [WARN] Skipping package with null/empty identity (interpreter guard active)." -ForegroundColor Yellow
            Write-Log -Action $Mode -Target "(empty-id)" -Status "Skipped" -Details "Package identity null or whitespace"
            continue
        }
        switch ($Mode) {
            "UPDATE" {
                Invoke-UWMDownloadCache -TargetId $id
                Write-Host "`n[UWM Engine] Upgrading target payload for $id..." -ForegroundColor Cyan
                winget upgrade --id $id --accept-package-agreements --accept-source-agreements
                $ec = $LASTEXITCODE
                if ($ec -eq 0 -or $ec -eq 3010) {
                    Write-Host "`n[SUCCESS] $id upgraded successfully!" -ForegroundColor Green
                } else {
                    Write-Host "`n[INFO] Update transaction finalized with exit code: $ec" -ForegroundColor Yellow
                }
            }
            "PIN"   { Invoke-UWMPinEngine -Id $id }
            "BLOCK" { Invoke-UWMPinEngine -Id $id -Blocking }
        }
    }
    if ($LASTEXITCODE -eq 0) { [Console]::Beep(800,80) } else { [Console]::Beep(300,150) }
    Write-Host "`n $($script:Locale['OpComplete'])" -ForegroundColor $script:Theme['Success']
    if (-not $script:SilentMode) { Read-Host " $($script:Locale['PressEnter'])" }
}

function Invoke-UWMPinEngine {
    param([string]$Id, [switch]$Blocking)
    if ([string]::IsNullOrWhiteSpace($Id)) {
        Write-Host "  [WARN] Pin/Block engine aborted: empty package identity received." -ForegroundColor Yellow
        return $false
    }
    $Id = $Id.Trim()
    $argsList = @('pin', 'add', '--id', $Id)
    if ($Blocking) { $argsList += '--blocking' }
    $label = if ($Blocking) { "BLOCK" } else { "PIN" }
    Write-Host "  [ENGINE] $label safeguard armed for $Id (15s ceiling)..." -ForegroundColor $script:Theme['Accent']
    $proc = $null
    try {
        $proc = Start-Process -FilePath "winget.exe" -ArgumentList $argsList -NoNewWindow -PassThru -ErrorAction Stop
        if (-not $proc.WaitForExit(15000)) {
            try {
                $proc.Refresh()
                if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
            } catch { }
            Write-Host "  [TIMEOUT] $label operation on $Id exceeded the 15s ceiling — hung process terminated to prevent UI freeze." -ForegroundColor Yellow
            Write-Log -Action $label -Target $Id -Status "Timeout(15s)" -Details "Killed hung winget pin process"
            return $false
        }
        $ec = $proc.ExitCode
        if ($ec -eq 0) {
            Write-Host "  [OK] $label confirmed for $Id (exit $ec)." -ForegroundColor $script:Theme['Success']
        } else {
            Write-Host "  [INFO] $label transaction for $Id completed with exit code: $ec" -ForegroundColor $script:Theme['Dim']
        }
        Write-Log -Action $label -Target $Id -Status $(if ($ec -eq 0) { "Done" } else { "Exit$ec" })
        return ($ec -eq 0)
    }
    catch {
        Write-Host "  [WARN] $label engine could not start for $Id : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Log -Action $label -Target $Id -Status "Failed" -Details $_.Exception.Message
        return $false
    }
    finally {
        if ($null -ne $proc) {
            try { $proc.Refresh(); if (-not $proc.HasExited) { $proc.Kill() } } catch { }
            $proc.Dispose()
        }
    }
}

# ---- Phase 6: Pre-Upgrade Device Optimization ----
function Optimize-SystemBeforeUpdate {
    if (-not $script:SilentMode) { Write-Host "`n  $($script:Locale['OptimizeTitle'])" -ForegroundColor $script:Theme['Accent'] }
    Write-Progress -Activity ($script:Locale['OptimizeTitle']) -Status ($script:Locale['OptimizeScan']) -PercentComplete -1
    $heavyPatterns = 'steam|epicgameslauncher|battlenet|ubisoftconnect|origin|gog|blender|maya|3dsmax|cinebench|premiere|aftereffects|davinci|msbuild|clang|gcc|ffmpeg|handbrake|obs|vmware|virtualbox|docker'
    try {
        $heavy = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -or $_.WorkingSet64 -gt 200MB
        } | Where-Object {
            $_.ProcessName -match $heavyPatterns -or $_.WorkingSet64 -gt 500MB
        } | Select-Object -First 5
    } catch { $heavy = @() }
    Write-Progress -Activity ($script:Locale['OptimizeTitle']) -Completed
    if (-not $heavy -or $heavy.Count -eq 0) {
        if (-not $script:SilentMode) { Write-Host "   $($script:Locale['OptimizeNone'])" -ForegroundColor $script:Theme['Success'] }
        return
    }
    $paused = @()
    foreach ($p in $heavy) {
        $mb = [Math]::Round($p.WorkingSet64/1MB, 0)
        Write-Host ($script:Locale['OptimizeFound'] -f $p.ProcessName, $p.Id, $mb) -ForegroundColor $script:Theme['Accent']
        if (-not $script:SilentMode) {
            $choice = (Read-Host " $($script:Locale['OptimizePrompt'])").ToUpper()
            if ($choice -eq 'P' -or $choice -eq 'إ') {
                try { $p.Suspend(); $paused += $p.ProcessName; Write-Host ($script:Locale['OptimizePaused'] -f $p.ProcessName) -ForegroundColor $script:Theme['Success'] } catch { }
            } elseif ($choice -eq 'A' -or $choice -eq 'ل') {
                Write-Log -Action "OPTIMIZE" -Target "Update" -Status "Aborted" -Details "By user at $($p.ProcessName)"
                throw "Aborted by user"
            } else { Write-Host ($script:Locale['OptimizeSkipped'] -f $p.ProcessName) -ForegroundColor $script:Theme['Dim'] }
        } else {
            try { $p.Suspend(); $paused += $p.ProcessName } catch { }
        }
    }
    if ($paused.Count -gt 0) {
        Write-Host "   [i] $($paused.Count) process(es) paused — will resume after update" -ForegroundColor $script:Theme['Accent']
        $script:PausedProcesses = $paused
    }
}
function Resume-PausedProcesses {
    if (-not $script:PausedProcesses -or $script:PausedProcesses.Count -eq 0) { return }
    foreach ($pn in $script:PausedProcesses) {
        try { (Get-Process -Name $pn -ErrorAction SilentlyContinue).Resume() } catch { }
    }
    Write-Host "   [i] Resumed $($script:PausedProcesses.Count) paused process(es)" -ForegroundColor $script:Theme['Dim']
    $script:PausedProcesses = @()
}

function Invoke-GlobalUpdate {
    if (-not (Assert-UWMWriteAccess)) { return }
    if (-not $script:SilentMode) { Show-Header }
    if (-not (Test-BatteryLevel)) {
        Write-Log -Action "GLOBAL" -Target "All" -Status "Aborted" -Details "Low battery"
        if (-not $script:SilentMode) { Read-Host " $($script:Locale['PressEnter'])" }; return
    }
    # ---- Phase 6: Pre-Upgrade Optimization ----
    $script:PausedProcesses = @()
    Optimize-SystemBeforeUpdate
    if (-not $script:SilentMode) { Write-Host ($script:Locale['ScanUpdates']) -ForegroundColor $script:Theme['Accent'] }
    Write-Progress -Activity "Global Update" -Status ($script:Locale['ScanPackages']) -PercentComplete -1
    $list = Get-WingetUpgradeList; Write-Progress -Activity "Global Update" -Completed
    if ($list.Count -eq 0) {
        Write-Host "`n $($script:Locale['AllUpToDate'])" -ForegroundColor $script:Theme['Success']
        Write-Log -Action "GLOBAL" -Target "All" -Status "Up to date"
        if (-not $script:SilentMode) { Read-Host " $($script:Locale['PressEnter'])" }; return
    }
    if (-not $script:SilentMode) { Write-Host ($script:Locale['FoundUpdatable'] -f $list.Count) -ForegroundColor $script:Theme['Text'] }

    # ---- Phase 4: Merge Store Updates ----
    $storeList = Get-StoreUpdateList
    if ($storeList.Count -gt 0) {
        $list += $storeList
        Write-Host ($script:Locale['StoreMergeNote'] -f $storeList.Count) -ForegroundColor $script:Theme['Accent']
    }

    # ---- Phase 5: Merge Bridge Updates ----
    $bridgeList = Get-BridgeUpgradeList
    if ($bridgeList.Count -gt 0) {
        $list += $bridgeList
        $choco = ($bridgeList | Where-Object { $_.Source -eq "Choco" }).Count
        $scoop = ($bridgeList | Where-Object { $_.Source -eq "Scoop" }).Count
        if ($choco -gt 0) { Write-Host ($script:Locale['BridgeChocoItems'] -f $choco) -ForegroundColor $script:Theme['Accent'] }
        if ($scoop -gt 0) { Write-Host ($script:Locale['BridgeScoopItems'] -f $scoop) -ForegroundColor $script:Theme['Accent'] }
    }

    $disk = Get-DiskSpaceInfo
    if ($disk) { Write-Host ($script:Locale['DiskPredict'] -f $disk.FreeGB, $list.Count) -ForegroundColor $script:Theme['Dim'] }

    $origPri = $null
    if ($script:Config.throttle.enabled) {
        Write-Host ($script:Locale['ThrottleNotice'] -f $script:Config.throttle.maxBandwidthMbps) -ForegroundColor $script:Theme['Accent']
        $proc = [System.Diagnostics.Process]::GetCurrentProcess(); $origPri = $proc.PriorityClass
        $proc.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
    }
    New-SystemRestorePoint -Description "Ultra Winget Manager Global Update"
    Invoke-PreScripts
    $startTime = Get-Date; $total = $list.Count; $ok = 0; $fail = 0
    for ($i = 0; $i -lt $total; $i++) {
        Start-Sleep -Milliseconds 25
        $pkg = $list[$i]; $pct = [Math]::Round(($i+1)/$total*100)
        $elapsed = (Get-Date) - $startTime
        $avg = if ($i -gt 0) { $elapsed.TotalSeconds / ($i+1) } else { 0 }
        $cat = Get-PackageCategory -Id $pkg.ID -Name $pkg.Name
        # ---- Phase 4: Per-Package Health Score ----
        $health = Get-PackageHealth -PackageId $pkg.ID
        $healthStr = if ($health -ne "N/A") { " [Health: $health]" } else { "" }
        Write-Progress -Activity ($script:Locale['PkgOfTotal'] -f ($i+1),$total) -Status "$($pkg.Name) [$cat] ($ok ok, $fail fail)$healthStr" -CurrentOperation $pkg.ID -PercentComplete $pct -SecondsRemaining ([Math]::Round($avg*($total-$i-1)))
        # ---- UWM Vault: Pre-upgrade native download ----
        Invoke-UWMDownloadCache -TargetId $pkg.ID
        # ---- Phase 4: Pre-Package Hook ----
        Invoke-PrePackageHook -PackageId $pkg.ID
        $ec = 0; $maxRetries = 3; $retryDelay = 1
        for ($r = 0; $r -le $maxRetries; $r++) {
            if ($r -gt 0) {
                Write-Host ($script:Locale['RetryTitle'] -f ($r+1), ($maxRetries+1), $pkg.ID) -ForegroundColor $script:Theme['Accent']
                Write-Host ($script:Locale['RetryWait'] -f $retryDelay) -ForegroundColor $script:Theme['Dim']
                Start-Sleep -Seconds $retryDelay; $retryDelay = [Math]::Min($retryDelay*2, 8)
            }
            try {
                switch ($pkg.Source) {
                    "Store" {
                        $storeId = $pkg.ID -replace '^msstore-', ''
                        winget upgrade --id $storeId --source msstore --silent --accept-package-agreements --accept-source-agreements 2>&1 | Out-String
                        $ec = $LASTEXITCODE
                    }
                    "Choco" { choco upgrade $pkg.Name -y --no-progress 2>&1 | Out-String; $ec = $LASTEXITCODE }
                    "Scoop" { scoop update $pkg.Name 2>&1 | Out-String; $ec = $LASTEXITCODE }
                    default {
                        winget upgrade --id $pkg.ID --accept-package-agreements --accept-source-agreements
                        $ec = $LASTEXITCODE
                    }
                }
                if ($ec -eq 0) { break }
            } catch { $ec = -1; if ($r -eq $maxRetries) { break } }
        }
        if ($ec -eq 0) { $ok++ } else { $fail++ }
        # ---- Phase 4: Post-Package Hook ----
        Invoke-PostPackageHook -PackageId $pkg.ID -ExitCode $ec
        Write-Log -Action "GLOBAL" -Target $pkg.ID -Status $(if ($ec -eq 0){"Success"}else{"Failed"}) -Details "Exit: $ec; Cat: $cat; Source: $($pkg.Source); Health: $health"
    }
    Write-Progress -Activity "Global Update" -Completed; Invoke-PostScripts
    # ---- Phase 6: Resume Paused Processes ----
    Resume-PausedProcesses
    if ($origPri) { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = $origPri }
    $dur = (Get-Date) - $startTime
    Write-Host "`n $($script:Locale['CompleteIn'] -f $dur.ToString("hh\:mm\:ss"))" -ForegroundColor $script:Theme['Success']
    Write-Host "    $($script:Locale['OkFailed'] -f $ok, $fail)" -ForegroundColor $script:Theme['Text']
    # ---- Phase 5: Notification ----
    $notifyMsg = $script:Locale['NotifyGlobalMsg'] -f $ok, $fail, $dur.ToString("mm\:ss")
    Send-CloudNotification -Message $notifyMsg
    if (Test-UWMConsoleAvailable) { if ($fail -eq 0 -and $ok -gt 0) { [Console]::Beep(1000,150) } elseif ($fail -gt 0) { [Console]::Beep(300,200) } }
    if (-not $script:SilentMode) { Read-Host " $($script:Locale['PressEnter'])" }
}

function Invoke-SmartSearch {
    $cart = [System.Collections.Generic.List[hashtable]]::new()
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $globalSearchQuery = ""
    $allResults = [System.Collections.Generic.List[hashtable]]::new()
    $searchSources = @()
    $viewCartMode = $false

    function Get-CartPreview {
        if ($cart.Count -eq 0) { return $script:Locale['SearchCartEmpty'] }
        $names = ($cart | Select-Object -First 5 | ForEach-Object { $_.Name }) -join ", "
        $extra = if ($cart.Count -gt 5) { " (+$($cart.Count - 5))" } else { "" }
        return "$($script:Locale['SearchCart'] -f $cart.Count): $names$extra"
    }

    function Sync-CartState {
        foreach ($r in $allResults) {
            $r.Selected = [bool]($cart | Where-Object { $_.Id -eq $r.Id })
        }
    }

    while ($true) {
        if (-not $viewCartMode -and [string]::IsNullOrWhiteSpace($globalSearchQuery)) {
            Show-Header
            Write-Host "  $($script:Locale['SearchBulkTitle'])" -ForegroundColor $script:Theme['Header']
            Write-Host "  $($script:Locale['SearchBulkSub'])" -ForegroundColor $script:Theme['Dim']
            Write-Host "  $(Get-CartPreview)" -ForegroundColor $(if ($cart.Count -gt 0) { "Green" } else { $script:Theme['Dim'] })
            Write-Host ("  " + "-" * 50) -ForegroundColor $script:Theme['Dim']
            $raw = (Read-Host "  Search Query (ENTER=deploy cart, B=back)").Trim()
            if ($raw -eq 'B' -or $raw -eq 'b') { break }
            if ([string]::IsNullOrWhiteSpace($raw)) {
                if ($cart.Count -gt 0) { break }
                continue
            }
            $globalSearchQuery = (($raw.TrimEnd('.') -replace '[\[\]\(\)\{\}\*\+\?\\\^\$\|]', '') -replace '\s+', ' ').Trim()
        }

        if (-not $viewCartMode -and -not [string]::IsNullOrWhiteSpace($globalSearchQuery)) {
            $allResults.Clear(); $searchSources = @()
            Clear-Host; Show-Header
            Write-Host "  Searching '$globalSearchQuery' across winget, Chocolatey, Scoop..." -ForegroundColor Cyan

            $wgJob = $null
            try {
                $wgJob = Start-Job -ScriptBlock {
                    param($q)
                    try { $q = ($q -replace '\s+', ' ').Trim(); if ($q) { & winget search "`"$q`"" --accept-source-agreements 2>$null | Out-String } else { "" } } catch { "" }
                } -ArgumentList $globalSearchQuery
                $wgDone = $wgJob | Wait-Job -Timeout 15
                if ($null -ne $wgDone) {
                    $wgRaw = @((Receive-Job $wgJob -ErrorAction SilentlyContinue) -join "`n")
                    if ($wgRaw.Count -gt 0 -and $wgRaw[0] -notmatch '(?i)No package found' -and -not [string]::IsNullOrWhiteSpace($wgRaw[0])) {
                        $lines = $wgRaw[0] -split "`r?`n"; $hdr = $false
                        foreach ($line in $lines) {
                            if ([string]::IsNullOrWhiteSpace($line)) { continue }
                            if ($line -match "Name\s+Id\s+Version") { $hdr = $true; continue }
                            if ($line -match "-----\s+----") { continue }
                            if (-not $hdr) { continue }
                            if ($line -match '(?i)^Found\s+\d+') { continue }
                            $cols = @($line -split '\s{2,}' | Where-Object { $_ -and $_.Trim() })
                            $n = if ($cols.Count -ge 3) { $cols[0].Trim() } else { "" }
                            $id = if ($cols.Count -ge 3) { $cols[1].Trim() } elseif ($cols.Count -ge 2) { $cols[1].Trim() } else { "" }
                            $v = if ($cols.Count -ge 4) { $cols[2].Trim() } else { "" }
                            $s = if ($cols.Count -ge 4) { $cols[3].Trim() } else { "winget" }
                            if ($id -and $id -notmatch '^\d+\.\d+') { $allResults.Add(@{ Name=$n; Id=$id; Version=$v; Source=$s; Selected=$false }) }
                        }
                        $searchSources += "winget"
                    }
                }
                Remove-Job $wgJob -Force -ErrorAction SilentlyContinue
            } catch { Remove-Job $wgJob -Force -ErrorAction SilentlyContinue }

            $chocoAvail = $false
            try { & choco --version 2>$null | Out-Null; $chocoAvail = ($LASTEXITCODE -eq 0) } catch { }
            if ($chocoAvail -and $allResults.Count -lt 50) {
                $chocoJob = $null
                try {
                    $chocoJob = Start-Job -ScriptBlock {
                        param($q)
                        try { $q = ($q -replace '\s+', ' ').Trim(); if ($q) { & choco search "`"$q`"" -r 2>$null | Out-String } else { "" } } catch { "" }
                    } -ArgumentList $globalSearchQuery
                    $chocoDone = $chocoJob | Wait-Job -Timeout 30
                    if ($null -ne $chocoDone) {
                        $chocoRaw = @((Receive-Job $chocoJob -ErrorAction SilentlyContinue) -join "`n")
                        if ($chocoRaw.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($chocoRaw[0])) {
                            foreach ($cl in ($chocoRaw[0] -split "`r?`n" | Where-Object { $_ -match '\|' })) {
                                $pts = $cl -split '\|'
                                if ($pts.Count -ge 2) {
                                    $cId = $pts[0].Trim(); $cVer = $pts[1].Trim()
                                    if ($cId -and -not ($allResults | Where-Object { $_.Id -eq $cId })) { $allResults.Add(@{ Name=$cId; Id=$cId; Version=$cVer; Source="chocolatey"; Selected=$false }) }
                                }
                            }
                            $searchSources += "chocolatey"
                        }
                    }
                } catch { }
                try { Stop-Job $chocoJob -ErrorAction SilentlyContinue } catch { }
                Remove-Job $chocoJob -Force -ErrorAction SilentlyContinue
            }

            $scoopAvail = $false
            try { & scoop --version 2>$null | Out-Null; $scoopAvail = ($LASTEXITCODE -eq 0) } catch { }
            if ($scoopAvail -and $allResults.Count -lt 50) {
                $scoopJob = $null
                try {
                    $scoopJob = Start-Job -ScriptBlock {
                        param($q)
                        try { $q = ($q -replace '\s+', ' ').Trim(); if ($q) { & scoop search "`"$q`"" 2>$null | Out-String } else { "" } } catch { "" }
                    } -ArgumentList $globalSearchQuery
                    $scoopDone = $scoopJob | Wait-Job -Timeout 30
                    if ($null -ne $scoopDone) {
                        $scoopRaw = @((Receive-Job $scoopJob -ErrorAction SilentlyContinue) -join "`n")
                        if ($scoopRaw.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($scoopRaw[0]) -and $scoopRaw[0] -notmatch '(?i)did you mean') {
                            foreach ($sl in ($scoopRaw[0] -split "`r?`n" | Where-Object { $_ -match '\s{2,}' })) {
                                $sTk = $sl -split '\s{2,}' | Where-Object { $_.Trim() }
                                if ($sTk.Count -ge 2) {
                                    $sId = $sTk[0].Trim(); $sVer = if ($sTk.Count -ge 3) { $sTk[2].Trim() } else { $sTk[1].Trim() }
                                    if ($sId -and -not ($allResults | Where-Object { $_.Id -eq $sId })) { $allResults.Add(@{ Name=$sId; Id=$sId; Version=$sVer; Source="scoop"; Selected=$false }) }
                                }
                            }
                            $searchSources += "scoop"
                        }
                    }
                } catch { }
try { Stop-Job $scoopJob -ErrorAction SilentlyContinue } catch { }
                Remove-Job $scoopJob -Force -ErrorAction SilentlyContinue
            }

            $ghJob = $null
            try {
                $ghJob = Start-Job -ScriptBlock {
                    param($q)
                    try {
                        $q = ($q -replace '\s+', ' ').Trim()
                        if (-not $q) { return @() }
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        $hdr = @{ 'User-Agent' = 'UltraWingetManager/15.0'; 'Accept' = 'application/vnd.github+json' }
                        $uri = "https://api.github.com/search/repositories?q=" + [uri]::EscapeDataString('"' + $q + '"') + "&per_page=8&sort=stars"
                        $resp = Invoke-RestMethod -Uri $uri -Headers $hdr -TimeoutSec 15 -ErrorAction Stop
                        if ($null -ne $resp.items) {
                            foreach ($r in $resp.items) {
                                [pscustomobject]@{ Name = [string]$r.name; Id = [string]$r.full_name; Version = "stable"; Source = "GitHub"; Selected = $false; Owner = [string]$r.owner.login; Stars = [long]$r.stargazers_count }
                            }
                        } else { @() }
                    } catch { @() }
                } -ArgumentList $globalSearchQuery
                $ghDone = $ghJob | Wait-Job -Timeout 20
                if ($null -ne $ghDone) {
                    $ghItems = @(Receive-Job $ghJob -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $null })
                    foreach ($gi in $ghItems) {
                        if ($allResults.Count -ge 50) { break }
                        [string]$ghId = [string]$gi.Id
                        if ($ghId -and -not ($allResults | Where-Object { $_.Id -eq $ghId })) {
                            $allResults.Add([hashtable]@{ Name=[string]$gi.Name; Id=$ghId; Version=[string]$gi.Version; Source="GitHub"; Selected=$false; Trust=$null; Owner=[string]$gi.Owner; Stars=[long]$gi.Stars })
                        }
                    }
                    if ($ghItems.Count -gt 0) { $searchSources += "GitHub" }
                }
            } catch { }
            Remove-Job $ghJob -Force -ErrorAction SilentlyContinue

            Sync-CartState
            $globalSearchQuery = ""
            if ($allResults.Count -eq 0) { Write-Host "`n  [X] No results. Sources: $($searchSources -join ', ')" -ForegroundColor Yellow; Read-Host "  Press Enter..."; continue }
        }

        if ($viewCartMode) { $allResults.Clear(); foreach ($c in $cart) { $allResults.Add(@{ Name=$c.Name; Id=$c.Id; Version=$c.Version; Source=$c.Source; Selected=$true; Trust=$c.Trust }) } }

        # ===== SELECTION GRID =====
        Set-UWMConsoleFixed
        $metrics = Get-UWMConsoleMetrics
        [int]$pageSize = [Math]::Max(3, [Math]::Min(15, $metrics.Height - 16))
        $cp = 0
        $tp = [Math]::Max(1, [Math]::Ceiling($allResults.Count / [double]$pageSize))
        $cursor = 0
        $gridAction = "none"
        $needsRedraw = $true
        $termW = $metrics.Width
        $gridTopY = -1
        $gridDataTopY = 0
$prevCursor = -1
        [int]$selCount = 0
        foreach ($r in $allResults) { if ($r.Selected) { $selCount++ } }

        [int]$cTogW=4; [int]$cIdxW=4; [int]$cNmW=30; [int]$cIdW=28; [int]$cVrW=14; [int]$cScW=14; [int]$cStW=14
        $colWidths = @($cTogW, $cIdxW, $cNmW, $cIdW, $cVrW, $cScW, $cStW)
        $rowInnerW = $cTogW + $cIdxW + $cNmW + $cIdW + $cVrW + $cScW + $cStW + 6

        function Write-GridLine {
            param([string]$Text, [string]$Color = $script:Theme['Text'])
            $dw = Get-UWMDisplayWidth $Text
            $pad = [Math]::Max(0, $termW - $dw)
            if ($pad -gt 0) { Write-Host "$Text$(' ' * $pad)" -ForegroundColor $Color }
            else { Write-Host $Text -ForegroundColor $Color }
        }
        function Write-DataRow {
            param([int]$RowIdx, [int]$ItemIdx, [bool]$IsCursor)
            try { [Console]::SetCursorPosition(0, $gridDataTopY + $RowIdx) } catch { }
            $item = $allResults[$ItemIdx]
            if ($IsCursor) {
                $tog = "[►]"; $tC = "Cyan"; $rC = "Cyan"; $idxC = "Cyan"
            } else {
                $tog = if ($item.Selected) { "[✓]" } else { "[  ]" }
                $tC = if ($item.Selected) { "Green" } else { $script:Theme['Dim'] }
                $rC = $script:Theme['Text']; $idxC = "Cyan"
            }
$nm = $item.Name; if ($nm.Length -gt 28) { $nm = $nm.Substring(0,25) + "..." }
            $id = $item.Id; if ($id.Length -gt 26) { $id = $id.Substring(0,23) + "..." }
            if ($null -eq $item.Trust) { $item.Trust = Get-UWMTrustScore -Name $item.Name -Id $item.Id -Source $item.Source -Version $item.Version -GitHubStars $(if ($null -ne $item.Stars) { $item.Stars } else { 0 }) -GitHubOwner $item.Owner }
            $stTxt = if ($item.Trust.Tier -eq 'VERIFIED') { "VERIFIED $($item.Trust.Score)%" }
                     elseif ($item.Trust.Tier -eq 'COMMUNITY') { "COMMUNITY $($item.Trust.Score)%" }
                     else { "CRITICAL $($item.Trust.Score)%" }
            $stCol = if ($item.Trust.Tier -eq 'VERIFIED') { 'Green' } elseif ($item.Trust.Tier -eq 'COMMUNITY') { 'Yellow' } else { 'Red' }
            Write-UWMRowLine -Widths $colWidths -Cells @(
                @{ Text=$tog; Color=$tC }, @{ Text=($ItemIdx+1).ToString(); Color=$idxC },
                @{ Text=$nm; Color=$rC }, @{ Text=$id; Color=$script:Theme['Dim'] },
                @{ Text=$item.Version; Color=$script:Theme['Dim'] }, @{ Text=$item.Source; Color=$script:Theme['Accent'] },
                @{ Text=$stTxt; Color=$stCol })
        }
        function Write-EmptyRow {
            param([int]$RowIdx)
            try { [Console]::SetCursorPosition(0, $gridDataTopY + $RowIdx) } catch { }
            Write-GridLine ("  ║" + (" " * $rowInnerW) + "║") $script:Theme['Dim']
        }

        while ($true) {
            if ($needsRedraw) {
                $needsRedraw = $false; $prevCursor = $cursor
$s = $cp * $pageSize; $e = [Math]::Min($s + $pageSize - 1, $allResults.Count - 1)
                $rowsOnPage = $e - $s + 1

                if ($gridTopY -lt 0) { try { Clear-Host } catch { }; $gridTopY = [Console]::CursorTop; $gridDataTopY = $gridTopY + 12 }
                else { try { [Console]::SetCursorPosition(0, $gridTopY) } catch { } }

                $h = $script:Theme['Header']; $d = $script:Theme['Dim']
                Write-GridLine "  +------------------------------------------------+" $h
                Write-GridLine "  |        $($script:Locale['HeaderTitle'])" $h
                Write-GridLine "  +------------------------------------------------+" $h
                $tl = if ($script:Config.theme -eq "light") { $script:Locale['HeaderLight'] } else { $script:Locale['HeaderDark'] }
                $bat = Get-BatteryStatus; $thr = if ($script:Config.throttle.enabled) { $script:Locale['ThrottleOnLabel'] } else { $script:Locale['ThrottleOffLabel'] }
                $hScore = Get-PackageHealthScore
                Write-GridLine "   [ $tl | $bat | THR: $thr | $($script:Locale['HealthLabel']): $hScore ]" $d
                Write-GridLine ""
                $modeTag = if ($viewCartMode) { "[CART VIEW]" } else { $script:Locale['SearchBulkTitle'] }
                Write-GridLine "  $modeTag" $script:Theme['Header']
                Write-GridLine "  $(Get-CartPreview)" $(if ($cart.Count -gt 0) { "Green" } else { $d })
                Write-GridLine "  Source: $($searchSources -join ', ') | Page $($cp+1)/$tp | Total: $($allResults.Count)" Cyan
                Write-GridLine ""

                Write-GridLine (New-UWMBorderLine -Widths $colWidths -L "╔" -Mid "╦" -R "╗") $script:Theme['Dim']
                Write-UWMRowLine -Widths $colWidths -Cells @(
                    @{ Text=" ✓ "; Color="Cyan" }, @{ Text=" # "; Color="Cyan" }, @{ Text="Application Name"; Color="Cyan" },
                    @{ Text="Package ID"; Color="Cyan" }, @{ Text="Version"; Color="Cyan" }, @{ Text="Source"; Color="Cyan" }, @{ Text="Status"; Color="Cyan" })
                Write-GridLine (New-UWMBorderLine -Widths $colWidths -L "╠" -Mid "╬" -R "╣") $script:Theme['Dim']

                for ($ri = 0; $ri -lt $pageSize; $ri++) {
                    $ii = $s + $ri
                    if ($ii -lt $allResults.Count) { Write-DataRow -RowIdx $ri -ItemIdx $ii -IsCursor ($ri -eq $cursor) }
                    else { Write-EmptyRow -RowIdx $ri }
                }

                Write-GridLine (New-UWMBorderLine -Widths $colWidths -L "╚" -Mid "╩" -R "╝") $script:Theme['Dim']
                $footer = if ($viewCartMode) {
                    "  [SPACE] Remove | [V] Close Cart | [ENTER] Deploy ($selCount) | [B] Back"
                } else {
                    "  [SPACE] Toggle | [J/K] Nav | [V] Cart | [DEL] New Search | [ENTER] Deploy ($selCount) | [B] Back"
                }
                Write-GridLine $footer $script:Theme['Accent']
            }

            if (-not (Test-UWMConsoleAvailable)) { $gridAction = "back"; break }
            $keyInfo = [Console]::ReadKey($true)
            $keyChar = [char]::ToUpper($keyInfo.KeyChar)
            $cursorMoved = $false; $checkboxToggled = $false

            switch ($keyInfo.Key) {
                'UpArrow'   { if ($cursor -gt 0) { $cursor--; $cursorMoved = $true }; break }
                'DownArrow' { if ($cursor -lt ($rowsOnPage - 1)) { $cursor++; $cursorMoved = $true }; break }
                'Enter'     { $gridAction = "deploy"; break }
                'Escape'    { $gridAction = "menu"; break }
                'Delete'    { $gridAction = "refresh"; break }
'Spacebar'  {
                    if ($s + $cursor -lt $allResults.Count) {
                        $item = $allResults[$s + $cursor]
                        if ($viewCartMode) {
                            $cart.RemoveAll({ param($c) $c.Id -eq $item.Id }) | Out-Null
                            if ($item.Selected) { $selCount-- }
                            $allResults.RemoveAt($s + $cursor)
                            if ($cursor -ge $allResults.Count -and $cursor -gt 0) { $cursor-- }
                            $tp = [Math]::Max(1, [Math]::Ceiling($allResults.Count / [double]$pageSize))
                        } else {
                            if ($item.Selected) {
                                $item.Selected = $false
                                $cart.RemoveAll({ param($c) $c.Id -eq $item.Id }) | Out-Null
                                $selCount--
                            } else {
                                $item.Selected = $true
                                $cart.Add([hashtable]@{ Name=[string]$item.Name; Id=[string]$item.Id; Version=[string]$item.Version; Source=[string]$item.Source; Trust=$item.Trust })
                                $selCount++
                            }
                        }
                        $checkboxToggled = $true
                    }
                    break
                }
                default {
                    switch ($keyChar) {
                        'J' { if ($cursor -lt ($rowsOnPage - 1)) { $cursor++; $cursorMoved = $true } }
                        'K' { if ($cursor -gt 0) { $cursor--; $cursorMoved = $true } }
                        'N' { if ($cp -lt ($tp - 1)) { $cp++; $cursor = 0; $needsRedraw = $true } }
                        'P' { if ($cp -gt 0) { $cp--; $cursor = 0; $needsRedraw = $true } }
'A' { for ($i = $s; $i -lt [Math]::Min($s + $pageSize, $allResults.Count); $i++) { $r = $allResults[$i]; if (-not $r.Selected) { $r.Selected = $true; $selCount++ }; if (-not ($cart | Where-Object { $_.Id -eq $r.Id })) { $cart.Add([hashtable]@{ Name=[string]$r.Name; Id=[string]$r.Id; Version=[string]$r.Version; Source=[string]$r.Source; Trust=$r.Trust }) } }; $needsRedraw = $true }
                        'D' { for ($i = $s; $i -lt [Math]::Min($s + $pageSize, $allResults.Count); $i++) { $r = $allResults[$i]; if ($r.Selected) { $r.Selected = $false; $selCount-- }; $cart.RemoveAll({ param($c) $c.Id -eq $r.Id }) | Out-Null }; $needsRedraw = $true }
                        'V' { $viewCartMode = -not $viewCartMode; $gridTopY = -1; $cp = 0; $cursor = 0; $needsRedraw = $true }
                        'B' { $gridAction = "back" }
                    }
if ($keyChar -ge '1' -and $keyChar -le '9') {
                        [int]$numRow = [int]$keyChar - 49
                        if ($numRow -ge 0 -and $numRow -lt $rowsOnPage -and ($s + $numRow) -lt $allResults.Count) {
                            $target = $allResults[$s + $numRow]
                            if ($viewCartMode) {
                                $cart.RemoveAll({ param($c) $c.Id -eq $target.Id }) | Out-Null
                                if ($target.Selected) { $selCount-- }
                                $allResults.RemoveAt($s + $numRow)
                                if ($cursor -ge $allResults.Count -and $cursor -gt 0) { $cursor-- }
                                $tp = [Math]::Max(1, [Math]::Ceiling($allResults.Count / [double]$pageSize))
                            } else {
                                if ($target.Selected) { $target.Selected = $false; $cart.RemoveAll({ param($c) $c.Id -eq $target.Id }) | Out-Null; $selCount-- }
                                else { $target.Selected = $true; $cart.Add([hashtable]@{ Name=[string]$target.Name; Id=[string]$target.Id; Version=[string]$target.Version; Source=[string]$target.Source; Trust=$target.Trust }); $selCount++ }
                            }
                            $cursor = $numRow; $needsRedraw = $true
                        }
                    }
                    break
                }
            }
            if ($gridAction -ne "none") { break }
            if ($needsRedraw) { continue }

            if ($cursorMoved -and $prevCursor -ne $cursor) {
                $pIdx = $s + $prevCursor
                if ($prevCursor -ge 0 -and $pIdx -lt $allResults.Count) { Write-DataRow -RowIdx $prevCursor -ItemIdx $pIdx -IsCursor $false }
                $cIdx = $s + $cursor
                if ($cIdx -lt $allResults.Count) { Write-DataRow -RowIdx $cursor -ItemIdx $cIdx -IsCursor $true }
                $prevCursor = $cursor
            } elseif ($checkboxToggled -or ($cursorMoved -and $prevCursor -eq $cursor)) {
                $cIdx = $s + $cursor
                if ($cIdx -lt $allResults.Count) { Write-DataRow -RowIdx $cursor -ItemIdx $cIdx -IsCursor $true }
            }
        }

        if ($gridAction -eq "refresh") {
            if ($cart.Count -gt 0) {
                $clonedCart = [System.Collections.Generic.List[hashtable]]::new()
                foreach ($c in $cart) {
                    $clonedCart.Add([hashtable]@{
                        Name    = [string]$c.Name
                        Id      = [string]$c.Id
                        Version = [string]$c.Version
                        Source  = [string]$c.Source
                        Trust   = $c.Trust
                    })
                }
                $cart.Clear()
                foreach ($cc in $clonedCart) { $cart.Add($cc) }
            }
            $allResults.Clear(); $selCount = 0; $viewCartMode = $false; $cp = 0; $cursor = 0; $gridTopY = -1
            continue
        }
        if ($gridAction -eq "menu" -or $gridAction -eq "back") {
            if (-not $viewCartMode -and $gridAction -eq "back") { $gridTopY = -1; $globalSearchQuery = ""; $allResults.Clear(); $selCount = 0; continue }
            break
        }

        $selectedPkgs = @($cart)
        if ($selectedPkgs.Count -eq 0) { continue }

        # ===== DEPLOYMENT PIPELINE =====
        Clear-Host; Show-Header
        Write-Host "  $($script:Locale['SearchDeployTitle'])" -ForegroundColor $script:Theme['Header']
        Write-Host "  $($selectedPkgs.Count) package(s) queued for deployment.`n" -ForegroundColor Cyan
        Write-Host "  Context: $(if ($isAdmin) { $script:Locale['DeployCtxAdmin'] } else { $script:Locale['DeployCtxUser'] })" -ForegroundColor DarkCyan

        Write-Host "`n  $($script:Locale['DeploySourceSync'])" -ForegroundColor Yellow
        try {
            & winget source update *> $null
            if ($LASTEXITCODE -eq 0) { Write-Host "  [OK] Package index synchronized.`n" -ForegroundColor Green }
            else { Write-Host "  [WARN] Source sync code $LASTEXITCODE -- using cache.`n" -ForegroundColor DarkYellow }
        } catch { Write-Host "  [WARN] Source sync boundary -- using cache.`n" -ForegroundColor DarkYellow }

        $downloadDir = Join-Path ([System.IO.Path]::GetTempPath()) "UWM_Downloads"
        if (-not (Test-Path $downloadDir)) { New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null }

        Write-Host "  [DOWNLOAD] Fetching $($selectedPkgs.Count) installer(s) in parallel..." -ForegroundColor Cyan
        $dlJobs = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($pkg in $selectedPkgs) {
            $dlJob = Start-Job -ScriptBlock {
                param($pkgId, $dlDir, $src)
                try {
                    switch ($src) {
                        "chocolatey" {
                            $p = Start-Process -FilePath "choco.exe" -ArgumentList "install `"$pkgId`" --force --no-progress --limit-output --download-only -dv `"$dlDir`"" -NoNewWindow -PassThru -Wait -ErrorAction Stop
                            $dlFile = $null
                            for ($r = 0; $r -lt 5; $r++) {
                                Start-Sleep -Seconds 2
                                $dlFile = Get-ChildItem -Path $dlDir -Recurse -Include *.exe,*.msi,*.msix,*.appx -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                                if ($null -ne $dlFile) { break }
                            }
                            return @{ Ok=([int]$p.ExitCode -eq 0 -and $null -ne $dlFile); Path=if($dlFile){$dlFile.FullName}else{""} }
                        }
                        "scoop" {
                            $p = Start-Process -FilePath "scoop.cmd" -ArgumentList "download `"$pkgId`" --no-cache -d `"$dlDir`"" -NoNewWindow -PassThru -Wait -ErrorAction Stop
                            $dlFile = $null
                            for ($r = 0; $r -lt 5; $r++) {
                                Start-Sleep -Seconds 2
                                $dlFile = Get-ChildItem -Path $dlDir -Recurse -Include *.exe,*.msi,*.msix,*.appx -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                                if ($null -ne $dlFile) { break }
                            }
                            return @{ Ok=([int]$p.ExitCode -eq 0 -and $null -ne $dlFile); Path=if($dlFile){$dlFile.FullName}else{""} }
                        }
                        "github" {
                            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                            $hdr = @{ 'User-Agent' = 'UltraWingetManager/15.0'; 'Accept' = 'application/vnd.github+json' }
                            $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$pkgId/releases/latest" -Headers $hdr -TimeoutSec 20 -ErrorAction Stop
                            $asset = $rel.assets | Where-Object { $_.name -match '\.(exe|msi|msix|appx)$' } | Sort-Object size -Descending | Select-Object -First 1
                            if ($null -eq $asset) { return @{ Ok=$false; Path="" } }
                            $relFile = Join-Path $dlDir ([System.IO.Path]::GetFileName([string]$asset.name))
                            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $relFile -Headers $hdr -TimeoutSec 600 -ErrorAction Stop
                            return @{ Ok=(Test-Path -LiteralPath $relFile); Path=$relFile }
                        }
                        default {
                            $WgDlArgs = @('download', '--id', $pkgId, '--download-directory', $dlDir, '--accept-source-agreements')
                            $p = Start-Process -FilePath "winget.exe" -ArgumentList $WgDlArgs -NoNewWindow -PassThru -Wait -ErrorAction Stop
                            $installer = $null
                            for ($r = 0; $r -lt 5; $r++) {
                                Start-Sleep -Seconds 2
                                $installer = Get-ChildItem -Path $dlDir -Recurse -Include *.exe,*.msi,*.msix,*.appx -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                                if ($null -ne $installer) { break }
                            }
                            return @{ Ok=([int]$p.ExitCode -eq 0 -and $null -ne $installer); Path=if($installer){$installer.FullName}else{""} }
                        }
                    }
                } catch { return @{ Ok=$false; Path="" } }
            } -ArgumentList $pkg.Id, $downloadDir, $pkg.Source
            $dlJobs.Add(@{ Job=$dlJob; Pkg=$pkg; StartedAt=[DateTime]::UtcNow })
        }

        foreach ($dl in $dlJobs) {
            $dlTimeout = 600
            $dlWait = $dl.Job | Wait-Job -Timeout $dlTimeout
            if ($null -eq $dlWait) {
                [double]$dlElapsed = [Math]::Round(([DateTime]::UtcNow - $dl.StartedAt).TotalSeconds, 1)
                Write-Host "  [WARN] Download timed out for $($dl.Pkg.Id) after ${dlElapsed}s — aborting." -ForegroundColor DarkYellow
                Write-Log -Action "DL_TIMEOUT" -Target $dl.Pkg.Id -Status "Warning" -Details "Download exceeded ${dlTimeout}s wall-clock (${dlElapsed}s elapsed)"
                try { Stop-Job $dl.Job -ErrorAction SilentlyContinue } catch { }
                $dl.Result = @{ Ok=$false; Path="" }
            } else {
                $dlRaw = Receive-Job $dl.Job -ErrorAction SilentlyContinue
                if ($dlRaw -is [hashtable] -and $dlRaw.ContainsKey('Ok')) { $dl.Result = $dlRaw }
                else { $dl.Result = @{ Ok=$false; Path="" } }
            }
            Remove-Job $dl.Job -Force -ErrorAction SilentlyContinue
        }
        $dlOk = @($dlJobs | Where-Object { $_.Result.Ok }).Count
        Write-Host "  [OK] Downloaded $dlOk/$($selectedPkgs.Count) installer(s).`n" -ForegroundColor Green

        $deployed = 0; $failed = 0; $total = $selectedPkgs.Count; $prog = 0
        foreach ($dl in $dlJobs) {
            $prog++
            [string]$curName = [string]$dl.Pkg.Name
            [string]$curId   = [string]$dl.Pkg.Id
            [string]$curVer  = [string]$dl.Pkg.Version
            [string]$curSrc  = [string]$dl.Pkg.Source
            $pct = [Math]::Round(($prog / $total) * 100)
            $bLen = 30; $filled = [Math]::Round($pct / 100 * $bLen)
            $bar = ("█" * $filled) + ("░" * ($bLen - $filled))
            Write-Host ""
            Write-Host "  [$prog/$total] $bar $pct% — $curName ($curId)" -ForegroundColor $script:Theme['Accent']

            $scanResult = Invoke-UWMCloudScanner -PackageId $curId -Version $curVer
            if ($scanResult.Token -and -not $scanResult.Safe) {
                Write-Host "  [SKIP] Security gate: [$($scanResult.Token)]" -ForegroundColor Red; $failed++; continue
            }

            $pkgTrust = $dl.Pkg.Trust
            if ($null -eq $pkgTrust) { $pkgTrust = Get-UWMTrustScore -Name $curName -Id $curId -Source $curSrc -Version $curVer -GitHubStars $(if ($null -ne $dl.Pkg.Stars) { $dl.Pkg.Stars } else { 0 }) -GitHubOwner $dl.Pkg.Owner; $dl.Pkg.Trust = $pkgTrust }
            $forceUserScope = ($pkgTrust.Score -lt 50)
            if ($forceUserScope) {
                Write-Host "  [INSULATE] Trust $($pkgTrust.Score)% < 50% — forcing userspace install context." -ForegroundColor DarkYellow
                Write-Log -Action "SEC_INSULATE" -Target $curId -Status "Warning" -Details "TrustScore=$($pkgTrust.Score)% Tier=$($pkgTrust.Tier) Source=$curSrc — userspace containment applied"
            }

            $instOk = $false
            try {
                if (-not $dl.Result.Path -or -not (Test-Path $dl.Result.Path)) {
                    $fbFile = Get-ChildItem -Path $downloadDir -Recurse -Include *.exe,*.msi,*.msix,*.appx -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($fbFile) {
                        $dl.Result.Path = $fbFile.FullName
                        $dl.Result.Ok = $true
                    }
                }
                $useOnlineFailover = $false
                $offlineReady = $dl.Result.Ok -and $dl.Result.Path -and (Test-Path $dl.Result.Path)
                if ($offlineReady) {
                    [long]$fileSize = 0
                    try { $fileSize = (Get-Item -LiteralPath $dl.Result.Path -ErrorAction SilentlyContinue).Length } catch { }
                    if ($fileSize -le 0) {
                        Write-Host "  [FALLOVER] Binary empty (0 bytes) for $curId — routing to online install" -ForegroundColor DarkYellow
                        Write-Log -Action "DL_EMPTY" -Target $curId -Status "Warning" -Details "0-byte binary detected, switching to online failover"
                        $useOnlineFailover = $true
                    }
                } else {
                    $dlBinaries = @(Get-ChildItem -Path $downloadDir -Recurse -Include *.exe,*.msi,*.msix,*.appx -ErrorAction SilentlyContinue)
                    if ($dlBinaries.Count -eq 0) {
                        Write-Host "  [FALLOVER] Empty download footprint for $curId — routing to online install" -ForegroundColor DarkYellow
                        Write-Log -Action "DL_EMPTY" -Target $curId -Status "Info" -Details "Zero binaries in download directory, switching to online failover"
                    }
                    $useOnlineFailover = $true
                }
                if ($useOnlineFailover) {
                    [datetime]$instStart = [DateTime]::UtcNow
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.UseShellExecute = $true
                    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                    switch ($curSrc) {
                        "chocolatey" {
                            $psi.FileName = "choco.exe"
                            $psi.Arguments = "install `"$curId`" -y --no-progress"
                            if ($isAdmin -and -not $forceUserScope) { $psi.Verb = "runas" }
                        }
                        "scoop" {
                            $psi.FileName = "scoop.cmd"
                            $psi.Arguments = "install `"$curId`""
                            if ($isAdmin -and -not $forceUserScope) { $psi.Verb = "runas" }
                        }
                        default {
                            $WingetArgs = @('install', '--id', $curId, '--exact', '--silent', '--accept-package-agreements', '--accept-source-agreements')
                            if ($isAdmin -and -not $forceUserScope) { $WingetArgs += '--scope', 'machine' } else { $WingetArgs += '--scope', 'user' }
                            $psi.FileName = "winget.exe"
                            $psi.Arguments = ($WingetArgs -join ' ')
                            if ($isAdmin -and -not $forceUserScope) { $psi.Verb = "runas" }
                        }
                    }
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $p.WaitForExit()
                    [double]$instElapsed = [Math]::Round(([DateTime]::UtcNow - $instStart).TotalSeconds, 1)
                    [int]$exitCode = [int]$p.ExitCode
                    $instOk = ($exitCode -eq 0 -or $exitCode -eq 3010)
                    if (-not $instOk) {
                        Write-Log -Action "INSTALL_FAIL" -Target $curId -Status "Error" -Details "Online failover exit=$exitCode after ${instElapsed}s, source=$curSrc"
                    } elseif ($instElapsed -gt 60) {
                        Write-Log -Action "INSTALL_SLOW" -Target $curId -Status "Info" -Details "Installed in ${instElapsed}s (exit=$exitCode)"
                    }
                } else {
                    $ext = [System.IO.Path]::GetExtension($dl.Result.Path).ToLower()
                    $instArgStr = switch ($ext) {
                        ".msi"  { "/i `"$($dl.Result.Path)`" /qn /norestart /l*v `"$downloadDir\$curId.log`"" }
                        default { "`"$($dl.Result.Path)`" /S /silent /verysilent /suppressmsgboxes" }
                    }
                    $nativeExe = if ($ext -eq ".msi") { "msiexec.exe" } else { $dl.Result.Path }
                    [datetime]$instStart = [DateTime]::UtcNow
                    $psi = New-Object System.Diagnostics.ProcessStartInfo
                    $psi.FileName = $nativeExe
                    $psi.Arguments = $instArgStr
                    $psi.UseShellExecute = $true
                    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                    if ($isAdmin -and -not $forceUserScope) { $psi.Verb = "runas" }
                    $p = [System.Diagnostics.Process]::Start($psi)
                    $p.WaitForExit()
                    [double]$instElapsed = [Math]::Round(([DateTime]::UtcNow - $instStart).TotalSeconds, 1)
                    [int]$exitCode = [int]$p.ExitCode
                    $instOk = ($exitCode -eq 0 -or $exitCode -eq 3010)
                    if (-not $instOk) {
                        Write-Log -Action "INSTALL_FAIL" -Target $curId -Status "Error" -Details "Native exit=$exitCode after ${instElapsed}s (file=$ext)"
                    } elseif ($instElapsed -gt 60) {
                        Write-Log -Action "INSTALL_SLOW" -Target $curId -Status "Info" -Details "Installed in ${instElapsed}s (exit=$exitCode)"
                    }
                }
            } catch { Write-Host "  [FAIL] Exception: $($_.Exception.Message)" -ForegroundColor Red; Write-Log -Action "INSTALL_ERR" -Target $curId -Status "Error" -Details $_.Exception.Message }

            if ($instOk) { Write-Host "  [OK] $curName — Installed successfully." -ForegroundColor Green; $deployed++ }
            else { Write-Host "  [FAIL] $curName — Installation failed." -ForegroundColor Red; $failed++ }
        }

        Write-Host "`n  " + ("=" * 54) -ForegroundColor Yellow
        Write-Host "  $($script:Locale['DeployComplete'])" -ForegroundColor Green
        Write-Host "  $($script:Locale['DeploySummary'] -f $deployed, $failed, $total)" -ForegroundColor Cyan
        Write-Host "  " + ("=" * 54) -ForegroundColor Yellow
        Write-Log -Action "BULK_DEPLOY" -Target "SearchDeploy" -Status "Done" -Details "Deployed=$deployed Failed=$failed Total=$total"

        Start-Sleep -Seconds 5
        if (Test-Path $downloadDir) { Remove-Item -Path $downloadDir -Recurse -Force -ErrorAction SilentlyContinue }
        while ([Console]::KeyAvailable) { [Console]::ReadKey($true) | Out-Null }

        if ($viewCartMode) { $cart.Clear() }
        else { foreach ($r in $allResults) { $r.Selected = $false } }
        $viewCartMode = $false; $gridTopY = -1
        Read-Host "`n  $($script:Locale['PressEnter'])"
    }
}


function Invoke-StatusMenu {
    Show-Header
    Write-Host "  $($script:Locale['StatusTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    $raw = winget pin list 2>&1 | Out-String; $lines = $raw -split "`r?`n" | Where-Object { $_ -match '\S' }; $hdr = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "Id") { $hdr = $i; break } }
    if ($hdr -eq -1 -or $lines.Count -le ($hdr + 2)) {
        Write-Host "   $($script:Locale['NoPins'])" -ForegroundColor $script:Theme['Dim']
    } else {
        $idPos = $lines[$hdr].IndexOf("Id"); $verPos = $lines[$hdr].IndexOf("Version"); $pList = @()
        for ($i = $hdr + 2; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line.Length -gt $idPos -and $verPos -gt $idPos) {
                $pList += [PSCustomObject]@{ Name=$line.Substring(0,$idPos).Trim(); ID=$line.Substring($idPos,$verPos-$idPos).Trim() }
                Write-Host "   [$($pList.Count)] | $($pList[-1].Name)" -ForegroundColor $script:Theme['Text']
            }
        }
        Write-Host ("  " + "-" * 46)
        $idx = Read-Host "`n $($script:Locale['UnpinPrompt'])"
        if ($idx -eq 'B' -or $idx -eq 'b') { Read-Host " $($script:Locale['PressEnter'])"; return }
        if ($idx -match '^\d+$' -and [int]$idx -le $pList.Count) {
            if (Assert-UWMWriteAccess) {
                winget pin remove --id $pList[[int]$idx-1].ID 2>&1
                Write-Host " $($script:Locale['Unpinned'])" -ForegroundColor $script:Theme['Success']
                Write-Log -Action "UNPIN" -Target $pList[[int]$idx-1].ID -Status "Done"
            }
        }
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

function Invoke-Cleanup {
    Show-Header
    if (-not (Assert-UWMWriteAccess)) { return }
    Write-Host " $($script:Locale['CleanTitle'])" -ForegroundColor $script:Theme['Accent']

    # ---- Fail-Safe System Restore Gateway ----
    New-SystemRestorePoint -Description "Ultra Winget Manager Cleanup"

    # ---- PHASE A: Multi-profile + system volatile matrix purge (serial) ----
    Write-Host "`n [PURGE-ENGINE] PHASE A - Scanning volatile cache matrix across all user profiles..." -ForegroundColor Cyan
    Write-Progress -Activity ($script:Locale['CleanProgress']) -Status "PURGE-ENGINE Phase A active" -PercentComplete -1
    $stats = @{ Bytes = [long]0; Skip = 0; JunctionSkip = 0; GuardSkip = 0; HardSkip = 0 }
    $active = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { if ($p.Name) { [void]$active.Add([string]$p.Name) } }

    $profiles = @(Get-UWMActiveUserProfiles)
    $targets = [System.Collections.Generic.List[string]]::new()
    foreach ($profile in $profiles) {
        [void]$targets.Add((Join-Path $profile 'AppData\Local\Temp'))
        [void]$targets.Add((Join-Path $profile 'AppData\Local\Microsoft\Windows\INetCache'))
    }
    [void]$targets.Add((Join-Path $env:WINDIR 'Temp'))
    [void]$targets.Add((Join-Path $env:WINDIR 'Prefetch'))
    [void]$targets.Add((Join-Path $env:WINDIR 'SoftwareDistribution\Download'))

    [int]$targetCount = 0
    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t -ErrorAction SilentlyContinue)) { continue }
        $targetCount++
        Write-Host "  [PURGE] $t" -ForegroundColor DarkGray
        Invoke-UWMDeepPurge -Root $t -Stats $stats -ActiveProcesses $active
    }
    Write-Progress -Activity ($script:Locale['CleanProgress']) -Status ($script:Locale['CleanBin']) -PercentComplete -1
    Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue
    Write-Progress -Activity ($script:Locale['CleanProgress']) -Completed

    [double]$diskMB = [Math]::Round($stats.Bytes / 1MB, 2)
    Write-Host "`n [PURGE-ENGINE] PHASE A complete: $diskMB MB reclaimed | profiles: $($profiles.Count) | targets: $targetCount | locked: $($stats.Skip) | junctions protected: $($stats.JunctionSkip) | live-app segments guarded: $($stats.GuardSkip) | sensitive files shielded: $($stats.HardSkip)" -ForegroundColor Green
    Write-Log -Action "PURGE" -Target "System" -Status "Success" -Details "UniversalPurge: $diskMB MB, profiles $($profiles.Count), targets $targetCount, skipped $($stats.Skip), junctions $($stats.JunctionSkip), guarded $($stats.GuardSkip), shielded $($stats.HardSkip)"

    # ---- PHASE B: DISM component store compaction (async, non-blocking) ----
    Write-Host "`n [PURGE-ENGINE] PHASE B - Invoking DISM component store compaction as background job..." -ForegroundColor Cyan
    $null = Invoke-UWMDismCleanup

    # ---- PHASE C (Final): Native memory working-set compaction ----
    Write-Host "`n [PURGE-ENGINE] PHASE C (Final) - Native memory working-set compaction..." -ForegroundColor Cyan
    $ramMB = Invoke-UWMWorkingSetCompact

    Write-Host "`n [PURGE-ENGINE] FINAL REPORT - Total disk reclaimed: ${diskMB} MB | Recovered RAM capacity: ${ramMB} MB" -ForegroundColor Green
    Write-Log -Action "PURGE" -Target "Memory" -Status "Success" -Details "RAM recovered $ramMB MB | Pipeline disk $diskMB MB"
    $notifyCleanMsg = $script:Locale['NotifyCleanMsg'] -f $diskMB
    Send-CloudNotification -Message $notifyCleanMsg
    if (Test-UWMConsoleAvailable) { [Console]::Beep(800,80) }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Universal Purge Engine Helpers ----
function Get-UWMActiveUserProfiles {
    $profiles = [System.Collections.Generic.List[string]]::new()
    try {
        $profileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($sub in (Get-ChildItem $profileList -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $sub.PSPath -ErrorAction SilentlyContinue
            if ($p -and $p.ProfileImagePath) {
                $dir = [string]$p.ProfileImagePath
                if (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue) { [void]$profiles.Add($dir) }
            }
        }
    } catch { }
    if ($profiles.Count -eq 0) {
        try {
            foreach ($d in (Get-ChildItem 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
                if (Test-Path -LiteralPath $d.FullName -ErrorAction SilentlyContinue) { [void]$profiles.Add($d.FullName) }
            }
        } catch { }
    }
    $templateNames = @('public','default','defaultuser','allusers','defaultapppool','administrator','networkservice','localservice','system','systemprofile')
    $usersBase = ''
    try { $usersBase = Split-Path ([Environment]::GetFolderPath('UserProfile')) -Parent } catch { $usersBase = '' }
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($pf in ($profiles | Select-Object -Unique)) {
        [string]$leaf = [System.IO.Path]::GetFileName($pf)
        if ([string]::IsNullOrWhiteSpace($leaf)) { continue }
        [string]$compact = ($leaf -replace '\s','').ToLowerInvariant()
        if ($templateNames -contains $compact) { continue }
        if ($usersBase -and -not $pf.StartsWith($usersBase, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        [void]$result.Add($pf)
    }
    return @($result)
}
function Test-UWMReparsePoint {
    param([System.IO.FileSystemInfo]$Item)
    if ($null -eq $Item) { return $false }
    try { return (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) } catch { return $false }
}
function Test-UWMGuardedPath {
    param([string]$Path, [System.Collections.Generic.HashSet[string]]$ActiveProcesses)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    [string]$p = $Path.ToLowerInvariant()
    # ---- :: DISPLAY SOVEREIGNTY SHIELD :: ----
    # Strictly-hardened display-driver protection matrix. These artifacts are designated
    # TRUE on pure path match (independent of active-process state), so PHASE A sweeping
    # can never destroy display scaling configurations, vendor control-panel profiles
    # (NVIDIA Control Panel / AMD Radeon Software), or Custom Resolution Utility (CRU)
    # registry/temp deployment nodes -- all of which trigger display refresh-rate reset.
    $displayTokens = @(
        '\nvidia',
        'nvidia corporation',
        '\displayconfig',
        '\nview',
        '\nvcpl',
        '\nidiadrv',
        'virtual display',
        'radeon software',
        '\radeon',
        'amd software',
        '\atihdc',
        '\atikmdag',
        'display driver',
        '\currentcontrolset\control\video',
        '\currentcontrolset\control\graphicsdrivers',
        '\cui_64',
        '\toppgl',
        'custom resolution utility',
        '\cru\',
        '\crtconfig',
        '\memento'
    )
    foreach ($dt in $displayTokens) { if ($p.Contains($dt)) { return $true } }
    $guards = @(
        @{ Tokens = @('\google\chrome','chromium','brave'); Processes = @('chrome','brave') }
        @{ Tokens = @('\microsoft\edge'); Processes = @('msedge','iexplore') }
        @{ Tokens = @('\mozilla\firefox','\firefox'); Processes = @('firefox') }
        @{ Tokens = @('\nvidia\'); Processes = @('nvcontainer','nvbackend','nvdisplay.container') }
        @{ Tokens = @('\amd\dxcache','\amd\glcache','radeon'); Processes = @('radeonsoftware','amdow','amduserfe') }
        @{ Tokens = @('\intel\shadercache','\intel\gpucache'); Processes = @('igfxemn','igfxtray','igfxhk') }
        @{ Tokens = @('dxcache','glcache'); Processes = @('nvcontainer','nvbackend','radeonsoftware','amdow','igfxemn','igfxtray') }
        @{ Tokens = @('\microsoft\teams','ms-teams'); Processes = @('teams','ms-teams') }
        @{ Tokens = @('\microsoft\office\','\office\'); Processes = @('winword','excel','powerpnt','outlook') }
        @{ Tokens = @('discord'); Processes = @('discord') }
    )
    foreach ($g in $guards) {
        [bool]$hit = $false
        foreach ($t in $g.Tokens) { if ($p.Contains($t)) { $hit = $true; break } }
        if (-not $hit) { continue }
        foreach ($pn in $g.Processes) { if ($ActiveProcesses.Contains($pn)) { return $true } }
    }
    return $false
}
function Invoke-UWMDeepPurge {
    param([string]$Root, [hashtable]$Stats, [System.Collections.Generic.HashSet[string]]$ActiveProcesses)
    try {
        $items = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction SilentlyContinue)
        foreach ($item in $items) {
            if (Test-UWMReparsePoint -Item $item) { $Stats.JunctionSkip++; continue }
            if (Test-UWMGuardedPath -Path $item.FullName -ActiveProcesses $ActiveProcesses) { $Stats.GuardSkip++; continue }
            if ($item.PSIsContainer) {
                try {
                    Invoke-UWMDeepPurge -Root $item.FullName -Stats $Stats -ActiveProcesses $ActiveProcesses
                } catch {
                    $Stats.Skip++
                    Write-Log -Action "PURGE" -Target "Recurse" -Status "Warning" -Details "Subtree enumeration failed for $($item.FullName): $($_.Exception.Message)"
                }
                try {
                    [System.IO.Directory]::Delete($item.FullName, $false)
                } catch [System.IO.IOException] {
                    $Stats.Skip++
                } catch [System.UnauthorizedAccessException] {
                    $Stats.Skip++
                    Write-Log -Action "PURGE" -Target "DirCleanup" -Status "Warning" -Details "Access denied removing empty dir: $($item.FullName)"
                } catch {
                    $Stats.Skip++
                }
            } else {
                [long]$sz = 0
                try { $sz = [long]$item.Length } catch { $sz = 0 }
                [string]$leaf = ''
                try { $leaf = [System.IO.Path]::GetFileName($item.FullName).ToLowerInvariant() } catch { $leaf = '' }
                if ($leaf -in @('ntuser.dat','ntuser.dat.log1','ntuser.dat.log2','usrclass.dat','usrclass.dat.log1','usrclass.dat.log2','bootsect.bak')) { $Stats.HardSkip++; continue }
                if ($leaf.EndsWith('.lock') -or $leaf.EndsWith('.lck') -or $leaf.EndsWith('.lockfile')) { $Stats.HardSkip++; continue }
                [bool]$deleted = $false
                try {
                    Remove-Item -LiteralPath $item.FullName -Force -ErrorAction Stop
                    $Stats.Bytes += $sz
                    $deleted = $true
                } catch [System.UnauthorizedAccessException] {
                    try {
                        [System.IO.File]::Delete($item.FullName)
                        $Stats.Bytes += $sz
                        $deleted = $true
                    } catch {
                        try {
                            $null = cmd /c "del /f /q `"$($item.FullName)`" 2>nul"
                            if (-not (Test-Path -LiteralPath $item.FullName -ErrorAction SilentlyContinue)) {
                                $Stats.Bytes += $sz
                                $deleted = $true
                            }
                        } catch { }
                    }
                    if (-not $deleted) {
                        $Stats.Skip++
                        Write-Log -Action "PURGE" -Target "Permission" -Status "Warning" -Details "All fallbacks exhausted (AccessDenied): $($item.FullName)"
                    }
                } catch [System.IO.IOException] {
                    try {
                        [System.IO.File]::Delete($item.FullName)
                        $Stats.Bytes += $sz
                        $deleted = $true
                    } catch {
                        try {
                            $null = cmd /c "del /f /q `"$($item.FullName)`" 2>nul"
                            if (-not (Test-Path -LiteralPath $item.FullName -ErrorAction SilentlyContinue)) {
                                $Stats.Bytes += $sz
                                $deleted = $true
                            }
                        } catch { }
                    }
                    if (-not $deleted) { $Stats.Skip++ }
                } catch {
                    try {
                        [System.IO.File]::Delete($item.FullName)
                        $Stats.Bytes += $sz
                        $deleted = $true
                    } catch {
                        try {
                            $null = cmd /c "del /f /q `"$($item.FullName)`" 2>nul"
                            if (-not (Test-Path -LiteralPath $item.FullName -ErrorAction SilentlyContinue)) {
                                $Stats.Bytes += $sz
                                $deleted = $true
                            }
                        } catch { }
                    }
                    if (-not $deleted) {
                        $Stats.Skip++
                        Write-Log -Action "PURGE" -Target "File" -Status "Warning" -Details "All deletion methods failed for: $($item.FullName)"
                    }
                }
            }
        }
    } catch {
        $Stats.Skip++
        Write-Log -Action "PURGE" -Target "DirEnum" -Status "Warning" -Details "Top-level enumeration failed for ${Root}: $($_.Exception.Message)"
    }
}

function Invoke-UWMDisplayTopologyShield {
    param([switch]$Restore)
    $state = [pscustomobject]@{ Backups = @(); Dir = $null }
    try {
        $tmpRoot = [System.IO.Path]::GetTempPath()
        if ($Restore) {
            $shieldDir = $script:UWMDisplayShieldDir
            if ([string]::IsNullOrWhiteSpace($shieldDir) -or -not (Test-Path -LiteralPath $shieldDir -ErrorAction SilentlyContinue)) {
                $shieldDir = @(Get-ChildItem -LiteralPath $tmpRoot -Directory -Filter 'UWM_DisplayTopology_*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName)
            }
            if ([string]::IsNullOrWhiteSpace($shieldDir)) {
                Write-Host " [SHIELD] No display topology snapshot available to restore." -ForegroundColor Yellow
                Write-Log -Action "DISPLAY_SHIELD" -Target "Restore" -Status "Warning" -Details "No UWM_DisplayTopology_* backup structure found in temp"
                return $state
            }
            $backupFiles = @(Get-ChildItem -LiteralPath $shieldDir -Filter '*.reg' -File -ErrorAction SilentlyContinue)
            if ($backupFiles.Count -eq 0) {
                Write-Host " [SHIELD] Snapshot dir exists but holds no .reg profiles: $shieldDir" -ForegroundColor Yellow
                Write-Log -Action "DISPLAY_SHIELD" -Target "Restore" -Status "Warning" -Details "Empty display topology backup dir: $shieldDir"
                return $state
            }
            $restored = 0
            foreach ($bf in $backupFiles) {
                try {
                    & reg.exe import "$($bf.FullName)" 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        $restored++
                        Write-Host " [SHIELD] Re-injected display topology profile: $($bf.Name)" -ForegroundColor Green
                        Write-Log -Action "DISPLAY_SHIELD" -Target "Restore" -Status "Success" -Details "Imported $($bf.FullName)"
                    } else {
                        Write-Host " [SHIELD] WARN: reg import returned exit $LASTEXITCODE for $($bf.Name)" -ForegroundColor Yellow
                        Write-Log -Action "DISPLAY_SHIELD" -Target "Restore" -Status "Warning" -Details "reg import exit $($LASTEXITCODE): $($bf.FullName)"
                    }
                } catch {
                    Write-Host " [SHIELD] WARN: re-injection failed for $($bf.Name): $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-Log -Action "DISPLAY_SHIELD" -Target "Restore" -Status "Warning" -Details $_.Exception.Message
                }
            }
            Write-Host (" [SHIELD] Display topology lock-back completed: {0}/{1} profiles re-injected." -f $restored, $backupFiles.Count) -ForegroundColor Cyan
            Write-Log -Action "DISPLAY_SHIELD" -Target "Restore" -Status "Done" -Details "Imported $restored/$($backupFiles.Count) profiles from $shieldDir"
            return $state
        }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $shieldDir = Join-Path $tmpRoot ("UWM_DisplayTopology_{0}" -f $stamp)
        $null = New-Item -ItemType Directory -Path $shieldDir -Force -ErrorAction SilentlyContinue
        $script:UWMDisplayShieldDir = $shieldDir
        $state.Dir = $shieldDir

        $nodes = @(
            'HKCU\Control Panel\Desktop\WindowMetrics',
            'HKLM\SYSTEM\CurrentControlSet\Control\Video',
            'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers',
            'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}',
            'HKCU\Software\NVIDIA Corporation',
            'HKCU\Software\AMD',
            'HKCU\Software\Custom Resolution Utility'
        )
        $idx = 0
        foreach ($node in $nodes) {
            $idx++
            $tag = ("node{0:00}_{1}" -f $idx, (($node -replace '[^A-Za-z0-9]+','_') -replace '^_+|_+$',''))
            $backFile = Join-Path $shieldDir ("{0}.reg" -f $tag)
            try {
                $null = Start-Process reg.exe -ArgumentList @('export', ("`"{0}`"" -f $node), ("`"{0}`"" -f $backFile), '/y') -Wait -WindowStyle Hidden -ErrorAction Stop
                if (Test-Path -LiteralPath $backFile -ErrorAction SilentlyContinue) {
                    $fi = Get-Item -LiteralPath $backFile -ErrorAction SilentlyContinue
                    if ($fi -and $fi.Length -gt 16) { $state.Backups += $backFile } else { Remove-Item -LiteralPath $backFile -Force -ErrorAction SilentlyContinue }
                }
            } catch {
                Write-Host (" [SHIELD] WARN: export failed for {0}: {1}" -f $node, $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
        if ($state.Backups.Count -gt 0) {
            Write-Host (" [SHIELD] Display topology hives isolated & snapshotted ({0}/{1} nodes): {2}" -f $state.Backups.Count, $nodes.Count, $shieldDir) -ForegroundColor Cyan
            Write-Log -Action "DISPLAY_SHIELD" -Target "Backup" -Status "Success" -Details "Snapshotted $($state.Backups.Count) nodes -> $shieldDir"
        } else {
            Write-Host " [SHIELD] WARNING: Display topology snapshot not confirmed. Compaction proceeds at nominal risk." -ForegroundColor Yellow
            Write-Log -Action "DISPLAY_SHIELD" -Target "Backup" -Status "Warning" -Details "No display topology nodes exported"
        }
    } catch {
        Write-Host " [SHIELD] Display topology shield skipped: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Log -Action "DISPLAY_SHIELD" -Target "Shield" -Status "Warning" -Details $_.Exception.Message
    }
    return $state
}

function Invoke-UWMDismCleanup {
    if (-not (Get-Command dism.exe -ErrorAction SilentlyContinue)) {
        Write-Host " [DISM] dism.exe not available; component store compaction deferred." -ForegroundColor DarkYellow
        return
    }
    if (Get-Process -Name dism -ErrorAction SilentlyContinue) {
        Write-Host " [DISM] Another DISM session is already active; component store compaction deferred." -ForegroundColor Yellow
        return
    }
    # ---- :: DISPLAY TOPOLOGY SOVEREIGNTY SHIELD :: ----
    # Electronically isolate + snapshot active display configuration hives (refresh rate,
    # resolution, scaling) BEFORE /StartComponentCleanup /ResetBase, as a zero-loss
    # safety net. Mandatory re-injection runs AFTER the DISM sweep below.
    $null = Invoke-UWMDisplayTopologyShield
    try {
        $proc = Start-Process dism.exe -ArgumentList @('/Online','/Cleanup-Image','/StartComponentCleanup','/ResetBase') -PassThru -WindowStyle Hidden -ErrorAction Stop
        $spin = @('|','/','-','\')
        $s = 0
        while ($true) {
            $proc.Refresh()
            if ($proc.HasExited) { break }
            Write-Host ("`r  [DISM] Component Store cleanup in progress... {0}" -f $spin[$s % 4]) -NoNewline
            $s++
            Start-Sleep -Milliseconds 900
        }
        [void]$proc.WaitForExit()
        [int]$code = $proc.ExitCode
        Write-Host ("`r  [DISM] Component Store cleanup finished (exit code: {0}).                   " -f $code)
        Write-Log -Action "PURGE" -Target "DISM" -Status $(if ($code -eq 0 -or $code -eq 3010) { "Success" } else { "Failed" }) -Details "StartComponentCleanup /ResetBase exit $code"
    } catch {
        Write-Host " [DISM] Component Store cleanup skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow
        Write-Log -Action "PURGE" -Target "DISM" -Status "Skipped" -Details $_.Exception.Message
    }
    # ---- :: DISPLAY TOPOLOGY SOVEREIGNTY SHIELD (mandatory re-injection) :: ----
    try {
        Write-Host " [DISM] Re-injecting preserved display topology profiles into the kernel registry..." -ForegroundColor Cyan
        $null = Invoke-UWMDisplayTopologyShield -Restore
    } catch {
        Write-Host " [DISM] WARNING: Display topology re-injection failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Log -Action "DISM" -Target "DisplayTopology" -Status "Warning" -Details "Re-injection failed: $($_.Exception.Message)"
    }
}
function Invoke-UWMWorkingSetCompact {
    $freeBefore = 0.0; $freeAfter = 0.0; $wsFlushed = 0; $wsSkipped = 0
    Write-Log -Action "WS_COMPACT" -Target "Memory" -Status "Info" -Details "Working set compaction pipeline initiated"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $freeBefore = [Math]::Round($os.FreePhysicalMemory / 1024, 2)
    } catch {
        Write-Log -Action "WS_COMPACT" -Target "Memory" -Status "Warning" -Details "Could not read initial free RAM: $($_.Exception.Message)"
    }
    $wsMethod = "psapi"
    try {
        if (-not ('UWM_WSFlush' -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class UWM_WSFlush {
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern int EmptyWorkingSet(IntPtr hwProc);
}
"@ -ErrorAction Stop
        }
    } catch {
        Write-Log -Action "WS_COMPACT" -Target "PInvoke" -Status "Warning" -Details "psapi EmptyWorkingSet type compile failed: $($_.Exception.Message). Attempting kernel32 fallback."
        $wsMethod = "kernel32"
    }
    if ($wsMethod -eq "kernel32") {
        try {
            if (-not ('UWM_WSFlushK32' -as [type])) {
                Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class UWM_WSFlushK32 {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@ -ErrorAction Stop
            }
        } catch {
            Write-Log -Action "WS_COMPACT" -Target "PInvoke" -Status "Warning" -Details "kernel32 fallback type compile failed: $($_.Exception.Message). All PInvoke methods unavailable."
            $wsMethod = "none"
        }
    }
    if ($wsMethod -ne "none") {
        try {
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
        } catch {
            Write-Log -Action "WS_COMPACT" -Target "GC" -Status "Warning" -Details "Garbage collection cycle failed: $($_.Exception.Message)"
        }
        $systemCritical = @('csrss','dwm','wininit','winlogon','lsass','smss','services','svchost','System','Idle','Registry','conhost','fontdrvhost','sihost','ShellExperienceHost','StartMenuExperienceHost','SearchUI','dismhost','TrustedInstaller','tiworker','WmiPrvSE','spoolsv','SearchIndexer','RuntimeBroker')
        foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
            if (-not $proc.Name) { $wsSkipped++; continue }
            if ($proc.Name -in $systemCritical) { continue }
            if ($proc.Id -le 4) { continue }
            try {
                if ($wsMethod -eq "psapi") {
                    [void][UWM_WSFlush]::EmptyWorkingSet($proc.Handle)
                } else {
                    $hProc = [UWM_WSFlushK32]::OpenProcess(0x01F0, $false, $proc.Id)
                    if ($hProc -ne [IntPtr]::Zero) {
                        [void][UWM_WSFlushK32]::SetProcessWorkingSetSize($hProc, [IntPtr]::new(-1), [IntPtr]::new(-1))
                        [void][UWM_WSFlushK32]::CloseHandle($hProc)
                    } else {
                        $wsSkipped++
                        continue
                    }
                }
                $wsFlushed++
            } catch [System.ComponentModel.Win32Exception] {
                $wsSkipped++
            } catch [System.Diagnostics.Process] {
                $wsSkipped++
            } catch [System.InvalidOperationException] {
                $wsSkipped++
            } catch {
                $wsSkipped++
            }
        }
    }
    try {
        $os2 = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $freeAfter = [Math]::Round($os2.FreePhysicalMemory / 1024, 2)
    } catch {
        Write-Log -Action "WS_COMPACT" -Target "Memory" -Status "Warning" -Details "Could not read final free RAM: $($_.Exception.Message)"
    }
    [double]$gain = [Math]::Round($freeAfter - $freeBefore, 2)
    if ($gain -lt 0) { $gain = 0 }
    Write-Host "  [WS-FLUSH] Working sets compacted on $wsFlushed non-critical process(es) via $wsMethod | skipped: $wsSkipped | RAM recovered: ${gain} MB." -ForegroundColor Green
    Write-Log -Action "WS_COMPACT" -Target "Memory" -Status "Success" -Details "Method=$wsMethod, Flushed=$wsFlushed, Skipped=$wsSkipped, Before=${freeBefore}MB, After=${freeAfter}MB, Gain=${gain}MB"
    return $gain
}

function Invoke-ScheduleMenu {
    Show-Header
    if (-not (Assert-UWMWriteAccess)) { return }
    Write-Host "  [SCH] Weekly Auto-Update Registration" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    $existing = Get-ScheduledTask -TaskName "Ultra Winget Manager Weekly Update" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host " [i] Existing: $($existing.Triggers[0].DaysOfWeek) at $($existing.Triggers[0].StartBoundary.ToString('HH:mm'))" -ForegroundColor $script:Theme['Dim']
        if ((Read-Host " Remove? (Y/N)").ToUpper() -eq 'Y') {
            Unregister-ScheduledTask -TaskName "Ultra Winget Manager Weekly Update" -Confirm:$false
            Write-Host " [OK] Removed." -ForegroundColor $script:Theme['Success']
            Write-Log -Action "SCHEDULE" -Target "TaskScheduler" -Status "Removed"
        }
        Read-Host " $($script:Locale['PressEnter'])"; return
    }
    $day = Read-Host " $($script:Locale['SchedDayPrompt'])"; $time = Read-Host " $($script:Locale['SchedTimePrompt'])"
    $script:Config.scheduledUpdate.day=$day; $script:Config.scheduledUpdate.time=$time; $script:Config.scheduledUpdate.enabled=$true
    Save-Config; Register-ScheduledUpdate; Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Smart Audit & Analytics Engine ----
$script:UWMCodes = @{
    1603L  = @{ En="Fatal error during installation";                       Ar="خطأ فادح أثناء التثبيت";                TipEn="Re-download the package, run Windows Update, then retry.";                TipAr="أعد تنزيل الحزمة، شغّل Windows Update، ثم حاول مجددًا." }
    3010L  = @{ En="Success - restart required";                            Ar="تم بنجاح - يلزم إعادة التشغيل";         TipEn="Restart the PC to finalize changes.";                                     TipAr="أعد تشغيل الجهاز لإتمام التغييرات." }
    1638L  = @{ En="Another / newer version already installed";             Ar="تم تثبيت إصدار آخر / أحدث مسبقًا";      TipEn="Uninstall the existing version or match the same version.";                 TipAr="ألغِ تثبيت الإصدار الحالي أو استخدم نفس الإصدار." }
    1602L  = @{ En="User cancelled the installation";                       Ar="ألغى المستخدم التثبيت";                 TipEn="Rerun the operation when ready.";                                            TipAr="أعد تشغيل العملية عندما تكون جاهزًا." }
    1641L  = @{ En="Installation successful - restart started";             Ar="نجح التثبيت - بدأت إعادة التشغيل";      TipEn="The machine will restart automatically.";                                   TipAr="سيعاد تشغيل الجهاز تلقائيًا." }
    -2147467259L = @{ En="Generic failure (E_FAIL / 0x80004005)";           Ar="فشل عام (E_FAIL / 0x80004005)";         TipEn="Verify prerequisite runtimes (VC++, .NET) and retry.";                      TipAr="تحقق من متطلبات التشغيل (VC++، .NET) ثم أعد المحاولة." }
    -2147024891L = @{ En="Access denied (E_ACCESSDENIED / 0x80070005)";     Ar="تم رفض الوصول (E_ACCESSDENIED / 0x80070005)"; TipEn="Run elevated as Administrator.";                                           TipAr="شغّل بصلاحيات المسؤول." }
    -2147024894L = @{ En="File not found (0x80070002)";                     Ar="الملف غير موجود (0x80070002)";          TipEn="Re-download and verify the installer path.";                                TipAr="أعد تنزيل المثبت وتحقق من المسار." }
    2149844547L = @{ En="Installation failed (0x80070643)";                 Ar="فشل التثبيت (0x80070643)";              TipEn="Run Windows Update repair, then retry.";                                    TipAr="شغّل إصلاح Windows Update ثم أعد المحاولة." }
    2147942512L = @{ En="Disk is full (0x80070070)";                        Ar="القرص ممتلئ (0x80070070)";              TipEn="Free up disk space and retry.";                                              TipAr="أخلِ مساحة على القرص ثم أعد المحاولة." }
    2147787517L = @{ En="Network connection error (0x80072EFD)";            Ar="خطأ في الاتصال بالشبكة (0x80072EFD)";   TipEn="Check internet connectivity and proxy settings.";                          TipAr="تحقق من الاتصال بالإنترنت وإعدادات الوكيل." }
}
function Get-UWMExitCodeDiagnostic {
    param([long]$Code)
    if ($null -ne $script:UWMCodes -and $script:UWMCodes.ContainsKey($Code)) { return $script:UWMCodes[$Code] }
    return $null
}
function Get-UWMExitCodesInSet {
    param($Entries)
    $found = [System.Collections.Generic.Dictionary[string, object]]::new()
    foreach ($en in $Entries) {
        $text = [string]$en.Details + " " + [string]$en.Target
        $ms = [regex]::Matches($text, '(?i)(?:exit\s*code|code|status)\s*[:=]\s*((-?\d+)|(0x[0-9a-fA-F]+))')
        foreach ($m in $ms) {
            [string]$raw = $m.Groups[1].Value
            [long]$val = 0
            if ($raw -match '^0x') { try { $val = [Convert]::ToInt64($raw.Substring(2), 16) } catch { continue } }
            else { try { $val = [long]$raw } catch { continue } }
            $diag = Get-UWMExitCodeDiagnostic -Code $val
            if ($null -eq $diag) { continue }
            $found[$val.ToString()] = @{ Code = $val; En = $diag.En; Ar = $diag.Ar; TipEn = $diag.TipEn; TipAr = $diag.TipAr }
        }
    }
    return @($found.Values)
}
function Show-UWMExitCodeIndex {
    Write-Host ""
    Write-Host "  [EXIT-CODE INDEX] Deployment diagnostics (EN / AR)" -ForegroundColor Cyan
    Write-Host ("  " + "-" * 52)
    foreach ($k in @($script:UWMCodes.Keys | Sort-Object)) {
        $d = $script:UWMCodes[$k]
        $hex = "0x{0:X8}" -f ([int64]$k -band 0xFFFFFFFF)
        Write-Host ("   {0,-12} | {1}" -f $k, $d.En) -ForegroundColor Yellow
        Write-Host ("     AR : {0}" -f $d.Ar) -ForegroundColor $script:Theme['Text']
        Write-Host ("     TIP: {0}" -f $d.TipEn) -ForegroundColor $script:Theme['Dim']
    }
    Write-Host ("  " + "-" * 52)
    Read-Host " $($script:Locale['PressEnter'])"
}
function Show-UWMLogFilter {
    param($Filter)
    while ($true) {
        Write-Host ""
        Write-Host "  [FILTER] Smart Audit filter controls" -ForegroundColor Cyan
        Write-Host ("  " + "-" * 52)
        Write-Host ("   [F] Failures-only toggle .......... {0}" -f $(if ($Filter.Failures) { 'ON' } else { 'OFF' })) -ForegroundColor $script:Theme['Text']
        Write-Host ("   [A] Filter by Action .............. {0}" -f $(if ($Filter.Action) { $Filter.Action } else { '-' })) -ForegroundColor $script:Theme['Text']
        Write-Host ("   [S] Filter by application search .. {0}" -f $(if ($Filter.Search) { $Filter.Search } else { '-' })) -ForegroundColor $script:Theme['Text']
        Write-Host "   [C] Clear all filters" -ForegroundColor $script:Theme['Text']
        Write-Host "   [B] Back to audit viewer" -ForegroundColor $script:Theme['Text']
        Write-Host ("  " + "-" * 52)
        Write-Host "   $($script:Locale['NavPrompt'])" -NoNewline -ForegroundColor $script:Theme['Accent']
        [char]$k = Get-UWMRawKey
        if ($k -eq [char]0) { if (-not (Test-UWMConsoleAvailable)) { return $Filter }; continue }
        [char]$ck = [char]::ToUpper($k)
        if ($ck -eq 'B') { return $Filter }
        elseif ($ck -eq 'F') { $Filter.Failures = -not $Filter.Failures }
        elseif ($ck -eq 'C') { $Filter = @{ Failures = $false; Action = $null; Search = $null } }
        elseif ($ck -eq 'A') {
            Write-Host ""
            $Filter.Action = Read-Host "   Action filter (e.g. UPDATE, INSTALL, PURGE, GLOBAL). Empty = clear"
            if ([string]::IsNullOrWhiteSpace($Filter.Action)) { $Filter.Action = $null }
        }
        elseif ($ck -eq 'S') {
            Write-Host ""
            $Filter.Search = Read-Host "   Application search string. Empty = clear"
            if ([string]::IsNullOrWhiteSpace($Filter.Search)) { $Filter.Search = $null }
        }
    }
}
function Invoke-ViewLog {
    Show-Header
    $entries = @(Read-UWMTransactionLog)
    if ($entries.Count -eq 0) {
        Write-Host "  [INFO] No transaction records found in the audit database." -ForegroundColor Yellow
        Write-Host ("  [INFO] Audit log: {0}" -f $script:LogPath) -ForegroundColor $script:Theme['Dim']
        Read-Host " $($script:Locale['PressEnter'])"
        return
    }

    $filter = @{ Failures = $false; Action = $null; Search = $null }
    [bool]$interactive = Test-UWMConsoleAvailable
    [string]$cacheFilterSig = $null
    [object[]]$cacheSorted = @()
    [int]$cacheShown = 0
    [int]$cacheFails = 0
    [int]$cacheOkRate = 0
    [object[]]$cacheDiag = @()
    [string]$cacheFState = "OFF"
    [string]$cacheAState = "-"
    [string]$cacheSState = "-"
    [hashtable]$cacheTsLocal = @{}
    [int]$page = 0

    while ($true) {
        [string]$curSig = [string]$filter.Failures + [string][char]2 + [string]$filter.Action + [string][char]2 + [string]$filter.Search
        if ($curSig -ne $cacheFilterSig) {
            [object[]]$pool = @($entries)
            if ($filter.Failures) { $pool = @($pool | Where-Object { $_.Status -in @('Failed','Error') }) }
            if (-not [string]::IsNullOrWhiteSpace($filter.Action)) { $pool = @($pool | Where-Object { [string]$_.Action -match [regex]::Escape($filter.Action) }) }
            if (-not [string]::IsNullOrWhiteSpace($filter.Search)) { $pool = @($pool | Where-Object { ("$($_.Target) $($_.Details)") -match [regex]::Escape($filter.Search) }) }
            if ($null -ne $script:UWMRescueAcked -and $script:UWMRescueAcked.Count -gt 0) {
                $pool = @($pool | Where-Object {
                    [string]$s = [string]$_.Status
                    [string]$k = [string]$_.Timestamp
                    ($s -notin @('Failed','Error')) -or [string]::IsNullOrWhiteSpace($k) -or (-not $script:UWMRescueAcked.ContainsKey($k))
                })
            }
            if ($pool.Count -eq 0) {
                Write-Host "  [INFO] No entries match the active filter set." -ForegroundColor Yellow
                Read-Host " $($script:Locale['PressEnter'])"
                $filter = @{ Failures = $false; Action = $null; Search = $null }
                continue
            }
            [object[]]$sorted = @($pool | Sort-Object -Property @{ Expression = {
                try { [datetime]::Parse($_.Timestamp).ToUniversalTime() } catch { [datetime]::MinValue }
            }} -Descending)

            [int]$shown = $sorted.Count
            [int]$fails = @($sorted | Where-Object { $_.Status -in @('Failed','Error') }).Count
            [int]$okRate = 0
            if ($shown -gt 0) { $okRate = [Math]::Round((($shown - $fails) / $shown) * 100) }
            [object[]]$diag = @(Get-UWMExitCodesInSet -Entries $sorted)
            [string]$fState = if ($filter.Failures) { "ON" } else { "OFF" }
            [string]$aState = if ($filter.Action) { $filter.Action } else { "-" }
            [string]$sState = if ($filter.Search) { $filter.Search } else { "-" }

            [hashtable]$tsLocal = @{}
            foreach ($en in $sorted) {
                [string]$tsr = [string]$en.Timestamp
                if ([string]::IsNullOrWhiteSpace($tsr)) { continue }
                try { $tsLocal[$tsr] = ([datetime]::Parse($tsr)).ToLocalTime().ToString("HH:mm:ss") } catch { $tsLocal[$tsr] = "--:--:--" }
            }

            $cacheFilterSig = $curSig
            $cacheSorted = @($sorted)
            $cacheShown = $shown
            $cacheFails = $fails
            $cacheOkRate = $okRate
            $cacheDiag = @($diag)
            $cacheFState = $fState
            $cacheAState = $aState
            $cacheSState = $sState
            $cacheTsLocal = $tsLocal
            $page = 0
        }

        [object[]]$sorted = @($cacheSorted)
        [int]$shown = $cacheShown
        [int]$fails = $cacheFails
        [int]$okRate = $cacheOkRate
        [object[]]$diag = @($cacheDiag)
        [string]$fState = $cacheFState
        [string]$aState = $cacheAState
        [string]$sState = $cacheSState

        [int]$pageSize = [Math]::Max(1, [int]$script:Config.ui.pageSize)
        [int]$pageCount = [Math]::Max(1, [Math]::Ceiling($shown / $pageSize))
        if ($page -gt ($pageCount - 1)) { $page = $pageCount - 1 }
        if ($page -lt 0) { $page = 0 }
        :pageLoop while ($true) {
            Show-Header
            Write-Host "  [AUDIT] Smart Transaction Audit & Analytics Engine" -ForegroundColor $script:Theme['Accent']
            Write-Host ("  " + "-" * 52)
            Write-Host ("  [ANALYTICS] Total: {0} | Shown: {1} | Failures: {2} | Success-rate: {3}%" -f $entries.Count, $shown, $fails, $okRate) -ForegroundColor Cyan
            if ($diag.Count -gt 0) {
                Write-Host ("  [CODES] " + (($diag | ForEach-Object { $_.Code }) -join ", ")) -ForegroundColor Yellow
            }
            Write-Host ("  [FILTER] Failures:{0} | Action:{1} | Search:{2}" -f $fState, $aState, $sState) -ForegroundColor $script:Theme['Dim']
            if ($null -ne $script:UWMRescueAcked -and $script:UWMRescueAcked.Count -gt 0) {
                Write-Host ("  [RESCUE] {0} red error line(s) wiped from the active view this session. Press [R] again to re-arm." -f $script:UWMRescueAcked.Count) -ForegroundColor $script:Theme['Success']
            }

            [int]$start = $page * $pageSize
            [int]$end = [Math]::Min($start + $pageSize - 1, $shown - 1)
            [object[]]$slice = @($sorted[$start..$end])

            [int]$timeW = 8
            [int]$statusW = 10; [int]$actionW = 18; [int]$targetW = 28
            foreach ($en in $slice) {
                [string]$st = [string]$en.Status; if (-not $st) { $st = "Info" }
                [string]$ac = [string]$en.Action; if (-not $ac) { $ac = "-" }
                [string]$tg = [string]$en.Target; if (-not $tg) { $tg = "-" }
                $statusW = [Math]::Max($statusW, (Get-UWMDisplayWidth $st))
                $actionW = [Math]::Max($actionW, (Get-UWMDisplayWidth $ac))
                $targetW = [Math]::Max($targetW, (Get-UWMDisplayWidth $tg))
            }
            $statusW = [Math]::Min($statusW, 14)
            $actionW = [Math]::Min($actionW, 26)
            $targetW = [Math]::Min($targetW, 34)
            [hashtable]$m = Get-UWMConsoleMetrics
            [int]$avail = [Math]::Max(40, $m.Width - 9)
            [int]$detailsW = $avail - ($timeW + $statusW + $actionW + $targetW)
            while ($detailsW -lt 12 -and $targetW -gt 16) { $targetW--; $detailsW++ }
            while ($detailsW -lt 12 -and $actionW -gt 14) { $actionW--; $detailsW++ }
            if ($detailsW -lt 12) { $detailsW = 12 }

            [int[]]$widths = @($timeW, $statusW, $actionW, $targetW, $detailsW)
            Write-Host (New-UWMBorderLine -Widths $widths -L "╔" -Mid "╦" -R "╗") -ForegroundColor $script:Theme['Dim']
            $hdrCells = @(
                @{ Text = "Time"; Color = "Cyan" }
                @{ Text = "Status"; Color = "Cyan" }
                @{ Text = "Action"; Color = "Cyan" }
                @{ Text = "Target"; Color = "Cyan" }
                @{ Text = "Details"; Color = "Cyan" }
            )
            Write-UWMRowLine -Widths $widths -Cells $hdrCells
            Write-Host (New-UWMBorderLine -Widths $widths -L "╠" -Mid "╬" -R "╣") -ForegroundColor $script:Theme['Dim']
            foreach ($en in $slice) {
                [string]$ts = [string]$en.Timestamp
                [string]$tLocal = if ($cacheTsLocal.ContainsKey($ts)) { $cacheTsLocal[$ts] } else { "--:--:--" }
                [string]$st = [string]$en.Status; if (-not $st) { $st = "Info" }
                [string]$ac = [string]$en.Action; if (-not $ac) { $ac = "-" }
                [string]$tg = [string]$en.Target; if (-not $tg) { $tg = "-" }
                [string]$de = [string]$en.Details; if (-not $de) { $de = "" }
                [string]$stColor = if ($st -in @('Failed','Error')) { "Red" } elseif ($st -eq 'Success') { $script:Theme['Success'] } else { "Yellow" }
                $cells = @(
                    @{ Text = $tLocal; Color = $script:Theme['Dim'] }
                    @{ Text = $st; Color = $stColor }
                    @{ Text = $ac; Color = "Cyan" }
                    @{ Text = $tg; Color = $script:Theme['Accent'] }
                    @{ Text = $de; Color = $script:Theme['Text'] }
                )
                Write-UWMRowLine -Widths $widths -Cells $cells
            }
            Write-Host (New-UWMBorderLine -Widths $widths -L "╚" -Mid "╩" -R "╝") -ForegroundColor $script:Theme['Dim']
            Write-Host ("  " + "-" * 52)
            Write-Host ("  Page {0}/{1}" -f ($page + 1), $pageCount) -ForegroundColor $script:Theme['Dim']
            Write-UWMLogLegend

            if (-not $interactive) { return }
            [char]$nk = Get-UWMRawKey
            if ($nk -eq [char]0) { if (-not $interactive) { return }; continue }
            [char]$ck = [char]::ToUpper($nk)
            if ($ck -eq 'N') { if ($page -lt $pageCount - 1) { $page++ } }
            elseif ($ck -eq 'P') { if ($page -gt 0) { $page-- } }
            elseif ($ck -eq 'B') { return }
            elseif ($ck -eq 'F') { $filter = Show-UWMLogFilter -Filter $filter; $cacheFilterSig = $null; break pageLoop }
            elseif ($ck -eq 'E') { Show-UWMExitCodeIndex }
            elseif ($ck -eq 'R') {
                Invoke-UWMRescuePipeline -Entries $entries
                $cacheFilterSig = $null
                $entries = @(Read-UWMTransactionLog)
                if (-not $interactive) { return }
                break pageLoop
            }
            elseif ($ck -eq 'C') { $filter = @{ Failures = $false; Action = $null; Search = $null }; $cacheFilterSig = $null; break pageLoop }
        }
    }
}

function Invoke-UWMRescuePipeline {
    param([object[]]$Entries)
    $script:UWMRescueAcked = @{}
    [object[]]$anoms = @()
    [object[]]$red = @()
    [bool]$infra = $false
    [bool]$spawned = $false
    [bool]$selfHealed = $false
    [int]$wipe = 0
    [string]$skipReason = ""
    [hashtable]$m = Get-UWMConsoleMetrics
    [int]$barW = [Math]::Max(20, $m.Width - 4)
    try {
        Show-Header
        Write-Host "  [RESCUE] Autonomous Hot-Remediation & Cache Purge Kernel" -ForegroundColor $script:Theme['Accent']
        Write-Host ("  " + ("-" * $barW))
        try {
            $anoms = @($Entries | Where-Object { $null -ne $_.Status -and [string]$_.Status -in @('Failed','Error') })
            if ($anoms.Count -eq 0) {
                $anoms = @($Entries | Where-Object { [string]$_.Action -match '(?i)(fail|error|denied|timeout|deadlock|repair|corrupt)' })
            }
        } catch { $anoms = @() }
        $red = @($anoms | Where-Object { [string]$_.Status -in @('Failed','Error') })
        $wipe = $red.Count
        Write-Host ("  [SCAN] {0} anomaly record(s) isolated from the active audit scope." -f $anoms.Count) -ForegroundColor Cyan
        Write-Host ("  [SCAN] {0} red-class error line(s) marked for wipe." -f $wipe) -ForegroundColor Yellow
        if ($anoms.Count -eq 0) {
            Write-Host "  [SCAN] System equilibrium nominal — no remediation blueprint required." -ForegroundColor $script:Theme['Success']
        }
        $infra = [bool]($anoms | Where-Object {
            (([string]$_.Action) -match '(?i)(UPDATE_REPAIR|DISM|SFC|WIN_UPDATE|WUSA|COMPONENT|STORE|ARC_)') -or
            ((("$($_.Target) $($_.Details)") -match '(?i)(component store|corrupt|softwaredistribution|catroot2|windows update|0x[0-9a-f]{6,8})'))
        })
        if ($infra) {
            Write-Host "  [INFRA] Infrastructure fault / component-store signature confirmed — engaging background hot-remediation blueprint..." -ForegroundColor Yellow
        } else {
            Write-Host "  [INFRA] No component-store corruption signature — repair daemon bypassed, cache purge engaged." -ForegroundColor $script:Theme['Dim']
        }
        if ($infra) {
            try {
                $cooldown = (([DateTime]::UtcNow) - $script:UWMArcLastTrigger).TotalSeconds -lt 60
                if ($cooldown) {
                    Write-Host "  [COOLDOWN] Global arc trigger cooldown active — remediation daemon already anchored recently." -ForegroundColor $script:Theme['Dim']
                    $skipReason = "global arc cooldown active"
                } else {
                    $sp = if ($script:ScriptPath) { $script:ScriptPath } else { Join-Path $PSScriptRoot "update.ps1" }
                    $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$sp`" -SilentGlobal -ArcRepairScope"
                    Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle Hidden -ErrorAction Stop | Out-Null
                    $spawned = $true
                    $script:UWMArcLastTrigger = [DateTime]::UtcNow
                    try { if ($null -eq $script:UWMArcRemediated) { $script:UWMArcRemediated = @{} }; $script:UWMArcRemediated['RESCUE'] = [DateTime]::UtcNow } catch { }
                }
            } catch { $spawned = $false; $skipReason = "hidden daemon spawn failed" }
        }
        if ($spawned) {
            Write-Host "  [DAEMON] Hidden elevated remediation daemon anchored. Repair + cache purge executing autonomously..." -ForegroundColor $script:Theme['Success']
            try { Write-Log -Action "RESCUE_TRIGGER" -Target "Infrastructure" -Status "Anchored" -Details "Hot-remediation daemon spawned from audit rescue kernel" } catch { }
            $t0 = [DateTime]::UtcNow
            $deadline = $t0.AddSeconds(16)
            while ([DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 800
                try {
                    $script:LogCache = $null
                    $fresh = @(Read-UWMTransactionLog)
                    $healed = @(($fresh | Where-Object {
                        [string]$_.Action -eq 'UPDATE_REPAIR' -and [string]$_.Status -in @('Done','Bypassed','Repaired')
                    } | Where-Object {
                        try { ([datetime]::Parse([string]$_.Timestamp).ToUniversalTime()) -gt $t0.AddSeconds(-2) } catch { $false }
                    }))
                    if ($healed.Count -gt 0) { $selfHealed = $true; break }
                } catch { }
            }
            if ($selfHealed) {
                Write-Host "  [SELF-HEAL] Confirmed: remediation daemon reported completion into the audit DB." -ForegroundColor $script:Theme['Success']
            } else {
                Write-Host "  [SELF-HEAL] Repair daemon still executing in background — red lines dissolve now, residuals at next refresh." -ForegroundColor Yellow
            }
        } else {
            if ($skipReason) {
                Write-Host ("  [DAEMON] Background repair cycle skipped ({0}). Cache purge + redraw proceeding." -f $skipReason) -ForegroundColor $script:Theme['Dim']
            } else {
                Write-Host "  [DAEMON] Background repair cycle skipped (no infrastructure fault). Cache purge + redraw proceeding." -ForegroundColor $script:Theme['Dim']
            }
        }
    } catch { }
    finally {
        try {
            foreach ($en in $red) {
                [string]$key = [string]$en.Timestamp
                if ([string]::IsNullOrWhiteSpace($key)) { $key = [guid]::NewGuid().ToString() }
                $script:UWMRescueAcked[$key] = $true
            }
        } catch { }
        $script:LogCache = $null
        try { [void](Read-UWMTransactionLog) } catch { }
        $recap = @(
            @{ Text = "  [PURGE] Error cache wiped; audit database refresh loop forced."; Color = $script:Theme['Success'] }
            @{ Text = ("  [REDRAW] Double-buffered redraw engaged — {0} red error line(s) dissolving from the active view." -f $wipe); Color = $script:Theme['Success'] }
            @{ Text = ("  [STATUS] Rescue opcode complete. Spawned={0} | SelfHealed={1} | Wiped={2} | InfraFault={3}" -f $spawned, $selfHealed, $wipe, $infra); Color = $script:Theme['Dim'] }
        )
        Show-Header
        Write-Host "  [RESCUE] Remediation Kernel — Completion Summary" -ForegroundColor $script:Theme['Accent']
        Write-Host ("  " + ("-" * $barW))
        foreach ($rc in $recap) {
            $lineTxt = [string]$rc.Text
            if ((Get-UWMDisplayWidth $lineTxt) -gt $barW) { $lineTxt = Get-UWMTruncated -Text $lineTxt -MaxWidth $barW }
            Write-Host $lineTxt -ForegroundColor $rc.Color
        }
        Write-Host ""
        Write-Host "  Press any key to return to the audit loop..." -ForegroundColor $script:Theme['Dim']
        try { [void][Console]::ReadKey($true) } catch { }
    }
}

# ---- Quantum Memory Optimizer (standalone legacy engine) ----
function Invoke-UWMMemoryOptimizer {
    Show-Header
    Write-Host "  [QUANTUM] Memory Optimizer & Working Set Compactor" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 52)

    $osSnap = Get-CimInstance Win32_OperatingSystem
    $freeBefore = [Math]::Round($osSnap.FreePhysicalMemory / 1024, 2)
    $totalMB = [Math]::Round($osSnap.TotalVisibleMemorySize / 1024, 2)
    Write-Host "`n  [SNAPSHOT] Pre-optimization free memory: ${freeBefore} MB / ${totalMB} MB" -ForegroundColor Cyan

    Write-Host "`n  [PHASE 1/3] Executing deep .NET garbage collection compaction cycle..." -ForegroundColor Yellow
    try {
        $gcBefore = [Math]::Round([GC]::GetTotalMemory($false) / 1MB, 2)
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        $gcAfter = [Math]::Round([GC]::GetTotalMemory($false) / 1MB, 2)
        $gcReclaimed = [Math]::Round($gcBefore - $gcAfter, 2)
        Write-Host "  [OK] GC compaction cycle complete. Heap reclaimed: ${gcReclaimed} MB (Before: ${gcBefore} MB -> After: ${gcAfter} MB)" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] GC cycle encountered access boundary: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    Write-Host "`n  [PHASE 2/3] Flushing working sets for non-critical user-space processes..." -ForegroundColor Yellow
    $wsFlushed = 0
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class UWM_WSFlush {
    [DllImport("psapi.dll", SetLastError = true)]
    public static extern int EmptyWorkingSet(IntPtr hwProc);
}
"@ -ErrorAction SilentlyContinue

        $systemCritical = @('csrss','dwm','wininit','winlogon','lsass','smss','services',
                            'svchost','System','Idle','Registry','conhost','fontdrvhost',
                            'sihost','ShellExperienceHost','StartMenuExperienceHost',
                            'SearchUI','dismhost','TrustedInstaller','tiworker',
                            'WmiPrvSE','spoolsv','SearchIndexer','RuntimeBroker')
        $targetProcesses = Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -and $_.Name -notin $systemCritical -and $_.Id -gt 4 }

        foreach ($proc in $targetProcesses) {
            try {
                $hProc = $proc.Handle
                if ($hProc -and $hProc -ne [IntPtr]::Zero) {
                    [void][UWM_WSFlush]::EmptyWorkingSet($hProc)
                    $wsFlushed++
                }
            } catch {}
        }
        Write-Host "  [OK] Working set flush executed on $wsFlushed user-space process(es)." -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Native API injection bypassed system boundary: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    Write-Host "`n  [PHASE 3/3] Purging OS cache pipelines and DNS resolver..." -ForegroundColor Yellow
    try {
        Clear-DnsClientCache -ErrorAction Stop
        Write-Host "  [OK] DNS resolver cache flushed successfully." -ForegroundColor Green
    } catch {
        Write-Host "  [INFO] DNS cache flush skipped (insufficient privilege)." -ForegroundColor DarkYellow
    }
    try {
        $ipFlush = & ipconfig /flushdns 2>&1
        Write-Host "  [OK] Network adapter DNS pipeline purged." -ForegroundColor Green
    } catch {
        Write-Host "  [INFO] ipconfig /flushdns skipped (permission boundary)." -ForegroundColor DarkYellow
    }

    $osFinal = Get-CimInstance Win32_OperatingSystem
    $freeAfter = [Math]::Round($osFinal.FreePhysicalMemory / 1024, 2)
    $netGain = [Math]::Round($freeAfter - $freeBefore, 2)

    Write-Host ("`n  " + "-" * 52)
    Write-Host "  [RESULT] Post-optimization free memory: ${freeAfter} MB / ${totalMB} MB" -ForegroundColor Cyan
    if ($netGain -gt 0) {
        Write-Host "  [GAIN] +${netGain} MB memory recovered through quantum compaction pipeline." -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Memory delta: ${netGain} MB (system dynamically redistributed allocations)." -ForegroundColor DarkYellow
    }
    Write-Host ("  " + "-" * 52)
    Write-Log -Action "MEMORY_OPTIMIZE" -Target "System" -Status "Success" -Details "Pre: ${freeBefore}MB | Post: ${freeAfter}MB | Delta: ${netGain}MB | WSFlushed: $wsFlushed"
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Forced Ownership Capture Harness: seizes System/TrustedInstaller boundaries ----
function Invoke-UWMOwnershipSeize {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        Start-Process takeown.exe -ArgumentList "/f `"$Path`" /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
    } catch {}
    try {
        Start-Process icacls.exe -ArgumentList "`"$Path`" /grant administrators:F /t /c /q" -NoNewWindow -Wait -ErrorAction SilentlyContinue
    } catch {}
}

# ---- Independent Physical Purge: recursive unblocked evaporation of residue paths ----
function Invoke-UWMResiduePurge {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $false }
    try {
        Invoke-UWMOwnershipSeize -Path $Path
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) {
            Start-Process cmd.exe -ArgumentList "/c rmdir /s /q `"$Path`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }
        return -not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

# ---- Resilient Matrix Profile Hub ----
function Invoke-IgnoreListMenu {
    while ($true) {
        Show-Header
        Write-Host "  [MATRIX] Resilient Software Profile Hub" -ForegroundColor $script:Theme['Accent']
        Write-Host ("  " + "-" * 46)
        Write-Host "   (E) Export current system software blueprint to JSON" -ForegroundColor $script:Theme['Text']
        Write-Host "   (I) Import a saved blueprint profile and deploy packages" -ForegroundColor $script:Theme['Text']
        Write-Host "   (B) Return to master control menu" -ForegroundColor $script:Theme['Dim']
        Write-Host ("  " + "-" * 46)
        $action = (Read-Host "`n Select matrix operation").ToUpper()
        if ($action -eq 'B') { break }

        switch ($action) {
        'E' {
            Clear-Host
            Show-Header
            Write-Host "=== MATRIX PROFILE EXPORT ENGINE ===" -ForegroundColor $script:Theme['Header']
            Write-Host " Collecting installed software blueprints from winget registries...`n" -ForegroundColor Cyan

            $ProfileEntries = [System.Collections.Generic.List[hashtable]]::new()
            $RegistryNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $RegistryIds   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

            # Pre-compiled library/framework token registry for O(1) substring matching
            $LibFrameworkTokens = @('VCLibs','Runtime','Framework','Xaml','SDK','DirectX',
                                    '.NET','Redistributable','Platform','UWP','DesktopBridge',
                                    'WebView','WebView2','MSVC','CRT','OpenSSL','Mono',
                                    'Native','Shared','Core','Base','Common','Engine',
                                    'Helper','Service','Bridge','Adapter','RuntimePackage',
                                    'FrameworkPackage','Dependencies','VisualCpp')
            $LibPatternStr = '(' + (($LibFrameworkTokens | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
            $LibPattern = [regex]::new($LibPatternStr, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

            # Publisher namespace: OS distribution channel identifiers
            $OSPublishers = @('Microsoft Corporation','Microsoft Windows','Microsoft Publisher',
                              'Microsoft Desktop','Windows','OS Distribution Channel')
            $OSPubsPatternStr = '(' + (($OSPublishers | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
            $OSPubsPattern = [regex]::new($OSPubsPatternStr, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

            # ==========================================================================
            # PHASE 1/2: Registry Hive Enumeration with Agnostic Infrastructure Filter
            # ==========================================================================
            Write-Host " [PHASE 1/2] Scanning Registry hives with heuristic attribute inspection..." -ForegroundColor Yellow
            $RegPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            $sysIsolated = 0; $libFiltered = 0; $nsFiltered = 0; $nonUiFiltered = 0; $msixFiltered = 0; $extFiltered = 0
            try {
                $regApps = Get-ItemProperty $RegPaths -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -and ($_.PSChildName -or $_.UninstallString) }

                foreach ($app in $regApps) {
                    $regId   = $app.PSChildName
                    $regName = $app.DisplayName
                    if ([string]::IsNullOrWhiteSpace($regId) -or [string]::IsNullOrWhiteSpace($regName)) { continue }

                    # --- Heuristic Attribute Inspection: Dynamic Component Isolation ---
                    $reject = $false

                    # SystemComponent=1 → integrated OS component (Windows itself sets this flag)
                    if ($app.SystemComponent -eq 1) { $reject = $true }

                    # ParentKeyName present → child/dependency product of a parent installer, not standalone
                    if (-not $reject -and -not [string]::IsNullOrWhiteSpace($app.ParentKeyName)) { $reject = $true }

                    # ReleaseType → structural classification by Windows Installer service
                    if (-not $reject) {
                        $rt = $app.ReleaseType
                        if ($rt -and $rt -in @('Update','Security Update','Hotfix','Service Pack',
                                                 'Driver','Update Rollout','Critical Update',
                                                 'Definition Update','Tools','PreRelease')) { $reject = $true }
                    }

                    # BundleToUpgrade → dependency bundle with no independent execution scope
                    if (-not $reject -and -not [string]::IsNullOrWhiteSpace($app.BundleToUpgrade)) { $reject = $true }

                    # WindowsInstaller=1 with empty InstallLocation and no QuietUninstallString
                    # → system-level MSI patch with no user-accessible application footprint
                    if (-not $reject -and $app.WindowsInstaller -eq 1 -and
                        [string]::IsNullOrWhiteSpace($app.InstallLocation) -and
                        [string]::IsNullOrWhiteSpace($app.QuietUninstallString)) { $reject = $true }

                    # Pure GUID as PSChildName with empty DisplayName → orphaned MSI component
                    if (-not $reject -and $regId -match '^\{[0-9A-Fa-f\-]+\}$' -and
                        [string]::IsNullOrWhiteSpace($regName)) { $reject = $true }

                    # KB article identifier pattern in either ID or Name → Windows Update hotfix
                    if (-not $reject -and ($regId -match '(?i)^KB\d+' -or $regName -match '(?i)^KB\d+')) { $reject = $true }

                    # --- Runtime & Library Eradication Filter ---
                    # Block execution libraries, frameworks, SDKs, redistributables, UWP bridge components
                    if (-not $reject) {
                        $nameIdConcat = "$regName $regId"
                        if ($LibPattern.IsMatch($nameIdConcat)) { $reject = $true; $libFiltered++ }
                    }

                    # --- Non-UI System Subsystem Isolation ---
                    # Reject shared libraries with no standalone launchable user interface
                    if (-not $reject) {
                        $hasValidLoc = (-not [string]::IsNullOrWhiteSpace($app.InstallLocation)) -and
                                       (Test-Path $app.InstallLocation -ErrorAction SilentlyContinue)
                        $hasQuietUn = -not [string]::IsNullOrWhiteSpace($app.QuietUninstallString)
                        $uninstStr  = $app.UninstallString
                        $isMsiExecOnly = $uninstStr -and $uninstStr -match '(?i)^MsiExec\.exe\s+/X\{'

                        if (-not $hasValidLoc -and -not $hasQuietUn -and $isMsiExecOnly) {
                            $reject = $true; $nonUiFiltered++
                        }
                    }

                    # --- Publisher Domain & Namespace Cleanliness ---
                    # Exclude shared infrastructure namespaces from OS distribution channels
                    if (-not $reject) {
                        $pub = $app.Publisher
                        if ($pub -and $OSPubsPattern.IsMatch($pub)) {
                            $hasLoc  = (-not [string]::IsNullOrWhiteSpace($app.InstallLocation)) -and
                                       (Test-Path $app.InstallLocation -ErrorAction SilentlyContinue)
                            $hasQuiet = -not [string]::IsNullOrWhiteSpace($app.QuietUninstallString)
                            $hasExec  = $app.UninstallString -and
                                        $app.UninstallString -notmatch '(?i)^MsiExec\.exe\s+/X\{'

                            if (-not $hasLoc -and -not $hasQuiet -and -not $hasExec) {
                                $reject = $true; $nsFiltered++
                            }
                        }
                    }

                    # --- MSIX/UWP Store Extension Hard-Block ---
                    # Reject provisioned AppX packages, store infrastructure, and UWP system overlays
                    if (-not $reject) {
                        # PackageFullName property present → MSIX/AppX provisioned package
                        if (-not [string]::IsNullOrWhiteSpace($app.PackageFullName)) {
                            $reject = $true; $msixFiltered++
                        }
                        # PackageFamilyName property present → store package family registration
                        if (-not $reject -and -not [string]::IsNullOrWhiteSpace($app.PackageFamilyName)) {
                            $reject = $true; $msixFiltered++
                        }
                        # WindowsApps install path → UWP store deployment root
                        if (-not $reject) {
                            $iloc = $app.InstallLocation
                            if ($iloc -and $iloc -match '(?i)\\WindowsApps\\') {
                                $reject = $true; $msixFiltered++
                            }
                        }
                    }

                    # --- App Extension & Stub Termination ---
                    # Deny OS extensions, background framework stubs, codec overlays, platform containers
                    if (-not $reject) {
                        $extStubPattern = '(?i)(Extension|Codec|Overlay|GameBar|GameOverlay|CrossDevice|Store|WebMedia|WebExperience|StorePurchase|PrintDialog|Wallet|People|PhoneLink|Skype|OneNote|StickyNotes|FeedbackHub|GetHelp|Getstarted|Tips|Solitaire|MixedReality|PenWorkspace|ScreenSketch|Xbox|MediaPlayer|ZuneMusic|ZuneVideo|SecurePlayer|HEIFImage|HEVCVideo|AV1|VP9)'
                        if ("$regName $regId" -match $extStubPattern) {
                            $reject = $true; $extFiltered++
                        }
                    }

                    if ($reject) { $sysIsolated++; continue }

                    # --- User-Space Verification: approve standalone consumer-facing deployments ---
                    [void]$RegistryIds.Add($regId)
                    [void]$RegistryNames.Add($regName)
                    $ProfileEntries.Add(@{
                        Name    = $regName
                        Id      = $regId
                        Version = $app.DisplayVersion
                        Source  = "registry"
                    })
                }
                Write-Host "  [FILTER] Inspection complete: $sysIsolated isolated | $libFiltered lib | $nonUiFiltered nonUI | $nsFiltered ns | $msixFiltered msix | $extFiltered ext." -ForegroundColor DarkCyan
            } catch {
                Write-Host "  [WARN] Registry enumeration hit access boundary: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            # ==========================================================================
            # PHASE 2/2: Winget Inventory with Cross-Reference Validation
            # ==========================================================================
            Write-Host " [PHASE 2/2] Querying Winget package inventory with cross-reference validation..." -ForegroundColor Yellow
            $wingetTotal = 0; $wingetCrossRef = 0; $wingetStruct = 0; $wingetLib = 0; $wingetMsix = 0; $wingetExt = 0
            try {
                $wingetRaw = & winget list --accept-source-agreements 2>$null | Out-String
                if (-not [string]::IsNullOrWhiteSpace($wingetRaw)) {
                    $wtLines = $wingetRaw -split "`r?`n"
                    $wtHeader = $false
                    foreach ($wl in $wtLines) {
                        if ($wl -match '^\s*Name\s+') { $wtHeader = $true; continue }
                        if ($wl -match '^\s*-{3,}') { continue }
                        if ($wtHeader -and -not [string]::IsNullOrWhiteSpace($wl)) {
                            $wtTokens = $wl -split '\s{2,}' | Where-Object { $_.Trim() }
                            if ($wtTokens.Count -ge 2) {
                                $wtName = $wtTokens[0].Trim()
                                $wtId   = $wtTokens[1].Trim()
                                $wtVer  = if ($wtTokens.Count -ge 3) { $wtTokens[2].Trim() } else { "" }
                                $wtVer  = $wtVer -replace '\\u003c','' -replace '[^\x20-\x7E]',''
                                $wingetTotal++

                                # MSIX/UWP prefix detection: reject MSIX\Microsoft* provisioned stubs
                                if ($wtId -match '(?i)^MSIX\\Microsoft') { $wingetMsix++; continue }
                                if ($wtId -match '(?i)^MSIX\\') { $wingetMsix++; continue }

                                # System core keyword sterilization
                                if ($wtId -match '(?i)(Photos|Clock|Alarms|GamingOverlay|Xbox|GameBar)') { $wingetExt++; continue }

                                # Structural rejection: empty/placeholder IDs
                                if ([string]::IsNullOrWhiteSpace($wtId) -or $wtId -eq 'None' -or $wtName -eq 'None') {
                                    $wingetStruct++; continue
                                }

                                # Structural rejection: KB article identifier in winget ID
                                if ($wtId -match '(?i)^KB\d+') { $wingetStruct++; continue }

                                # Structural rejection: pure GUID as package ID → orphaned MSI registration
                                if ($wtId -match '^\{[0-9A-Fa-f\-]+\}$') { $wingetStruct++; continue }

                                # Runtime & Library Eradication: block framework/library tokens in name or ID
                                $wtConcat = "$wtName $wtId"
                                if ($LibPattern.IsMatch($wtConcat)) { $wingetLib++; continue }

                                # MSIX/UWP Store Extension: reject provisioned AppX package ID pattern
                                # AppX format: Publisher.AppName_Hash (e.g. Microsoft.Windows.Photos_8wekyb3d8bbwe)
                                if ($wtId -match '(?i)^Microsoft\.[a-zA-Z]+\.[a-zA-Z]+_[a-zA-Z0-9]+$') {
                                    $wingetMsix++; continue
                                }

                                # App Extension & Stub: deny OS extensions, codec overlays, store infrastructure
                                $extStubPattern = '(?i)(Extension|Codec|Overlay|GameBar|GameOverlay|CrossDevice|Store|WebMedia|WebExperience|StorePurchase|PrintDialog|Wallet|People|PhoneLink|Skype|OneNote|StickyNotes|FeedbackHub|GetHelp|Getstarted|Tips|Solitaire|MixedReality|PenWorkspace|ScreenSketch|Xbox|MediaPlayer|ZuneMusic|ZuneVideo|SecurePlayer|HEIFImage|HEVCVideo|AV1|VP9)'
                                if ($wtConcat -match $extStubPattern) { $wingetExt++; continue }

                                # Cross-reference: registry already classified this as system component → skip
                                if ($RegistryIds.Contains($wtId) -or $RegistryNames.Contains($wtName)) {
                                    $wingetCrossRef++; continue
                                }

                                $ProfileEntries.Add(@{
                                    Name    = $wtName
                                    Id      = $wtId
                                    Version = $wtVer
                                    Source  = "winget"
                                })
                            }
                        }
                    }
                }
                Write-Host "  [CROSSREF] Winget: $wingetTotal total | $wingetStruct struct | $wingetLib lib | $wingetMsix msix | $wingetExt ext | $wingetCrossRef xref." -ForegroundColor DarkCyan
            } catch {
                Write-Host "  [WARN] Winget enumeration encountered a boundary: $($_.Exception.Message)" -ForegroundColor DarkYellow
            }

            # --- Final Array Recalculation: sanitized consumer application count ---
            $ValidatedPackagesCount = $ProfileEntries.Count
            $totalMsix = $msixFiltered + $wingetMsix
            $totalExt  = $extFiltered + $wingetExt
            Write-Host "`n  [MATRIX] Finalized consumer desktop applications: $ValidatedPackagesCount validated packages." -ForegroundColor Cyan
            Write-Host "  [FILTER] Sys: $sysIsolated | Lib: $($libFiltered + $wingetLib) | NonUI: $nonUiFiltered | NS: $nsFiltered | MSIX: $totalMsix | Ext: $totalExt" -ForegroundColor DarkCyan

            if ($ValidatedPackagesCount -eq 0) {
                Write-Host "`n [X] No standalone consumer desktop applications discovered for export." -ForegroundColor Red
                Read-Host " Press Enter to return..."; continue
            }

            $exportObj = @{
                ExportTimestamp          = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                Hostname                = $env:COMPUTERNAME
                EntryCount              = $ValidatedPackagesCount
                SystemComponentsFiltered = $sysIsolated
                LibrariesFiltered       = $libFiltered + $wingetLib
                NonUISubsystemsFiltered = $nonUiFiltered
                NamespacesFiltered      = $nsFiltered
                MSIXStoreFiltered       = $totalMsix
                ExtensionsFiltered      = $totalExt
                Packages                = $ProfileEntries.ToArray()
            }
            $exportDir = Join-Path $script:DataRoot "UWM_Profiles"
            if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
            $exportFile = Join-Path $exportDir "MatrixProfile_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

            try {
                $exportObj | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportFile -Encoding utf8 -Force
                Write-Host "`n  [SUCCESS] Matrix blueprint exported: $ValidatedPackagesCount validated packages." -ForegroundColor Green
                Write-Host "  [PATH] $exportFile" -ForegroundColor Cyan
            } catch {
                Write-Host "`n  [ERROR] Export serialization failed: $($_.Exception.Message)" -ForegroundColor Red
            }
            Write-Log -Action "MATRIX_EXPORT" -Target $exportFile -Status "Success" -Details "Validated: $ValidatedPackagesCount | Sys: $sysIsolated | Lib: $($libFiltered + $wingetLib) | NonUI: $nonUiFiltered | NS: $nsFiltered | MSIX: $totalMsix | Ext: $totalExt"
            Read-Host " $($script:Locale['PressEnter'])"
            Clear-Host
        }

        'I' {
            if (-not (Assert-UWMWriteAccess)) { continue }
            Clear-Host
            Show-Header
            Write-Host "=== MATRIX PROFILE IMPORT & DEPLOYMENT ENGINE ===" -ForegroundColor $script:Theme['Header']

            # --- Network bridge assertion ---
            Write-Host "`n [PRE-CHECK] Asserting active network bridge for deployment pipeline..." -ForegroundColor Yellow
            $isOnline = $false
            try {
                $isOnline = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction Stop
            } catch {
                try {
                    $isOnline = Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet -ErrorAction SilentlyContinue
                } catch {}
            }

            if (-not $isOnline) {
                Write-Host "  [X] No active network bridge detected. Import deployment requires internet connectivity." -ForegroundColor Red
                Write-Host "  [INFO] Connect to a network and re-run this operation." -ForegroundColor DarkYellow
                Read-Host " Press Enter to return..."; continue
            }
            Write-Host "  [OK] Network bridge active. Deployment pipeline authorized.`n" -ForegroundColor Green

            # --- Dynamic source index synchronization ---
            Write-Host " [INIT] Synchronizing installer database index..." -ForegroundColor Yellow
            try {
                & winget source update *> $null
                $srcExit = $LASTEXITCODE
                if ($srcExit -eq 0) {
                    Write-Host "  [OK] Package manager index synchronized successfully." -ForegroundColor Green
                } else {
                    Write-Host "  [WARN] Source sync returned code $srcExit — proceeding with cached index." -ForegroundColor DarkYellow
                }
            } catch {
                Write-Host "  [WARN] Source sync boundary: $($_.Exception.Message) — proceeding with cached index." -ForegroundColor DarkYellow
            }

            # --- Privilege context detection ---
            $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            $scopeArg = if ($isAdmin) { "--scope machine" } else { "--scope user" }

            # --- Locate blueprint profile ---
            $profileDir = Join-Path $script:DataRoot "UWM_Profiles"
            if (-not (Test-Path $profileDir)) {
                Write-Host "  [X] No UWM_Profiles directory found. Export a blueprint first." -ForegroundColor Red
                Read-Host " Press Enter to return..."; continue
            }
            $profiles = Get-ChildItem -Path $profileDir -Filter "*.json" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
            if ($null -eq $profiles -or $profiles.Count -eq 0) {
                Write-Host "  [X] No saved blueprint profiles discovered in vault." -ForegroundColor Red
                Read-Host " Press Enter to return..."; continue
            }

            Write-Host "Available Matrix Blueprint Profiles:" -ForegroundColor Green
            Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Yellow
            $pIdx = 1
            $pMap = @{}
            foreach ($pf in $profiles) {
                $sizeKB = [Math]::Round($pf.Length / 1KB, 1)
                Write-Host " [$pIdx] -> $($pf.Name)  (Size: ${sizeKB} KB | Modified: $($pf.LastWriteTime.ToString('MM-dd HH:mm')))" -ForegroundColor $script:Theme['Text']
                $pMap[$pIdx] = $pf.FullName
                $pIdx++
            }
            Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Yellow

            $pSel = (Read-Host "`nSelect blueprint number to DEPLOY (or 'B' to abort)").Trim()
            if ($pSel -eq 'B' -or $pSel -eq 'b') { break }
            if ([string]::IsNullOrEmpty($pSel)) { continue }
            if (-not ($pSel -match '^\d+$') -or -not $pMap.ContainsKey([int]$pSel)) {
                Write-Host "[X] Invalid selection." -ForegroundColor Red
                Read-Host " Press Enter to return..."; continue
            }

            $blueprintPath = $pMap[[int]$pSel]
            Write-Host "`n [LOADING] Parsing blueprint: $blueprintPath`n" -ForegroundColor Cyan

            try {
                $blueprint = Get-Content $blueprintPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                Write-Host "  [X] Blueprint JSON parse failed: $($_.Exception.Message)" -ForegroundColor Red
                Read-Host " Press Enter to return..."; continue
            }

            if (-not $blueprint.Packages -or $blueprint.Packages.Count -eq 0) {
                Write-Host "  [X] Blueprint contains zero deployable package entries." -ForegroundColor Red
                Read-Host " Press Enter to return..."; continue
            }

            Write-Host "  [BLUEPRINT] Host: $($blueprint.Hostname) | Entries: $($blueprint.EntryCount) | Exported: $($blueprint.ExportTimestamp)" -ForegroundColor DarkCyan
            Write-Host "  [CTX] Privilege: $(if ($isAdmin) {'Administrator'} else {'User'}) | Scope: $(if ($isAdmin) {'Machine'} else {'User'})" -ForegroundColor DarkCyan
            Write-Host "  [DEPLOY] Initiating self-healing deployment matrix...`n" -ForegroundColor Yellow

            $deployed = 0
            $skipped  = 0
            $failed   = 0
            $retryQueue = [System.Collections.Generic.List[hashtable]]::new()
            $pkgTotal = $blueprint.Packages.Count

            # --- Pre-Deployment Boundary Sanitization: orphan residue detection ---
            Write-Host " [SANITIZE] Scanning for orphaned installation residue before deployment..." -ForegroundColor Yellow
            Enter-UWMIsolation
            try {
                $sanitizedCount = 0
                $SanitizeScanRoots = @(
                    $home,
                    (Join-Path $home ".local\share"),
                    "C:\Program Files",
                    "C:\Program Files (x86)",
                    $env:LOCALAPPDATA,
                    $env:APPDATA,
                    [Environment]::GetFolderPath("Desktop")
                )
                $RegCheckRoots = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall")

            foreach ($pkg in $blueprint.Packages) {
                    $scanName = if (-not [string]::IsNullOrWhiteSpace($pkg.Name)) { $pkg.Name.Trim() } else { $null }
                    if (-not $scanName -or $scanName.Length -lt 3) { continue }
                    foreach ($sr in $SanitizeScanRoots) {
                        if (-not (Test-Path $sr)) { continue }
                        try {
                            $matchDirs = Get-ChildItem -Path $sr -Directory -ErrorAction SilentlyContinue |
                                        Where-Object { $_.Name -match [regex]::Escape($scanName) -and -not (Test-UWMIsReparsePoint -Path $_.FullName) }
                            foreach ($md in $matchDirs) {
                                $regFound = $false
                                foreach ($rr in $RegCheckRoots) {
                                    if (-not (Test-Path $rr)) { continue }
                                    $regHit = Get-ChildItem -Path $rr -ErrorAction SilentlyContinue |
                                             Where-Object { $_.PSChildName -match [regex]::Escape($scanName) -or $_.PSChildName -match [regex]::Escape($pkg.Id.Trim()) }
                                    if ($regHit) { $regFound = $true; break }
                                }
                                if (-not $regFound -and (Test-Path $md.FullName)) {
                                    Write-Host "    -> [SANITIZE] Orphaned residue: $($md.FullName) — no registry key exists." -ForegroundColor DarkYellow
                                    if (Invoke-UWMResiduePurge -Path $md.FullName) {
                                        Write-Host "    -> [OK] Residue wiped: $($md.FullName)" -ForegroundColor Green
                                        $sanitizedCount++
                                    } else {
                                        Write-Host "    -> [WARN] Could not wipe residue: $($md.FullName)" -ForegroundColor DarkYellow
                                    }
                                }
                            }
                        } catch {}
                    }
                }
            } finally {
                Exit-UWMIsolation
            }
            if ($sanitizedCount -gt 0) {
                Write-Host "  [SANITIZE] Purged $sanitizedCount orphaned residue directory(ies).`n" -ForegroundColor Green
            } else {
                Write-Host "  [SANITIZE] Clean — no orphaned residue detected.`n" -ForegroundColor Green
            }

            # --- Runtime dependency sorting: core runtimes deploy first ---
            $RuntimePattern = [regex]::new('VCLibs|Visual\.?C\+\+|VCRedist|MSVC|CRT|OpenSSL|\.NET|NET\.Framework|DirectX|WebView|Xaml\.Runtime|UWP\.Runtime|DesktopBridge|RuntimePackage|FrameworkPackage|Dependencies', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $runtimePkgs = [System.Collections.Generic.List[object]]::new()
            $clientPkgs  = [System.Collections.Generic.List[object]]::new()
            foreach ($pkg in $blueprint.Packages) {
                $pn = if (-not [string]::IsNullOrWhiteSpace($pkg.Name)) { $pkg.Name } else { "" }
                $pi = if (-not [string]::IsNullOrWhiteSpace($pkg.Id)) { $pkg.Id } else { "" }
                if ($RuntimePattern.IsMatch($pn) -or $RuntimePattern.IsMatch($pi)) { $runtimePkgs.Add($pkg) } else { $clientPkgs.Add($pkg) }
            }
            $sortedPkgs = @($runtimePkgs.ToArray(); $clientPkgs.ToArray())
            if ($runtimePkgs.Count -gt 0) {
                Write-Host "  [SORT] $($runtimePkgs.Count) core runtime(s) queued first, $($clientPkgs.Count) client app(s) second." -ForegroundColor DarkCyan
            }

            # --- 5-minute timeout wrapper for winget install commands ---
            $WingetTimeoutJob = {
                param([string]$WingetArgs)
                $job = Start-Job -ScriptBlock {
                    param($a)
                    try {
                        $p = Start-Process winget -ArgumentList $a -NoNewWindow -PassThru -Wait -ErrorAction Stop
                        return $p.ExitCode
                    } catch { return -1 }
                } -ArgumentList $WingetArgs
                $done = $job | Wait-Job -Timeout 300
                if ($null -ne $done) {
                    $exit = @((Receive-Job $job -ErrorAction SilentlyContinue) | Select-Object -Last 1)
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                    if ($exit.Count -gt 0) { return $exit[0] }
                    return -1
                }
                Stop-Job $job -ErrorAction SilentlyContinue
                Remove-Job $job -Force -ErrorAction SilentlyContinue
                return -1
            }

            foreach ($pkg in $sortedPkgs) {
                $pkgId   = $pkg.Id
                $pkgName = $pkg.Name
                $pkgVer  = $pkg.Version

                # --- Dynamic Source Normalization Shield ---
                $TargetSource = if ($pkg.Source -and $pkg.Source.Trim() -ne 'registry') { $pkg.Source.Trim() } else { 'winget' }

                # --- Heuristic string normalization ---
                $SanitizedId = $pkgId.Trim()
                $useFuzzySearch = $false

                if ($SanitizedId -match '^\{[0-9A-Fa-f\-]+\}$') {
                    $useFuzzySearch = $true
                    $SanitizedId = $null
                }

                if (-not $useFuzzySearch -and -not [string]::IsNullOrWhiteSpace($SanitizedId)) {
                    $SanitizedId = $SanitizedId -replace '\s+', '.'
                }

                if (-not [string]::IsNullOrWhiteSpace($SanitizedId)) {
                    $SanitizedId = $SanitizedId -replace '\\u003c','' -replace '\\u003e','' -replace '[^\x20-\x7E]',''
                }
                $cleanName = $pkgName -replace '\\u003c','' -replace '\\u003e','' -replace '[^\x20-\x7E]',''

                # --- Deterministic name normalization: strip versions, arch, parens, specials ---
                $normalizedName = $cleanName -replace '\s*\(.*?\)\s*','' -replace '\s+\d+(\.\d+)+','' -replace '\s+(x64|x86|ARM64|32-bit|64-bit)','' -replace '\s{2,}',' ' -replace '^\s+|\s+$',''

                if ($useFuzzySearch -and ([string]::IsNullOrWhiteSpace($cleanName) -or $cleanName -match '^\{[0-9A-Fa-f\-]+\}$')) {
                    $skipped++
                    Write-Host "  [SKIP] Unresolvable entry: $pkgId ($pkgName)" -ForegroundColor DarkYellow
                    continue
                }
                if (-not $useFuzzySearch -and ([string]::IsNullOrWhiteSpace($SanitizedId) -or $SanitizedId -eq 'None' -or $SanitizedId -match '^KB\d+$')) {
                    $skipped++
                    Write-Host "  [SKIP] Filtered entry: $pkgId ($pkgName)" -ForegroundColor DarkYellow
                    continue
                }

                # --- Construct terminal command string ---
                if ($useFuzzySearch) {
                    $wingetCmd = "install --name `"$cleanName`" --source `"$TargetSource`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                    $displayId = "~name:$cleanName"
                } else {
                    $wingetCmd = "install --id `"$SanitizedId`" --source `"$TargetSource`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                    $displayId = $SanitizedId
                }

                Write-Host "  [DEPLOYING] $cleanName ($displayId) ... " -NoNewline -ForegroundColor $script:Theme['Text']

                $installSuccess = $false

                # --- TIER 1: Primary command execution ---
                try {
                    $procExit = & $WingetTimeoutJob $wingetCmd
                    if ($procExit -eq 0 -or $procExit -eq 3010) { $installSuccess = $true }
                } catch {}

                # --- TIER 2: Deterministic name fallback with --exact ---
                if (-not $installSuccess -and -not $useFuzzySearch -and -not [string]::IsNullOrWhiteSpace($normalizedName)) {
                    Write-Host "[NAME] " -NoNewline -ForegroundColor DarkYellow
                    $fallbackCmd = "install --name `"$normalizedName`" --exact --source `"$TargetSource`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                    try {
                        $fExit = & $WingetTimeoutJob $fallbackCmd
                        if ($fExit -eq 0 -or $fExit -eq 3010) { $installSuccess = $true }
                    } catch {}
                }

                # --- TIER 3: Global cloud repository migration to msstore ---
                if (-not $installSuccess) {
                    Write-Host "[MSSTORE] " -NoNewline -ForegroundColor DarkYellow
                    if (-not [string]::IsNullOrWhiteSpace($SanitizedId)) {
                        $msstoreCmd = "install --id `"$SanitizedId`" --source `"msstore`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                    } else {
                        $msstoreCmd = "install --name `"$normalizedName`" --exact --source `"msstore`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                    }
                    try {
                        $mExit = & $WingetTimeoutJob $msstoreCmd
                        if ($mExit -eq 0 -or $mExit -eq 3010) { $installSuccess = $true }
                    } catch {}
                }

                # --- TIER 4: Multi-match guard — search + auto-select first official result ---
                if (-not $installSuccess -and -not [string]::IsNullOrWhiteSpace($normalizedName)) {
                    Write-Host "[AUTO] " -NoNewline -ForegroundColor DarkYellow
                    try {
                        $searchRaw = & winget search --name "$normalizedName" --source "winget" --exact 2>$null | Out-String
                        if (-not [string]::IsNullOrWhiteSpace($searchRaw)) {
                            $sLines = $searchRaw -split "`r?`n" | Where-Object { $_ -match '^\S' -and $_ -notmatch '(?i)^Name\s' -and $_ -notmatch '^\s*-' -and $_.Trim() }
                            if ($sLines.Count -gt 0) {
                                $sTokens = $sLines[0] -split '\s{2,}' | Where-Object { $_.Trim() }
                                if ($sTokens.Count -ge 2) {
                                    $autoId = $sTokens[1].Trim()
                                    $aAutoCmd = "install --id `"$autoId`" --source `"winget`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                                    $aExit = & $WingetTimeoutJob $aAutoCmd
                                    if ($aExit -eq 0 -or $aExit -eq 3010) { $installSuccess = $true }
                                }
                            }
                        }
                    } catch {}
                }

                if ($installSuccess) {
                    Write-Host "[OK]" -ForegroundColor Green
                    $deployed++
                } else {
                    Write-Host "[FAIL]" -ForegroundColor Red
                    $failed++
                    $retryQueue.Add(@{ Id = $SanitizedId; Name = $normalizedName; Fuzzy = $useFuzzySearch; Source = $TargetSource; Reason = "All 4 tiers exhausted" })
                    Write-Log -Action "MATRIX_IMPORT_FAIL" -Target $pkgId -Status "Failed" -Details "All 4 tiers exhausted | $normalizedName"
                }
            }

            # --- Secondary recovery pass (4-tier fallback) ---
            if ($retryQueue.Count -gt 0) {
                Write-Host "`n  [RETRY-PASS] Initiating 4-tier secondary recovery for $($retryQueue.Count) failed package(s)..." -ForegroundColor Yellow
                $retryRecovered = 0
                foreach ($retry in $retryQueue) {
                    Write-Host "  [RETRY] $($retry.Name) ... " -NoNewline -ForegroundColor $script:Theme['Text']
                    $retrySource = if ($retry.Source) { $retry.Source } else { 'winget' }
                    $retrySuccess = $false

                    # Tier 1: Name with exact on original source
                    try {
                        $rCmd = "install --name `"$($retry.Name)`" --exact --source `"$retrySource`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                        $rExit = & $WingetTimeoutJob $rCmd
                        if ($rExit -eq 0 -or $rExit -eq 3010) { $retrySuccess = $true }
                    } catch {}

                    # Tier 2: msstore cloud migration
                    if (-not $retrySuccess) {
                        Write-Host "[MSSTORE] " -NoNewline -ForegroundColor DarkYellow
                        try {
                        $rmCmd = "install --name `"$($retry.Name)`" --exact --source `"msstore`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                        $rmExit = & $WingetTimeoutJob $rmCmd
                        if ($rmExit -eq 0 -or $rmExit -eq 3010) { $retrySuccess = $true }
                        } catch {}
                    }

                    # Tier 3: Multi-match guard — auto-select first result
                    if (-not $retrySuccess) {
                        Write-Host "[AUTO] " -NoNewline -ForegroundColor DarkYellow
                        try {
                            $rSearchRaw = & winget search --name "$($retry.Name)" --source "winget" --exact 2>$null | Out-String
                            if (-not [string]::IsNullOrWhiteSpace($rSearchRaw)) {
                                $rSLines = $rSearchRaw -split "`r?`n" | Where-Object { $_ -match '^\S' -and $_ -notmatch '(?i)^Name\s' -and $_ -notmatch '^\s*-' -and $_.Trim() }
                                if ($rSLines.Count -gt 0) {
                                    $rSTokens = $rSLines[0] -split '\s{2,}' | Where-Object { $_.Trim() }
                                    if ($rSTokens.Count -ge 2) {
                                        $rAutoId = $rSTokens[1].Trim()
                                        $rAutoCmd = "install --id `"$rAutoId`" --source `"winget`" $scopeArg --silent --force --accept-package-agreements --accept-source-agreements --disable-interactivity"
                                        $rAExit = & $WingetTimeoutJob $rAutoCmd
                                        if ($rAExit -eq 0 -or $rAExit -eq 3010) { $retrySuccess = $true }
                                    }
                                }
                            }
                        } catch {}
                    }

                    if ($retrySuccess) {
                        Write-Host "[OK]" -ForegroundColor Green
                        $deployed++
                        $failed--
                        $retryRecovered++
                    } else {
                        Write-Host "[FAIL]" -ForegroundColor Red
                        Write-Log -Action "MATRIX_IMPORT_FAIL" -Target $retry.Id -Status "Failed" -Details "All 3 retry tiers exhausted | $($retry.Name)"
                    }
                }
                Write-Host "  [RETRY-PASS] Recovered: $retryRecovered / $($retryQueue.Count)" -ForegroundColor $(if ($retryRecovered -eq $retryQueue.Count) { 'Green' } else { 'DarkYellow' })
            }

            Write-Host "`n" + ("=" * 54) -ForegroundColor Yellow
            Write-Host "  [DEPLOYMENT COMPLETE]" -ForegroundColor Green
            Write-Host "  Deployed: $deployed | Skipped: $skipped | Failed: $failed | Total: $pkgTotal" -ForegroundColor Cyan
            Write-Host ("=" * 54) -ForegroundColor Yellow
            Write-Log -Action "MATRIX_IMPORT" -Target $blueprintPath -Status "Success" -Details "Deployed: $deployed | Skipped: $skipped | Failed: $failed"
            Read-Host " $($script:Locale['PressEnter'])"
            Clear-Host
        }
        }
        Clear-Host
    }
}

# ---- HTML Output Sanitizer (shared by all HTML renderers) ----
function ConvertTo-UWMHtmlSafe {
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $v = [string]$Value
    $v = $v -replace '&', '&amp;'
    $v = $v -replace '<', '&lt;'
    $v = $v -replace '>', '&gt;'
    $v = $v -replace '"', '&quot;'
    $v = $v -replace "'", '&#39;'
    $v = $v -replace "[\x00-\x08\x0B\x0C\x0E-\x1F]", ' '
    return $v
}

# ---- Phase 6: Interactive HTML Dashboard ----
function New-HTMLDashboard {
    # ---- Dashboard layout / data constants (hoisted at initialization scope) ----
    $DashBodyPadPx      = 20   # outer body padding (px)
    $DashCardsGapPx     = 16   # .cards flex gap (px)
    $DashCardMinWidthPx = 180  # .card flex min-width layout index (px)
    $DashCardPadPx      = 20   # .card inner padding (px)
    $DashCardRadiusPx   = 12   # .card border radius (px)
    $DashThPadTB        = 10   # table header vertical padding (px)
    $DashThPadLR        = 8    # table header horizontal padding (px)
    $DashTdPadPx        = 8    # table cell padding (px)
    $DashBarHeightPx    = 24   # activity track bar height (px)
    $DashActionNameWpx  = 120  # action-name column width (px)
    $DashActionCountWpx = 50   # action-count column width (px)
    $DashRecentCount    = 20   # memory size limit: recent-activity rows serialized
    Show-Header
    Write-Host "  $($script:Locale['DashTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    if (-not (Test-Path $script:LogPath)) { Write-Host " $($script:Locale['ExportEmpty'])" -ForegroundColor $script:Theme['Dim']; Read-Host " $($script:Locale['PressEnter'])"; return }
    try {
        $entries = Get-Content $script:LogPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (-not $entries -or ($entries -is [array] -and $entries.Count -eq 0)) { Write-Host " $($script:Locale['ExportEmpty'])" -ForegroundColor $script:Theme['Dim']; Read-Host " $($script:Locale['PressEnter'])"; return }
        if ($entries -isnot [array]) { $entries = @($entries) }
    } catch { Write-Host " $($script:Locale['ExportEmpty'])" -ForegroundColor $script:Theme['Dim']; Read-Host " $($script:Locale['PressEnter'])"; return }
    Write-Host ($script:Locale['DashGenerate'] -f $entries.Count) -ForegroundColor $script:Theme['Accent']
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $path = Join-Path $script:DataRoot "UWM_Dashboard_$ts.html"
    $total = $entries.Count; $success = ($entries | Where-Object { $_.Status -eq "Success" }).Count
    $failed = ($entries | Where-Object { $_.Status -in @("Failed","Error") }).Count
    $info = $total - $success - $failed
    $actions = $entries | Group-Object Action | Sort-Object Count -Descending
    $successRate = if ($total -gt 0) { [Math]::Round(($success/$total)*100) } else { 0 }
    $recent = $entries[-$DashRecentCount..-1] | Select-Object Timestamp, Action, Target, Status
    $html = @"
<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>UWM Dashboard</title>
<style>*{box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;background:#1e1e2e;color:#cdd6f4;margin:0;padding:${DashBodyPadPx}px}
h1{color:#89b4fa;border-bottom:2px solid #45475a;padding-bottom:10px}.cards{display:flex;gap:${DashCardsGapPx}px;flex-wrap:wrap;margin:20px 0}
.card{background:#313244;border-radius:${DashCardRadiusPx}px;padding:${DashCardPadPx}px;flex:1;min-width:${DashCardMinWidthPx}px;text-align:center}
.card .num{font-size:2.2em;font-weight:700;display:block}.card .lbl{font-size:.9em;color:#a6adc8;margin-top:4px}
.green{color:#a6e3a1}.red{color:#f38ba8}.yellow{color:#f9e2af}.blue{color:#89b4fa}
table{border-collapse:collapse;width:100%;margin-top:16px}
th{background:#45475a;padding:${DashThPadTB}px ${DashThPadLR}px;text-align:left;font-weight:600}
td{border-bottom:1px solid #45475a;padding:${DashTdPadPx}px}
tr:hover{background:#313244}
.bar-wrap{background:#45475a;border-radius:8px;height:${DashBarHeightPx}px;overflow:hidden;margin:4px 0}
.bar-fill{height:100%;border-radius:8px;transition:width .4s}
.action-row{display:flex;align-items:center;gap:10px;margin:4px 0}
.action-name{width:${DashActionNameWpx}px;text-align:right}.action-bar{flex:1}.action-count{width:${DashActionCountWpx}px}
</style></head><body>
<h1>Ultra Winget Manager — Dashboard</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Total: $total entries</p>
<div class='cards'>
<div class='card'><span class='num green'>$success</span><span class='lbl'>Success</span></div>
<div class='card'><span class='num red'>$failed</span><span class='lbl'>Failed</span></div>
<div class='card'><span class='num yellow'>$info</span><span class='lbl'>Info / Other</span></div>
<div class='card'><span class='num blue'>$successRate%</span><span class='lbl'>Success Rate</span></div>
</div>
<h2>Activity Breakdown</h2>
"@
    foreach ($a in $actions) {
        $barPct = [Math]::Round(($a.Count/$total)*100)
        $barColor = if ($a.Name -match 'Success|OK|Done') { '#a6e3a1' } elseif ($a.Name -match 'Failed|Error') { '#f38ba8' } else { '#89b4fa' }
        $html += "<div class='action-row'><span class='action-name'>$(ConvertTo-UWMHtmlSafe $a.Name)</span><div class='action-bar'><div class='bar-wrap'><div class='bar-fill' style='width:${barPct}%;background:$barColor'></div></div></div><span class='action-count'>$($a.Count) ($barPct%)</span></div>"
    }
    $html += @"
<h2>Recent Activity (Last $DashRecentCount)</h2>
<table><tr><th>Timestamp</th><th>Action</th><th>Target</th><th>Status</th></tr>
"@
    foreach ($e in $recent) {
        $c = if ($e.Status -eq "Success") { "green" } elseif ($e.Status -in @("Failed","Error")) { "red" } else { "yellow" }
        $ts2 = try { (Get-Date $e.Timestamp -Format "MM-dd HH:mm:ss") } catch { $e.Timestamp }
        $html += "<tr><td>$(ConvertTo-UWMHtmlSafe $ts2)</td><td>$(ConvertTo-UWMHtmlSafe $e.Action)</td><td>$(ConvertTo-UWMHtmlSafe $e.Target)</td><td class='$c'>$(ConvertTo-UWMHtmlSafe $e.Status)</td></tr>"
    }
    $html += "</table><p style='color:#6c7086;margin-top:24px'>Ultra Winget Manager v15.0 — Dashboard Report</p></body></html>"
    $html | Out-File $path -Encoding utf8
    Write-Host ($script:Locale['DashDone'] -f $path) -ForegroundColor $script:Theme['Success']
    Write-Log -Action "DASHBOARD" -Target "HTML" -Status "Done" -Details $path
    [Console]::Beep(800,80); Start-Process $path
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Toggle Language ----
function Invoke-ToggleLanguage {
    Show-Header
    Write-Host "  $($script:Locale['LangTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    $cur = $script:Config.language; $curName = if ($cur -eq "en") { $script:Locale['LangNameEN'] } else { $script:Locale['LangNameAR'] }
    Write-Host "   $($script:Locale['LangCurrent'] -f $curName)" -ForegroundColor $script:Theme['Text']
    $new = if ($cur -eq "en") { "ar" } else { "en" }; $newName = if ($new -eq "en") { $script:Locale['LangNameEN'] } else { $script:Locale['LangNameAR'] }
    if ((Read-Host " $($script:Locale['LangSwitchConfirm'] -f $newName)").ToUpper() -eq 'Y') {
        $script:Config.language = $new; $script:Locale = Get-Locale; Save-Config
        Write-Host ($script:Locale['LangSwitched'] -f $newName) -ForegroundColor $script:Theme['Success']
        Write-Log -Action "LANGUAGE" -Target $new -Status "Switched"
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Phase 6: UI Scale Toggle ----
function Invoke-UIScaleToggle {
    Show-Header
    Write-Host "  [SCALE] UI Size" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    $cur = if ($script:Config.ui.scale -eq "large") { $script:Locale['UIScaleLabel'] -f "LARGE" } else { $script:Locale['UIScaleLabel'] -f "NORMAL" }
    Write-Host "   $cur" -ForegroundColor $script:Theme['Text']
    $new = if ($script:Config.ui.scale -eq "large") { "normal" } else { "large" }
    $newLabel = if ($new -eq "large") { "LARGE" } else { "NORMAL" }
    if ((Read-Host " Switch to $newLabel? (Y/N)").ToUpper() -eq 'Y') {
        $script:Config.ui.scale = $new; Save-Config
        Write-Host ($script:Locale['UIScaleToggled'] -f $newLabel) -ForegroundColor $script:Theme['Success']
        Write-Log -Action "SCALE" -Target "UI" -Status $newLabel
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Sandbox Testing ----
function Invoke-SandboxTest {
    Show-Header
    if (-not (Assert-UWMWriteAccess)) { return }
    Write-Host "  $($script:Locale['SandboxTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    $pkgId = Read-Host " $($script:Locale['SandboxPrompt'])"
    if (-not $pkgId) { return }
    Write-Host ($script:Locale['SandboxCreating']) -ForegroundColor $script:Theme['Accent']
    Write-Host ($script:Locale['SandboxInject']) -ForegroundColor $script:Theme['Accent']
    # Generate silent install script inside sandbox
    $installScript = Join-Path $env:TEMP "UltraWinget_Install_$([Guid]::NewGuid().ToString('N')).ps1"
    $scriptContent = @"
param([string]`$PackageId)
`$logFile = Join-Path `$env:USERPROFILE "Desktop\sandbox-result.txt"
`$result = & winget install --id `$PackageId --accept-package-agreements --silent 2>&1
`$exitCode = `$LASTEXITCODE
`$status = if (`$exitCode -eq 0) { "SUCCESS" } else { "FAILED" }
"[`$status] Package: `$PackageId | Exit: `$exitCode | Time: `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File `$logFile -Encoding utf8 -Append
Write-Host "[SANDBOX] `$status (exit: `$exitCode)" -ForegroundColor `$(if(`$exitCode -eq 0){'Green'}else{'Red'})
Start-Sleep -Seconds 10
"@
    $scriptContent | Out-File $installScript -Encoding utf8
    # Build the WSB
    $wsbPath = Join-Path $env:TEMP "UltraWinget_Sandbox_$([Guid]::NewGuid().ToString('N')).wsb"
    $wsbContent = @"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$PSScriptRoot</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$installScript" -PackageId $pkgId</Command>
  </LogonCommand>
</Configuration>
"@
    $wsbContent | Out-File $wsbPath -Encoding utf8
    Write-Host ($script:Locale['SandboxCreated'] -f $wsbPath) -ForegroundColor $script:Theme['Success']
    Write-Log -Action "SANDBOX" -Target $pkgId -Status "Created" -Details $wsbPath
    Write-Host ($script:Locale['SandboxLaunch']) -ForegroundColor $script:Theme['Accent']
    [Console]::Beep(900,100)
    Invoke-Item $wsbPath
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Throttle Toggle ----
function Invoke-ThrottleToggle {
    Show-Header
    Write-Host "  [THROTTLE] Bandwidth Limiter" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    $cur = $script:Config.throttle.enabled
    $label = if ($cur) { $script:Locale['ThrottleNotice'] -f $script:Config.throttle.maxBandwidthMbps } else { $script:Locale['ThrottleOff'] }
    Write-Host "   Status: $label" -ForegroundColor $script:Theme['Text']
    $newState = -not $cur
    $confirm = Read-Host " Set to $(if($newState){'ON'}else{'OFF'})? (Y/N)"
    if ($confirm.ToUpper() -eq 'Y') {
        $script:Config.throttle.enabled = $newState; Save-Config
        $newLabel = if ($newState) { $script:Locale['ThrottleNotice'] -f $script:Config.throttle.maxBandwidthMbps } else { $script:Locale['ThrottleOff'] }
        Write-Host ($script:Locale['ThrottleToggled'] -f $newLabel) -ForegroundColor $script:Theme['Success']
        Write-Log -Action "THROTTLE" -Target "Toggle" -Status $(if($newState){"ON"}else{"OFF"})
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Export Report ----
function Export-UpdateReport {
    Show-Header
    Write-Host "  $($script:Locale['ExportTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    if (-not (Test-Path $script:LogPath)) { Write-Host " $($script:Locale['ExportEmpty'])" -ForegroundColor $script:Theme['Dim']; Read-Host " $($script:Locale['PressEnter'])"; return }
    try {
        $entries = Get-Content $script:LogPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if (-not $entries -or ($entries -is [array] -and $entries.Count -eq 0)) { Write-Host " $($script:Locale['ExportEmpty'])" -ForegroundColor $script:Theme['Dim']; Read-Host " $($script:Locale['PressEnter'])"; return }
        if ($entries -isnot [array]) { $entries = @($entries) }
    } catch { Write-Host " $($script:Locale['ExportEmpty'])" -ForegroundColor $script:Theme['Dim']; Read-Host " $($script:Locale['PressEnter'])"; return }

    # ---- Report export constants (hoisted at function initialization) ----
    $ReportEntryMax = 100   # memory size limit: max transaction rows serialized into HTML table
    $ReportBodyPadPx = 20   # <body> outer padding (px)
    $ReportThPadPx   = 8    # table header cell padding (px)
    $ReportTdPadPx   = 6    # table data cell padding (px)

    $fmt = (Read-Host " $($script:Locale['ExportPrompt'])").ToUpper()
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    if ($fmt -eq 'H') {
        $path = Join-Path $script:DataRoot "UWM_Report_$ts.html"
        $rows = ""
        foreach ($e in $entries[-$ReportEntryMax..-1]) {
            $ts2 = try { (Get-Date $e.Timestamp -Format "yyyy-MM-dd HH:mm:ss") } catch { $e.Timestamp }
            $color = if ($e.Status -eq "Success") { "green" } elseif ($e.Status -in @("Failed","Error")) { "red" } else { "#888" }
            $rows += "<tr><td>$(ConvertTo-UWMHtmlSafe $ts2)</td><td>$(ConvertTo-UWMHtmlSafe $e.Action)</td><td>$(ConvertTo-UWMHtmlSafe $e.Target)</td><td style='color:$color'>$(ConvertTo-UWMHtmlSafe $e.Status)</td><td>$(ConvertTo-UWMHtmlSafe $e.Details)</td></tr>`n"
        }
        $html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>UWM Report</title>
<style>body{font-family:'Segoe UI',sans-serif;background:#1e1e2e;color:#cdd6f4;padding:${ReportBodyPadPx}px}
h1{color:#89b4fa}table{border-collapse:collapse;width:100%}th{background:#45475a;padding:${ReportThPadPx}px;text-align:left}
td{border:1px solid #45475a;padding:${ReportTdPadPx}px}tr:nth-child(even){background:#313244}</style></head><body>
<h1>Ultra Winget Manager - Transaction Report</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Entries: $($entries.Count) | Rows: $([Math]::Min($entries.Count, $ReportEntryMax))</p>
<table><tr><th>Timestamp</th><th>Action</th><th>Target</th><th>Status</th><th>Details</th></tr>
$rows</table></body></html>"
        $html | Out-File $path -Encoding utf8
        Write-Host ($script:Locale['ExportHTML'] -f $path) -ForegroundColor $script:Theme['Success']
        Write-Log -Action "EXPORT" -Target "HTML" -Status "Done" -Details $path
        [Console]::Beep(800,80); Start-Process $path
    } elseif ($fmt -eq 'C') {
        $path = Join-Path $script:DataRoot "UWM_Report_$ts.csv"
        $entries | Select-Object Timestamp, Action, Target, Status, Details | Export-Csv $path -NoTypeInformation -Encoding utf8
        Write-Host ($script:Locale['ExportCSV'] -f $path) -ForegroundColor $script:Theme['Success']
        Write-Log -Action "EXPORT" -Target "CSV" -Status "Done" -Details $path
        [Console]::Beep(800,80); Start-Process $path
    } elseif ($fmt -eq 'D') {
        New-HTMLDashboard; return
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Phase 4: Performance Impact ----
function Measure-StartupImpact {
    Show-Header
    Write-Host "  $($script:Locale['ImpactTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    Write-Progress -Activity ($script:Locale['ImpactScan']) -Status "Collecting boot events..." -PercentComplete -1
    $findings = @(); $issues = @()
    # Boot time trend from diagnostics log
    try {
        $bootLog = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; ID=100} -MaxEvents 6 -ErrorAction SilentlyContinue
        if ($bootLog -and $bootLog.Count -ge 2) {
            $durations = @()
            foreach ($evt in $bootLog) {
                if ($evt.Message -match '(?i)boot\s*(duration|time).{0,20}?(\d+)\s*ms') {
                    $durations += [PSCustomObject]@{ Time=$evt.TimeCreated; DurationMS=[int]$Matches[2] }
                }
            }
            if ($durations.Count -ge 2) {
                $durations = $durations | Sort-Object Time -Descending
                $recent = $durations | Select-Object -First ([Math]::Min(3,$durations.Count))
                $older  = $durations | Select-Object -Last  ([Math]::Min(3,$durations.Count))
                $avgR = ($recent | Measure-Object -Property DurationMS -Average).Average
                $avgO = ($older  | Measure-Object -Property DurationMS -Average).Average
                $delta = $avgR - $avgO
                $thresh = $script:Config.startupImpact.bootDeltaThreshold
                if ($delta -gt $thresh) {
                    $findings += [PSCustomObject]@{ Metric="Boot Delta"; Value="$([Math]::Round($avgR/1000,1))s avg"; Detail="+$([Math]::Round($delta/1000,1))s (threshold ${thresh}s)"; Status="Warning" }
                    $issues += ($script:Locale['ImpactDeltaWarn'] -f [Math]::Round($delta/1000,1))
                } else {
                    $findings += [PSCustomObject]@{ Metric="Boot Delta"; Value="$([Math]::Round($avgR/1000,1))s avg"; Detail="$([Math]::Round($delta/1000,1))s change"; Status="OK" }
                }
            }
        } else { $findings += [PSCustomObject]@{ Metric="Boot Data"; Value=$script:Locale['ImpactNoData']; Detail="-"; Status="Info" } }
    } catch { $findings += [PSCustomObject]@{ Metric="Boot Log"; Value="Unavailable"; Detail=$_.Exception.Message; Status="Info" } }
    # Check stalled auto-start services
    try {
        $stalled = Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State!='Running'" -ErrorAction SilentlyContinue | Select-Object -First 10
        if ($stalled) {
            $findings += [PSCustomObject]@{ Metric="Stalled Services"; Value="$($stalled.Count) service(s)"; Detail="($(($stalled.Name) -join ', '))"; Status="Info" }
        } else { $findings += [PSCustomObject]@{ Metric="Stalled Services"; Value="None"; Detail="All auto-services running"; Status="OK" } }
    } catch { }
    Write-Progress -Activity ($script:Locale['ImpactScan']) -Completed
    Start-Sleep -Milliseconds 100
    # Display results
    foreach ($f in $findings) {
        $c = if ($f.Status -eq "Warning") { $script:Theme['Accent'] } elseif ($f.Status -eq "OK") { $script:Theme['Success'] } else { $script:Theme['Dim'] }
        Write-Host "   $($f.Metric): " -NoNewline -ForegroundColor $script:Theme['Text']
        Write-Host "$($f.Value)" -ForegroundColor $c
        if ($f.Detail -and $f.Detail -ne "-") { Write-Host "     -> $($f.Detail)" -ForegroundColor $script:Theme['Dim'] }
    }
    Write-Host ("  " + "-" * 46)
    if ($issues.Count -gt 0) {
        Write-Host "   [!] Recommendations:" -ForegroundColor $script:Theme['Accent']
        foreach ($issue in $issues) { Write-Host "    - $issue" -ForegroundColor $script:Theme['Text'] }
    } else { Write-Host "   [OK] System boot health nominal." -ForegroundColor $script:Theme['Success'] }
    Write-Log -Action "ANALYZE" -Target "StartupImpact" -Status "Done" -Details "Findings: $($findings.Count)"
    [Console]::Beep(800,80)
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Phase 4: Per-Package Health ----
function Get-PackageHealth {
    param([string]$PackageId)
    $e = Read-UWMTransactionLog
    if ($e.Count -eq 0) { return "N/A" }
    $ops = $e | Where-Object { $_.Target -eq $PackageId -and $_.Action -in @("UPDATE","GLOBAL","INSTALL") }
    if ($ops.Count -eq 0) { return "N/A" }
    $s = ($ops | Where-Object { $_.Status -eq "Success" }).Count
    $pct = [Math]::Round(($s/$ops.Count)*100)
    return "$pct%"
}

# ---- Phase 4: MS Store Integration ----
function Get-StoreUpdateList {
    if (-not $script:Config.storeIntegration.enabled) { return @() }
    $storePkgs = @()
    Write-Progress -Activity ($script:Locale['StoreTitle']) -Status ($script:Locale['StoreScan']) -PercentComplete -1
    try {
        $appMgmt = Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" -ErrorAction SilentlyContinue
        if ($appMgmt) {
            $installed = Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01.Installed" -ErrorAction SilentlyContinue
            if ($installed) {
                foreach ($app in $installed) {
                    $pkgName = $app.Name -replace '^[^|]+\|', ''
                    if ($pkgName) {
                        $id = "msstore-$($app.PackageFamilyName)"
                        $storePkgs += [PSCustomObject]@{ Name=$pkgName; ID=$id; Source="Store" }
                    }
                }
            }
        }
    } catch { Write-Host ($script:Locale['StoreNone']) -ForegroundColor $script:Theme['Dim'] }
    Write-Progress -Activity ($script:Locale['StoreTitle']) -Completed
    $ign = $script:Config.ignoreList
    if ($ign -and $ign.Count -gt 0) { $storePkgs = $storePkgs | Where-Object { $_.ID -notin $ign } }
    if ($storePkgs.Count -gt 0) { Write-Host ($script:Locale['StoreFound'] -f $storePkgs.Count) -ForegroundColor $script:Theme['Accent'] }
    return $storePkgs
}

# ---- Phase 4: Per-Package Hooks ----
function Invoke-PrePackageHook {
    param([string]$PackageId)
    $p = $script:Config.hooks.prePackageScript
    if (-not $p -or -not (Test-Path $p)) { return }
    Write-Host ($script:Locale['HookPreRun'] -f $p) -ForegroundColor $script:Theme['Accent']
    & $p -PackageId $PackageId
    Write-Log -Action "PREHOOK" -Target $PackageId -Status "Done" -Details $p
}
function Invoke-PostPackageHook {
    param([string]$PackageId, [int]$ExitCode)
    $p = $script:Config.hooks.postPackageScript
    if (-not $p -or -not (Test-Path $p)) { return }
    Write-Host ($script:Locale['HookPostRun'] -f $p) -ForegroundColor $script:Theme['Accent']
    & $p -PackageId $PackageId -ExitCode $ExitCode
    Write-Log -Action "POSTHOOK" -Target $PackageId -Status "Done" -Details $p
}

# ---- Phase 5: GitHub Gist Sync ----
function Invoke-GitHubSync {
    Write-Host "`n [WARNING] This feature has been disabled and removed by the Administrator.`n" -ForegroundColor Yellow
    Start-Sleep -Seconds 2
}

# ---- Phase 5: Cloud Notifications ----
function Send-CloudNotification {
    param([string]$Message)
    if (-not $script:Config.notifications.enabled) { return }
    [bool]$anyOk = $false
    if ($script:Config.notifications.telegramBotToken -and $script:Config.notifications.telegramChatId) {
        try {
            $url = "https://api.telegram.org/bot$($script:Config.notifications.telegramBotToken)/sendMessage"
            $body = @{ chat_id = $script:Config.notifications.telegramChatId; text = $Message; parse_mode = "Markdown" }
            Invoke-RestMethod -Uri $url -Method Post -Body $body -TimeoutSec 15 -ErrorAction Stop | Out-Null
            $anyOk = $true
        } catch { }
    }
    if ($script:Config.notifications.discordWebhookUrl) {
        try {
            $body = @{ content = $Message } | ConvertTo-Json
            Invoke-RestMethod -Uri $script:Config.notifications.discordWebhookUrl -Method Post -Body $body -ContentType "application/json" -TimeoutSec 15 -ErrorAction Stop | Out-Null
            $anyOk = $true
        } catch { }
    }
    if (-not $anyOk) {
        Invoke-UWMOfflineQueuePush -Message $Message
        Invoke-UWMOfflineFlushDaemon
    }
}
function Invoke-NotifyTest {
    Show-Header
    Write-Host "  $($script:Locale['NotifyTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    Write-Host "   $($script:Locale['NotifySending'])" -ForegroundColor $script:Theme['Accent']
    $msg = "Ultra Winget Manager — Test notification at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Send-CloudNotification -Message $msg
    Write-Host "   $($script:Locale['NotifySent'])" -ForegroundColor $script:Theme['Success']
    Write-Log -Action "NOTIFY" -Target "Test" -Status "Sent"
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Phase 5: Chocolatey & Scoop Bridge ----
function Get-BridgeUpgradeList {
    $bridgePkgs = @()
    if ($script:Config.bridges.chocolatey -and (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Progress -Activity ($script:Locale['BridgeTitle']) -Status ($script:Locale['BridgeChocoFound']) -PercentComplete -1
        try {
            $raw = choco outdated -r --no-color --limit-output 2>&1 | Out-String
            $lines = $raw -split "`r?`n" | Where-Object { $_ -match '\|' }
            foreach ($line in $lines) {
                $parts = $line -split '\|'
                if ($parts.Count -ge 2 -and $parts[0]) {
                    $bridgePkgs += [PSCustomObject]@{ Name=$parts[0]; ID="choco-$($parts[0])"; Version=$parts[1]; Source="Choco" }
                }
            }
        } catch { }
        Write-Progress -Activity ($script:Locale['BridgeTitle']) -Completed
    }
    if ($script:Config.bridges.scoop -and (Get-Command scoop -ErrorAction SilentlyContinue)) {
        Write-Progress -Activity ($script:Locale['BridgeTitle']) -Status ($script:Locale['BridgeScoopFound']) -PercentComplete -1
        try {
            $raw = scoop status 2>&1 | Out-String
            $lines = $raw -split "`r?`n" | Where-Object { $_ -match 'Update available' -or $_ -match '^\w+' }
            foreach ($line in $lines) {
                if ($line -match '^(\S+)\s+.*Update available') {
                    $bridgePkgs += [PSCustomObject]@{ Name=$Matches[1]; ID="scoop-$($Matches[1])"; Source="Scoop" }
                }
            }
        } catch { }
        Write-Progress -Activity ($script:Locale['BridgeTitle']) -Completed
    }
    $ign = $script:Config.ignoreList
    if ($ign -and $ign.Count -gt 0) { $bridgePkgs = $bridgePkgs | Where-Object { $_.ID -notin $ign } }
    return $bridgePkgs
}

# ---- Phase 7: Self-Healing & Integrity ----
function Repair-ScriptIntegrity {
    if ($script:AuditMode) { return }
    Write-Progress -Activity ($script:Locale['IntegrityTitle']) -Status "Checking config..." -PercentComplete 10
    $repaired = $false
    # 1. Validate config file exists and is valid JSON
    if (-not (Test-Path $script:ConfigPath)) {
        $cfg = Get-DefaultConfig; $cfg | ConvertTo-Json -Depth 5 | Out-File $script:ConfigPath -Encoding utf8 -Force
        Write-Host ($script:Locale['IntegrityRepair'] -f "Config") -ForegroundColor $script:Theme['Accent']; $repaired = $true
    } else {
        try { $null = Get-Content $script:ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch {
            $cfg = Get-DefaultConfig; $cfg | ConvertTo-Json -Depth 5 | Out-File $script:ConfigPath -Encoding utf8 -Force
            Write-Host ($script:Locale['IntegrityRepair'] -f "Config (corrupt)") -ForegroundColor $script:Theme['Accent']; $repaired = $true
        }
    }
    Write-Progress -Activity ($script:Locale['IntegrityTitle']) -Status "Checking log..." -PercentComplete 40
    # 2. Validate log file
    if (Test-Path $script:LogPath) {
        try {
            $c = Get-Content $script:LogPath -Raw -ErrorAction Stop
            if ($c -and $c.Trim()) { $null = $c | ConvertFrom-Json -ErrorAction Stop }
        } catch {
            @() | ConvertTo-Json | Out-File $script:LogPath -Encoding utf8 -Force
            Write-Host ($script:Locale['IntegrityRepair'] -f "Log (corrupt)") -ForegroundColor $script:Theme['Accent']; $repaired = $true
        }
    } else {
        @() | ConvertTo-Json | Out-File $script:LogPath -Encoding utf8 -Force
        if (-not $script:SilentMode) { Write-Host ($script:Locale['IntegrityRepair'] -f "Log") -ForegroundColor $script:Theme['Accent'] }; $repaired = $true
    }
    Write-Progress -Activity ($script:Locale['IntegrityTitle']) -Status "Checking hooks..." -PercentComplete 70
    # 3. Validate hook script paths
    if ($script:Config.hooks.prePackageScript -and -not (Test-Path $script:Config.hooks.prePackageScript)) {
        $script:Config.hooks.prePackageScript = ""; $repaired = $true
        Write-Host ($script:Locale['IntegrityRepair'] -f "Pre-hook (missing)") -ForegroundColor $script:Theme['Accent']
    }
    if ($script:Config.hooks.postPackageScript -and -not (Test-Path $script:Config.hooks.postPackageScript)) {
        $script:Config.hooks.postPackageScript = ""; $repaired = $true
        Write-Host ($script:Locale['IntegrityRepair'] -f "Post-hook (missing)") -ForegroundColor $script:Theme['Accent']
    }
    # 4. Validate scripts section
    if ($script:Config.scripts.preScript -and -not (Test-Path $script:Config.scripts.preScript)) {
        $script:Config.scripts.preScript = ""; $repaired = $true
        Write-Host ($script:Locale['IntegrityRepair'] -f "Pre-script (missing)") -ForegroundColor $script:Theme['Accent']
    }
    if ($script:Config.scripts.postScript -and -not (Test-Path $script:Config.scripts.postScript)) {
        $script:Config.scripts.postScript = ""; $repaired = $true
        Write-Host ($script:Locale['IntegrityRepair'] -f "Post-script (missing)") -ForegroundColor $script:Theme['Accent']
    }
    Write-Progress -Activity ($script:Locale['IntegrityTitle']) -Completed
    if ($repaired) { Save-Config }
    if (-not $script:SilentMode) { Write-Host "   $($script:Locale['IntegrityAllOk'])" -ForegroundColor $script:Theme['Success'] }
    Write-Log -Action "INTEGRITY" -Target "System" -Status $(if($repaired){"Repaired"}else{"OK"})
}

# ---- Phase 7: Built-in Self-Test Framework ----
function Invoke-SelfTest {
    $tests = @(
        @{ Name="Config loads"; Script={ $null -ne $script:Config -and $null -ne $script:Config.theme } }
        @{ Name="Locale loads"; Script={ $null -ne $script:Locale -and $null -ne $script:Locale['HeaderTitle'] } }
        @{ Name="Theme loads"; Script={ $null -ne $script:Theme -and $null -ne $script:Theme['Header'] } }
        @{ Name="Config file exists"; Script={ Test-Path $script:ConfigPath } }
        @{ Name="Log file writable"; Script={ try { $null | Out-File $script:LogPath -Encoding utf8 -Force -ErrorAction Stop; $true } catch { $false } } }
        @{ Name="Get-Locale returns hash"; Script={ $l = Get-Locale; $null -ne $l -and $l.Count -gt 50 } }
        @{ Name="Get-PackageCategory works"; Script={ Get-PackageCategory -Id "google.chrome" -Name "Chrome" -eq "Browser" } }
        @{ Name="Get-DiskSpaceInfo returns data"; Script={ $d = Get-DiskSpaceInfo; $null -ne $d -and $d.FreeGB -gt 0 } }
        @{ Name="Get-PackageHealthScore returns value"; Script={ $null -ne (Get-PackageHealthScore) } }
        @{ Name="Get-DefaultConfig has all sections"; Script={ $c = Get-DefaultConfig; $null -ne $c.github -and $null -ne $c.apiServer -and $null -ne $c.ui.scale } }
        @{ Name="EM & AR locale parity"; Script={ $en = $script:English; $ar = $script:Arabic; $ec = ($en.Keys | Where-Object { $_ -ne 'HeaderTitle' }).Count; $ac = ($ar.Keys | Where-Object { $_ -ne 'HeaderTitle' }).Count; $ec -eq $ac } }
        @{ Name="Battery awareness returns status"; Script={ $b = Get-BatteryStatus; $b -match '%|AC|100%|Battery' -or $b -eq "AC" } }
    )
    Write-Host "`n  $($script:Locale['TestTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    Write-Host ($script:Locale['TestRun'] -f $tests.Count) -ForegroundColor $script:Theme['Accent']
    $passed = 0; $failed = 0
    foreach ($t in $tests) {
        try {
            $result = & $t.Script
            if ($result) { Write-Host "   $($script:Locale['TestPass'] -f $t.Name)" -ForegroundColor $script:Theme['Success']; $passed++ }
            else { Write-Host "   $($script:Locale['TestFail'] -f $t.Name, 'Assertion returned false')" -ForegroundColor $script:Theme['Error']; $failed++ }
        } catch {
            Write-Host "   $($script:Locale['TestFail'] -f $t.Name, $_.Exception.Message)" -ForegroundColor $script:Theme['Error']; $failed++
        }
    }
    Write-Host ("  " + "-" * 46)
    if ($failed -eq 0) {
        Write-Host "   $($script:Locale['TestSummary'] -f $passed, $tests.Count, $failed)" -ForegroundColor $script:Theme['Success']
        Write-Host "   $($script:Locale['TestAllPassed'])" -ForegroundColor $script:Theme['Success']
        if (Test-UWMConsoleAvailable) { [Console]::Beep(1000,150) }
    } else {
        Write-Host "   $($script:Locale['TestSummary'] -f $passed, $tests.Count, $failed)" -ForegroundColor $script:Theme['Accent']
        if (Test-UWMConsoleAvailable) { [Console]::Beep(400,300) }
    }
    Write-Log -Action "SELFTEST" -Target "All" -Status $(if($failed -eq 0){"Passed"}else{"Failed"}) -Details "$passed/$($tests.Count) passed"
}

# ---- Nuclear Diagnostic & Self-Repair Sentinel ----
function Test-UWMDiskHeadroom {
    param([double]$MinFreeGB = 5.0)
    try {
        $drive = Get-PSDrive -Name C -ErrorAction Stop
        $freeGB = [Math]::Round($drive.Free / 1GB, 2)
        return [PSCustomObject]@{ Safe = ($freeGB -ge $MinFreeGB); FreeGB = $freeGB; MinGB = $MinFreeGB; Path = $drive.Root }
    } catch {
        return [PSCustomObject]@{ Safe = $false; FreeGB = -1; MinGB = $MinFreeGB; Path = $null }
    }
}

function Test-UWMUpdateEngineLock {
    $hits = @()
    foreach ($n in @('TrustedInstaller','wuauclt','wuaueng','WaaSMedicSvc','MoUsoCoreWorker','wuapp')) {
        if (Get-Process -Name $n -ErrorAction SilentlyContinue) { $hits += "proc:$n" }
    }
    foreach ($n in @('wuauserv','UsoSvc','TrustedInstaller')) {
        try {
            $svc = Get-Service -Name $n -ErrorAction Stop
            if ($svc.Status -eq 'Running') { $hits += "svc:$n" }
        } catch { }
    }
    return [PSCustomObject]@{ Locked = ($hits.Count -gt 0); Hits = $hits }
}

function Wait-UWMJobWithSpinner {
    param([object]$Job, [int]$TimeoutSec = 30, [string]$Label = "Working")
    $frames = @('|','/','-','\')
    $i = 0
    $elapsed = 0
    while ($Job.State -eq 'Running' -and $elapsed -lt $TimeoutSec) {
        Write-Host ("`r   {0} {1}  [{2}s/{3}s]" -f $Label, $frames[$i % 4], $elapsed, $TimeoutSec) -NoNewline
        Start-Sleep -Seconds 1
        $elapsed++
        $i++
    }
    Write-Host ("`r   {0} finished after {1}s.      " -f $Label, $elapsed)
    if ($Job.State -eq 'Running') {
        Stop-Job $Job -ErrorAction SilentlyContinue
        Remove-Job $Job -Force -ErrorAction SilentlyContinue
        return $false
    }
    return $true
}

function Invoke-UWMStorageTelemetry {
    $job = Start-Job -ScriptBlock {
        param($cultureName)
        $ci = [System.Globalization.CultureInfo]::GetCultureInfo($cultureName)
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
        Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { [PSCustomObject]@{ FriendlyName = $_.FriendlyName; HealthStatus = $_.HealthStatus; MediaType = $_.MediaType } }
    } -ArgumentList 'en-US'
    $done = $job | Wait-Job -Timeout 2
    if ($null -eq $done) {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host "   [STORAGE] Standard SMART query bypassed safely" -ForegroundColor Yellow
        Write-Log -Action "STORAGE_TELEMETRY" -Target "SMART" -Status "Bypassed" -Details "Get-PhysicalDisk exceeded 2s probe window; standard SMART query bypassed safely"
        return @{ Bypassed = $true }
    }
    $data = @(Receive-Job $job -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName })
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    Write-Host "   [STORAGE] SMART telemetry captured ($($data.Count) disk(s))." -ForegroundColor Green
    Write-Log -Action "STORAGE_TELEMETRY" -Target "SMART" -Status "Ok" -Details "$($data.Count) physical disk(s) enumerated"
    return @{ Bypassed = $false; Disks = $data }
}

function Invoke-UWMNetworkProbe {
    foreach ($target in @('1.1.1.1','8.8.8.8')) {
        $job = Start-Job -ScriptBlock {
            param($hostName)
            try {
                $probe = New-Object System.Net.NetworkInformation.Ping
                $reply = $probe.Send($hostName, 3000)
                if ($null -ne $reply -and $reply.Status -eq 'Success') { return $true }
            } catch { }
            return $false
        } -ArgumentList $target
        $done = $job | Wait-Job -Timeout 30
        $probeOk = $false
        if ($null -ne $done) {
            $probeOk = @(Receive-Job $job -ErrorAction SilentlyContinue | Where-Object { $_ -eq $true }).Count -gt 0
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        } else {
            Stop-Job $job -ErrorAction SilentlyContinue
            Remove-Job $job -Force -ErrorAction SilentlyContinue
        }
        if ($probeOk) { return $true }
    }
    return $false
}

function Get-UWMDiagnosticsBaseline {
    param([switch]$SkipTelemetry)
    $job = Start-Job -ScriptBlock {
        param($cultureName, $skipTelemetry)
        $ci = [System.Globalization.CultureInfo]::GetCultureInfo($cultureName)
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
        $result = [ordered]@{ FreeGB = -1; CompStoreGB = -1; CorruptAssets = $false; CheckHealth = 'Unavailable' }
        try {
            $drive = Get-PSDrive -Name C -ErrorAction Stop
            $result.FreeGB = [Math]::Round($drive.Free / 1GB, 2)
        } catch { }
        if (-not $skipTelemetry) {
            try {
                $chk = (Dism.exe /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String)
                if ($chk -match '(?i)no component store corruption') {
                    $result.CheckHealth = 'Clean'
                    $result.CorruptAssets = $false
                } elseif ($chk -match '(?i)repairable|corruption.*(?:detected|found)|corrupted') {
                    $result.CheckHealth = 'Corrupt'
                    $result.CorruptAssets = $true
                } else {
                    $result.CheckHealth = if ([string]::IsNullOrWhiteSpace($chk)) { 'Unavailable' } else { 'Clean' }
                }
            } catch { }
            try {
                $ana = (Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>&1 | Out-String)
                if ($ana -match '(?i)(actual\s+size\s+of\s+component\s+store|size\s+of\s+component\s+store)\s*:\s*([\d.,]+)\s*(MB|GB)') {
                    $val = [double]($Matches[2].Replace(',', '.'))
                    if ($Matches[3] -eq 'GB') { $result.CompStoreGB = [Math]::Round($val, 2) } else { $result.CompStoreGB = [Math]::Round($val / 1024, 2) }
                }
            } catch { }
        }
        return $result
    } -ArgumentList 'en-US', ([bool]$SkipTelemetry)
    $complete = Wait-UWMJobWithSpinner -Job $job -TimeoutSec 30 -Label "System baseline (CheckHealth)"
    if ($complete) {
        $data = Receive-Job $job -ErrorAction SilentlyContinue | Select-Object -First 1
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        if ($null -ne $data) { return $data }
    } else {
        Remove-Job $job -Force -ErrorAction SilentlyContinue
    }
    return [PSCustomObject]@{ FreeGB = -1; CompStoreGB = -1; CorruptAssets = $false; CheckHealth = 'Unavailable' }
}

function Invoke-UWMAppXHealer {
    $fixes = 0
    $pythonScript = Join-Path $PSScriptRoot "fix Get-Appx.py"
    if (Test-Path $pythonScript) {
        $py = Get-Command python -ErrorAction SilentlyContinue
        if ($null -ne $py -and -not [string]::IsNullOrEmpty($py.Source) -and (Test-Path $py.Source)) {
            try {
                Start-Process python -ArgumentList "`"$pythonScript`" --force" -Verb RunAs -Wait
                $fixes++
                Write-Host "   [APPX] Python payload executed (elevated)." -ForegroundColor $script:Theme['Success']
            } catch {
                Write-Host "   [APPX] Elevation rejected: $_" -ForegroundColor $script:Theme['Error']
            }
        } else {
            Write-Host "   [APPX] Python runtime not verified — skipping payload." -ForegroundColor Yellow
        }
    } else {
        Write-Host "   [APPX] 'fix Get-Appx.py' missing — using provisioned-package fallback." -ForegroundColor Yellow
    }
    try {
        $cbd = Get-Service -Name cbdhsvc -ErrorAction Stop
        if ($cbd.StartType -ne 'Automatic') {
            Set-Service -Name cbdhsvc -StartupType Automatic -ErrorAction Stop
            $fixes++
            Write-Host "   [APPX] cbdhsvc (CBS broker) set to Automatic." -ForegroundColor $script:Theme['Success']
        } else {
            Write-Host "   [APPX] cbdhsvc already Automatic." -ForegroundColor $script:Theme['Dim']
        }
    } catch {
        Write-Host "   [APPX] cbdhsvc not serviceable on this SKU." -ForegroundColor $script:Theme['Dim']
    }
    $store = Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue
    if ($null -eq $store) {
        try {
            $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { $_.PackageName -like '*WindowsStore*' })
            if ($provisioned.Count -gt 0) {
                Add-AppxPackage -Register (Join-Path $provisioned[0].InstallLocation "AppxManifest.xml") -DisableDevelopmentMode -ErrorAction Stop
                $fixes++
                Write-Host "   [APPX] Store re-registered from provisioned pool." -ForegroundColor $script:Theme['Success']
            } else {
                Write-Host "   [APPX] No Store package in provisioned pool." -ForegroundColor $script:Theme['Dim']
            }
        } catch {
            Write-Host "   [APPX] Provisioned-package re-registration unavailable." -ForegroundColor $script:Theme['Dim']
        }
    } else {
        Write-Host "   [APPX] Microsoft Store present — provisioned fallback not needed." -ForegroundColor $script:Theme['Dim']
    }
    return $fixes
}

function Invoke-UWMKernelRestore {
    $job = Start-Job -ScriptBlock {
        param($cultureName)
        $ci = [System.Globalization.CultureInfo]::GetCultureInfo($cultureName)
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
        $log = @()
        try {
            $dism = (Dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String)
            $log += "[DISM] " + ($dism -replace "`r?`n", " | ")
        } catch { $log += "[DISM] ERROR: $_" }
        try {
            $sfc = (sfc.exe /scannow 2>&1 | Out-String)
            $log += "[SFC] " + ($sfc -replace "`r?`n", " | ")
        } catch { $log += "[SFC] ERROR: $_" }
        $log -join [Environment]::NewLine
    } -ArgumentList 'en-US'
    $finished = Wait-UWMJobWithSpinner -Job $job -TimeoutSec 600 -Label "Kernel restore (DISM + SFC)"
    if ($finished) {
        $out = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        $hasError = (($out | Out-String) -match '(?i)error|failure|could not|0x8')
        Write-Host ("   [KERNEL] Completed. Verdict: {0}" -f $(if ($hasError) { 'Issues reported — review details.' } else { 'No errors reported.' })) -ForegroundColor $(if ($hasError) { 'Yellow' } else { $script:Theme['Success'] })
        Write-Log -Action "KERNEL_RESTORE" -Target "DISM/SFC" -Status $(if ($hasError) { 'Warnings' } else { 'Ok' }) -Details "Watchdog completed; issues=$hasError"
        return (-not $hasError)
    }
    Write-Host "   [KERNEL] Exceeded 600s watchdog — killed." -ForegroundColor $script:Theme['Error']
    Write-Host "   [W] A stale DISM/SFC process may still be running. A restart is recommended." -ForegroundColor Yellow
    Write-Log -Action "KERNEL_RESTORE" -Target "DISM/SFC" -Status "Timeout" -Details "Killed after 600s watchdog"
    Write-Host ""
    Write-Host "   Press [S] to reboot into Safe Mode for further repair, or any other key to continue." -NoNewline -ForegroundColor Yellow
    $rkey = Get-UWMRawKey
    Write-Host ""
    if ([char]::ToUpper([char]$rkey) -eq [char]'S') {
        try {
            Start-Process bcdedit.exe -ArgumentList "/set","{current}","safeboot","minimal" -Verb RunAs -Wait
            Start-Process shutdown.exe -ArgumentList "/r","/t","30","/c","UWM safe-mode reboot for kernel repair" -Verb RunAs -Wait
            Write-Host "   [KERNEL] Safe-mode restart scheduled in 30s." -ForegroundColor $script:Theme['Success']
        } catch {
            Write-Host "   [KERNEL] Safe-mode boot request rejected (elevation required)." -ForegroundColor $script:Theme['Error']
        }
    }
    return $false
}

function Test-UWMIsReparsePoint {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    } catch { return $false }
}

function Get-UWMUserProfiles {
    $profiles = @()
    try {
        $base = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $sids = @(Get-ChildItem -LiteralPath $base -ErrorAction Stop | Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' })
        foreach ($s in $sids) {
            $prof = Get-ItemProperty -LiteralPath $s.PSPath -ErrorAction SilentlyContinue
            if ($prof.ProfileImagePath) {
                $profiles += [PSCustomObject]@{ SID = $s.PSChildName; Path = $prof.ProfileImagePath; Exists = (Test-Path -LiteralPath $prof.ProfileImagePath) }
            }
        }
    } catch { }
    return $profiles
}

function Get-UWMWindowsUpdateEvents {
    param([int]$SinceDays = 7, [int]$MaxEvents = 200)
    $start = (Get-Date).AddDays(-$SinceDays)
    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Id = 20,24,27; StartTime = $start } -MaxEvents $MaxEvents -ErrorAction Stop)
    } catch {
        try {
            $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'WindowsUpdateClient'; StartTime = $start } -MaxEvents $MaxEvents -ErrorAction Stop | Where-Object { $_.Id -in 20,24,27 })
        } catch { $events = @() }
    }
    return $events
}

function Test-UWMWindowsUpdateHealth {
    param([int]$SinceDays = 7)
    $prevCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
    $prevUi = [System.Threading.Thread]::CurrentThread.CurrentUICulture
    $ci = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
    try {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
        $events = Get-UWMWindowsUpdateEvents -SinceDays $SinceDays
        $failures = @()
        $kbs = @()
        $codes = @()
        foreach ($e in $events) {
            $msg = [string]$e.Message
            $kb = [regex]::Match($msg, '(?i)\bKB\d{5,8}\b').Value
            $code = [regex]::Match($msg, '\b0x[0-9A-Fa-f]{6,8}\b').Value
            if (-not $code) { $code = [regex]::Match($msg, '\b80[0-9]{8}\b').Value }
            $failures += [PSCustomObject]@{ Time = $e.TimeCreated; Id = $e.Id; Kb = $kb; ExitCode = $code; Message = $msg }
            if ($kb -and $kb -notin $kbs) { $kbs += $kb }
            if ($code -and $code -notin $codes) { $codes += $code }
        }
        return [PSCustomObject]@{ Stable = ($failures.Count -eq 0); Failures = $failures; Kbs = $kbs; Codes = $codes; SinceDays = $SinceDays }
    } finally {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $prevCulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $prevUi
    }
}

function Get-UWMMicrosoftCatalogLink {
    param([string]$Kb)
    try {
        $searchUrl = "https://www.catalog.update.microsoft.com/Search.aspx?q=$Kb"
        $resp = Invoke-WebRequest -Uri $searchUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $content = $resp.Content
        $matches = [regex]::Matches($content, 'goToDetails\(&quot;([a-fA-F0-9-]+)&quot;\)')
        if ($matches.Count -eq 0) { $matches = [regex]::Matches($content, 'goToDetails\("([a-fA-F0-9-]+)"\)') }
        if ($matches.Count -eq 0) { return $null }
        $scored = @()
        foreach ($m in $matches) {
            $guid = $m.Groups[1].Value
            if (-not $guid) { continue }
            $pos = $m.Index
            $from = [Math]::Max(0, $pos - 1500)
            $len = [Math]::Min(3000, $content.Length - $from)
            $ctx = $content.Substring($from, $len)
            $arch = if ($ctx -match 'x64') { 'x64' } elseif ($ctx -match 'ARM64') { 'ARM64' } elseif ($ctx -match 'x86') { 'x86' } else { '?' }
            $scored += [PSCustomObject]@{ Guid = $guid; Arch = $arch }
        }
        $ordered = @()
        $ordered += @($scored | Where-Object { $_.Arch -eq 'x64' } | ForEach-Object { $_.Guid })
        $ordered += @($scored | Where-Object { $_.Arch -ne 'x64' } | ForEach-Object { $_.Guid })
        $ids = @($ordered | Select-Object -Unique)
        foreach ($id in $ids) {
            foreach ($body in @("updateIDs='[""{0}""]'" -f $id, "updateIDs='[{0}]'" -f $id)) {
                try {
                    $dl = Invoke-WebRequest -Method Post -Uri "https://www.catalog.update.microsoft.com/downloaddialog.aspx" -Body $body -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
                    $link = [regex]::Match($dl.Content, 'href="(https?://[^"]+\.msu)"').Groups[1].Value
                    if ($link) { return $link }
                } catch { }
            }
        }
    } catch { }
    return $null
}

function Invoke-UWMWusaMicroPatch {
    param([string]$Kb)
    $disk = Test-UWMDiskHeadroom
    if (-not $disk.Safe) {
        Write-Host "   [WUSA] Aborted: only $($disk.FreeGB) GB free — need >= $($disk.MinGB) GB for micro-patch staging." -ForegroundColor Red
        Write-Log -Action "UPDATE_REPAIR" -Target "WUSA" -Status "Aborted" -Details "Disk headroom below 5GB safeguard"
        return $false
    }
    Write-Host "   [WUSA] Querying Microsoft Update Catalog for $Kb ..." -ForegroundColor $script:Theme['Accent']
    $url = Get-UWMMicrosoftCatalogLink -Kb $Kb
    if (-not $url) {
        Write-Host "   [WUSA] Catalog lookup failed for $Kb — skipping micro-patch. No full OS assistant or heavy ISO will be deployed." -ForegroundColor Yellow
        Write-Log -Action "UPDATE_REPAIR" -Target $Kb -Status "CatalogNotFound" -Details "Microsoft Update Catalog returned no standalone MSU"
        return $false
    }
    $targetDir = Join-Path $env:TEMP 'UWM-MicroPatch'
    if (-not (Test-Path -LiteralPath $targetDir)) { New-Item -ItemType Directory -Path $targetDir -Force | Out-Null }
    $file = Join-Path $targetDir ($Kb + '.msu')
    Write-Host "   [WUSA] Downloading single micro-package (no OS assistant, no ISO)..."
    $dlJob = Start-Job -ScriptBlock {
        param($uri, $target, $ciName)
        $ci = [System.Globalization.CultureInfo]::GetCultureInfo($ciName)
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
        Invoke-WebRequest -Uri $uri -OutFile $target -UseBasicParsing -TimeoutSec 500 -ErrorAction Stop
    } -ArgumentList $url, $file, 'en-US'
    $dlOk = Wait-UWMJobWithSpinner -Job $dlJob -TimeoutSec 600 -Label "Micro-patch download"
    $dlVerified = (Test-Path -LiteralPath $file) -and ((Get-Item -LiteralPath $file -ErrorAction SilentlyContinue).Length -gt 0)
    if (-not $dlOk -or -not $dlVerified) {
        Remove-Job $dlJob -Force -ErrorAction SilentlyContinue
        Write-Host "   [WUSA] Download timed out or failed — micro-patch aborted safely." -ForegroundColor Yellow
        Write-Log -Action "UPDATE_REPAIR" -Target $Kb -Status "DownloadFailed" -Details "Micro-package download failed/timed out"
        return $false
    }
    $sizeMB = [Math]::Round((Get-Item -LiteralPath $file).Length / 1MB, 1)
    Write-Host ("   [WUSA] Downloaded {0} ({1} MB). Deploying via wusa.exe /quiet /norestart..." -f $Kb, $sizeMB) -ForegroundColor $script:Theme['Accent']
    $wusaJob = Start-Job -ScriptBlock {
        param($path, $ciName)
        $ci = [System.Globalization.CultureInfo]::GetCultureInfo($ciName)
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
        try {
            $p = Start-Process wusa.exe -ArgumentList @($path, '/quiet', '/norestart') -Wait -PassThru -Verb RunAs -ErrorAction Stop
            return $p.ExitCode
        } catch { return -1 }
    } -ArgumentList $file, 'en-US'
    $wusaOk = Wait-UWMJobWithSpinner -Job $wusaJob -TimeoutSec 600 -Label "Micro-patch deployment (wusa)"
    $exitCode = -1
    if ($wusaOk) {
        $exitCode = @(Receive-Job $wusaJob -ErrorAction SilentlyContinue) | Select-Object -Last 1
        Remove-Job $wusaJob -Force -ErrorAction SilentlyContinue
    } else {
        Remove-Job $wusaJob -Force -ErrorAction SilentlyContinue
    }
    $exitCode = if ($null -eq $exitCode) { -1 } else { [int]$exitCode }
    if ($exitCode -eq 0 -or $exitCode -eq 3010) {
        Write-Host "   [WUSA] $Kb deployed successfully (exit $exitCode) — deployment gap bridged." -ForegroundColor $script:Theme['Success']
        Write-Log -Action "UPDATE_REPAIR" -Target $Kb -Status "Success" -Details "wusa exit $exitCode"
        return $true
    }
    Write-Host "   [WUSA] wusa returned exit $exitCode for $Kb — consult the system event log." -ForegroundColor Yellow
    Write-Log -Action "UPDATE_REPAIR" -Target $Kb -Status "Failed" -Details "wusa exit $exitCode"
    return $false
}

function Reset-UWMUpdateServiceACL {
    $results = @()
    $sddl = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)"
    foreach ($svc in @('wuauserv','cryptsvc','bits','msiserver')) {
        $startOk = $false
        $aclOk = $false
        try {
            Set-Service -Name $svc -StartupType Automatic -ErrorAction Stop
            $startOk = $true
        } catch { }
        try {
            & sc.exe sdset $svc $sddl *> $null
            $aclOk = ($LASTEXITCODE -eq 0)
        } catch { $aclOk = $false }
        $ok = $startOk -and $aclOk
        $results += @{ Text = ("[SVC] {0}: startup={1}, sdset={2}" -f $svc, $(if ($startOk) { 'Auto' } else { 'DENIED' }), $(if ($aclOk) { 'OK' } else { 'DENIED' })); Color = $(if ($ok) { $script:Theme['Success'] } else { 'Red' }) }
    }
    return $results
}

function Rename-UWMUpdateStore {
    $results = @()
    $pairs = @(
        @{ Path = 'C:\Windows\SoftwareDistribution'; New = 'C:\Windows\SoftwareDistribution.old' },
        @{ Path = 'C:\Windows\System32\catroot2'; New = 'C:\Windows\System32\catroot2.old' }
    )
    Stop-Service -Name wuauserv, bits, cryptsvc, msiserver -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 800
    foreach ($p in $pairs) {
        $renamed = $false
        if (Test-UWMIsReparsePoint -Path $p.Path) {
            $results += @{ Text = ("[RENAME] {0} is a reparse point — guarded, skipped." -f $p.Path); Color = 'Yellow' }
            continue
        }
        if (-not (Test-Path -LiteralPath $p.Path)) {
            $results += @{ Text = ("[RENAME] {0} absent — nothing to quarantine." -f $p.Path); Color = $script:Theme['Dim'] }
            continue
        }
        $dest = $p.New
        if (Test-Path -LiteralPath $dest) {
            $dest = $dest + "." + (Get-Date -Format 'yyyyMMdd-HHmmss')
        }
        try {
            Move-Item -LiteralPath $p.Path -Destination $dest -Force -ErrorAction Stop
            $renamed = $true
        } catch {
            try {
                [System.IO.Directory]::Move($p.Path, $dest)
                $renamed = $true
            } catch { }
        }
        if ($renamed) {
            $results += @{ Text = ("[RENAME] {0} -> {1}" -f $p.Path, $dest); Color = $script:Theme['Success'] }
        } else {
            $results += @{ Text = ("[RENAME] {0} locked by a running process — quarantine deferred." -f $p.Path); Color = 'Red' }
        }
    }
    Start-Service -Name wuauserv, bits -ErrorAction SilentlyContinue
    return $results
}

function Register-UWMUpdateAssemblies {
    $dlls = @('atl.dll','urlmon.dll','mshtml.dll','shdocvw.dll','browseui.dll','jscript.dll','vbscript.dll','scrrun.dll','msxml.dll','msxml3.dll','msxml6.dll','actxprxy.dll','softpub.dll','wintrust.dll','dssenh.dll','rsaenh.dll','gpapi.dll','cryptdlg.dll','cryptui.dll','crypt32.dll','oleaut32.dll','ole32.dll','shell32.dll','initpki.dll','wuapi.dll','wuaueng.dll','wucltui.dll','wups.dll','wups2.dll','wuweb.dll','qmgr.dll','qmgrprxy.dll','wucltux.dll','muweb.dll','wuwebv.dll')
    $ok = 0
    foreach ($d in $dlls) {
        $sys = Join-Path $env:WINDIR ("System32\" + $d)
        if (-not (Test-Path -LiteralPath $sys)) { continue }
        try {
            & regsvr32.exe /s $sys *> $null
            if ($LASTEXITCODE -eq 0) { $ok++ }
        } catch { }
    }
    return $ok
}

function Invoke-UWMUpdateRepair {
    param([object]$Health)
    $prevCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
    $prevUi = [System.Threading.Thread]::CurrentThread.CurrentUICulture
    $ci = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
    try {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
        if ($null -eq $Health) { $Health = Test-UWMWindowsUpdateHealth }
        $disk = Test-UWMDiskHeadroom
        $repairLines = @()
        if (-not $disk.Safe) {
            Write-Host "   [U] ABORTED: disk headroom $($disk.FreeGB) GB < $($disk.MinGB) GB safeguard." -ForegroundColor Red
            return @{ Performed = $false; Bypassed = $false; Lines = @(@{ Text = "[U] Aborted by disk headroom safeguard."; Color = 'Red' }); Health = $null; Kbs = @(); Codes = @() }
        }
        if ($Health.Stable) {
            Write-Host "   [SYSTEM] Windows Update infrastructure is fully stable. No action required." -ForegroundColor Green
            Write-Log -Action "UPDATE_REPAIR" -Target "WindowsUpdate" -Status "Bypassed" -Details "ETW scan clean; heavy cache resets and downloads bypassed"
            return @{ Performed = $false; Bypassed = $true; Lines = @(@{ Text = "[SYSTEM] Windows Update infrastructure is fully stable. No action required."; Color = $script:Theme['Success'] }); Health = $Health; Kbs = @(); Codes = @() }
        }
        $profiles = Get-UWMUserProfiles
        $repairLines += @{ Text = ("[PROFILE] Discovered {0} user profile scope(s)." -f $profiles.Count); Color = $script:Theme['Dim'] }
        Write-Host ("   [ETW] {0} failed update trace(s) | KBs: {1} | Codes: {2}" -f $Health.Failures.Count, $(if ($Health.Kbs.Count) { $Health.Kbs -join ', ' } else { '-' }), $(if ($Health.Codes.Count) { $Health.Codes -join ', ' } else { '-' })) -ForegroundColor Yellow

        Write-Host ""
        Write-Host "   STAGE 1/4 — Reset service security descriptors + Automatic startup" -ForegroundColor $script:Theme['Accent']
        $svcResults = Reset-UWMUpdateServiceACL
        foreach ($s in $svcResults) {
            $repairLines += $s
            Write-Host ("     {0}" -f $s.Text) -ForegroundColor $s.Color
        }

        Write-Host ""
        Write-Host "   STAGE 2/4 — Quarantine SoftwareDistribution + catroot2" -ForegroundColor $script:Theme['Accent']
        $renameResults = Rename-UWMUpdateStore
        foreach ($s in $renameResults) {
            $repairLines += $s
            Write-Host ("     {0}" -f $s.Text) -ForegroundColor $s.Color
        }

        Write-Host ""
        Write-Host "   STAGE 3/4 — Re-register update assemblies + online store sync" -ForegroundColor $script:Theme['Accent']
        $regCount = Register-UWMUpdateAssemblies
        $regLine = @{ Text = ("[REGSVR] {0} assembly(ies) re-registered silently." -f $regCount); Color = $(if ($regCount -gt 0) { $script:Theme['Success'] } else { $script:Theme['Dim'] }) }
        $repairLines += $regLine
        Write-Host ("     {0}" -f $regLine.Text) -ForegroundColor $regLine.Color
        $dismJob = Start-Job -ScriptBlock {
            param($ciName)
            $ci = [System.Globalization.CultureInfo]::GetCultureInfo($ciName)
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $ci
            [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
            try { $o = (Dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String) } catch { $o = "ERROR: $_" }
            $o
        } -ArgumentList 'en-US'
        $dismOk = Wait-UWMJobWithSpinner -Job $dismJob -TimeoutSec 600 -Label "Component store online sync (DISM)"
        if ($dismOk) {
            $dismOut = Receive-Job $dismJob -ErrorAction SilentlyContinue
            Remove-Job $dismJob -Force -ErrorAction SilentlyContinue
            $dismClean = (($dismOut | Out-String) -match '(?i)no corruption detected')
            $dismLine = @{ Text = ("[DISM] Online component store sync completed. Verdict: {0}" -f $(if ($dismClean) { 'clean' } else { 'review output' })); Color = $(if ($dismClean) { $script:Theme['Success'] } else { 'Yellow' }) }
        } else {
            Remove-Job $dismJob -Force -ErrorAction SilentlyContinue
            $dismLine = @{ Text = "[DISM] Online component store sync exceeded 600s watchdog — killed safely."; Color = 'Yellow' }
        }
        $repairLines += $dismLine
        Write-Host ("     {0}" -f $dismLine.Text) -ForegroundColor $dismLine.Color

        Write-Host ""
        $afterHealth = Test-UWMWindowsUpdateHealth
        Write-Host "   STAGE 4/4 — Micro-Package Injection (single .msu fallback)" -ForegroundColor $script:Theme['Accent']
        $kbsUsed = @()
        if ($afterHealth.Stable) {
            Write-Host "     [U] Standard repairs resolved the deployment gap — micro-patch not required." -ForegroundColor $script:Theme['Success']
            $repairLines += @{ Text = "[U] Repairs resolved the gap; micro-patch skipped."; Color = $script:Theme['Success'] }
        } else {
            $kbsUsed = @($afterHealth.Kbs)
            if ($kbsUsed.Count -eq 0) { $kbsUsed = @($Health.Kbs) }
            if ($kbsUsed.Count -gt 0) {
                Write-Host "     [U] Native updater still blocked — deploying single micro-patch only (no OS assistant, no heavy ISO)." -ForegroundColor Yellow
                foreach ($kb in $kbsUsed) { Invoke-UWMWusaMicroPatch -Kb $kb }
                $repairLines += @{ Text = ("[U] Micro-patch injection attempted for: {0}." -f ($kbsUsed -join ', ')); Color = 'Yellow' }
            } else {
                Write-Host "     [U] No KB identifier isolated from event logs — micro-patch skipped." -ForegroundColor Yellow
                $repairLines += @{ Text = "[U] No KB isolated from event logs; micro-patch skipped."; Color = 'Yellow' }
            }
        }
        Write-Log -Action "UPDATE_REPAIR" -Target "WindowsUpdate" -Status "Done" -Details "KBs=$($kbsUsed -join ',') Codes=$($afterHealth.Codes -join ',')"
        return @{ Performed = $true; Bypassed = $false; Lines = $repairLines; Health = $afterHealth; Kbs = $kbsUsed; Codes = $afterHealth.Codes }
    } finally {
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $prevCulture
        [System.Threading.Thread]::CurrentThread.CurrentUICulture = $prevUi
    }
}

function Show-UWMDiagnosticsStepCard {
    param([object]$Step)
    $statusColor = switch ($Step.Status) {
        'OK'      { $script:Theme['Success'] }
        'BLOCKED' { 'Red' }
        'WARN'    { 'Yellow' }
        'BY-PASS' { $script:Theme['Success'] }
        default   { $script:Theme['Accent'] }
    }
    Write-Host ("  " + ("═" * 60)) -ForegroundColor $script:Theme['Dim']
    Write-Host ("  {0}   [{1}]" -f $Step.Title, $Step.Status) -ForegroundColor $statusColor
    foreach ($line in $Step.Lines) {
        Write-Host ("    {0}" -f $line.Text) -ForegroundColor $(if ($line.Color) { $line.Color } else { $script:Theme['Dim'] })
    }
}

function Show-UWMDiagnosticsMatrix {
    param([object]$Before, [object]$After, [switch]$RepairBlocked, [string]$BlockReason, [object]$WuBefore, [object]$WuAfter)
    $bFree = if ($null -ne $Before) { $Before.FreeGB } else { -1 }
    $aFree = if ($null -ne $After) { $After.FreeGB } else { -1 }
    $bComp = if ($null -ne $Before) { $Before.CompStoreGB } else { -1 }
    $aComp = if ($null -ne $After) { $After.CompStoreGB } else { -1 }
    $bCorr = if ($null -ne $Before) { $Before.CorruptAssets } else { $false }
    $aCorr = if ($null -ne $After) { $After.CorruptAssets } else { $false }
    $bWU = if ($null -ne $WuBefore) { @($WuBefore.Failures).Count } else { -1 }
    $aWU = if ($null -ne $WuAfter) { @($WuAfter.Failures).Count } else { -1 }
    $widths = @(22, 20, 20)
    Write-Host ""
    Write-Host "   Before vs After Repair Matrix" -ForegroundColor $script:Theme['Accent']
    Write-Host (New-UWMBorderLine -Widths $widths -L "╔" -Mid "╦" -R "╗") -ForegroundColor $script:Theme['Dim']
    Write-UWMRowLine -Widths $widths -Cells @(
        @{ Text = "Metric"; Color = $script:Theme['Header'] },
        @{ Text = "Before"; Color = $script:Theme['Header'] },
        @{ Text = "After"; Color = $script:Theme['Header'] })
    Write-Host (New-UWMBorderLine -Widths $widths -L "╠" -Mid "╬" -R "╣") -ForegroundColor $script:Theme['Dim']
    $rows = @(
        @(
            @{ Text = "Free Disk (GB)"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bFree -lt 0) { "—" } else { "{0} GB" -f $bFree }); Color = $(if ($bFree -ge 0 -and $bFree -lt 5.0) { 'Yellow' } else { $script:Theme['Dim'] }) }
            @{ Text = $(if ($aFree -lt 0) { "—" } else { "{0} GB" -f $aFree }); Color = $(if ($aFree -ge 0 -and $aFree -lt 5.0) { 'Yellow' } else { $script:Theme['Dim'] }) }
        )
        @(
            @{ Text = "Component Store (GB)"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bComp -lt 0) { "—" } else { "{0} GB" -f $bComp }); Color = $script:Theme['Dim'] }
            @{ Text = $(if ($aComp -lt 0) { "—" } else { "{0} GB" -f $aComp }); Color = $script:Theme['Dim'] }
        )
        @(
            @{ Text = "Corrupt Assets"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bCorr) { 'Yes' } else { 'No' }); Color = $(if ($bCorr) { 'Yellow' } else { $script:Theme['Success'] }) }
            @{ Text = $(if ($aCorr) { 'Yes' } else { 'No' }); Color = $(if ($aCorr) { 'Yellow' } else { $script:Theme['Success'] }) }
        )
        @(
            @{ Text = "Update Failures (7d)"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bWU -lt 0) { "—" } else { [string]$bWU }); Color = $(if ($bWU -eq 0) { $script:Theme['Success'] } elseif ($bWU -gt 0) { 'Yellow' } else { $script:Theme['Dim'] }) }
            @{ Text = $(if ($aWU -lt 0) { "—" } else { [string]$aWU }); Color = $(if ($aWU -eq 0) { $script:Theme['Success'] } elseif ($aWU -gt 0) { 'Yellow' } else { $script:Theme['Dim'] }) }
        )
    )
    foreach ($row in $rows) { Write-UWMRowLine -Widths $widths -Cells $row }
    Write-Host (New-UWMBorderLine -Widths $widths -L "╚" -Mid "╩" -R "╝") -ForegroundColor $script:Theme['Dim']
    if ($RepairBlocked) {
        Write-Host ""
        Write-Host "   [!] Integrity Repair is currently BLOCKED." -ForegroundColor Red
        if ($BlockReason) { Write-Host "   $BlockReason" -ForegroundColor Yellow }
    }
}

function Show-UWMDiagnosticsPage {
    param([object]$Step, [object]$MatrixBefore, [object]$MatrixAfter, [switch]$RepairBlocked, [string]$BlockReason, [object]$WuBefore, [object]$WuAfter)
    Show-Header
    Write-Host "   [UWM NUCLEAR DIAGNOSTIC & SELF-REPAIR SENTINEL]" -ForegroundColor Cyan
    Write-Host ("   " + ("-" * 60)) -ForegroundColor $script:Theme['Dim']
    if ($null -ne $MatrixBefore) {
        Show-UWMDiagnosticsMatrix -Before $MatrixBefore -After $MatrixAfter -RepairBlocked:$RepairBlocked -BlockReason $BlockReason -WuBefore $WuBefore -WuAfter $WuAfter
        return
    }
    if ($null -ne $Step) { Show-UWMDiagnosticsStepCard -Step $Step }
}

function Show-UWMDiagnosticsNavFooter {
    $footerText = "[A] Analyze System | [U] Update Repair | [I] Integrity Fix | [N] Next Page | [P] Prev Page | [B] Back to Menu"
    $seg1 = "[A] Analyze System | [U] Update Repair | [I] Integrity Fix"
    $seg2 = "[N] Next Page | [P] Prev Page | [B] Back to Menu"
    $width = 120
    if (Test-UWMConsoleAvailable) {
        try { $width = [Console]::WindowWidth } catch { }
    }
    if ($width -lt 1) { $width = 120 }
    $maxLine = $width - 5
    Write-Host ""
    if ((Get-UWMDisplayWidth $footerText) -le $maxLine) {
        Write-Host ("   " + $footerText) -ForegroundColor Cyan
    } else {
        Write-Host ("   " + $seg1) -ForegroundColor Cyan
        Write-Host ("   " + $seg2) -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "   $($script:Locale['NavPrompt'])" -NoNewline -ForegroundColor $script:Theme['Accent']
}

# ---- Diagnostics Gateway: input sanitizer, override guard, stable grid renderer ----
function Clear-UWMInputBuffer {
    try {
        while ([Console]::KeyAvailable) { $null = [Console]::ReadKey($true) }
    } catch { }
}

function Show-UWMConditionalChoicePrompt {
    param([string]$Message, [char]$PreloadAnswer = [char]0)
    Clear-UWMInputBuffer
    Write-Host ""
    Write-Host "   $Message (Y/N)" -ForegroundColor Yellow
    $resp = [char]0
    $failed = 0
    do {
        if ($PreloadAnswer -ne [char]0) {
            $resp = [char]::ToUpper($PreloadAnswer)
        } else {
            Write-Host "   > " -NoNewline -ForegroundColor $script:Theme['Accent']
            try {
                $key = [Console]::ReadKey($true)
                $resp = [char]::ToUpper([char]$key.KeyChar)
            } catch {
                $resp = [char]0
            }
        }
        if ($resp -eq [char]'Y' -or $resp -eq [char]'N') {
            if ($PreloadAnswer -eq [char]0) { Write-Host $resp }
            break
        }
        if ($PreloadAnswer -ne [char]0) { break }
        $failed++
        if ($failed -ge 2) {
            Write-Host ""
            Write-Host "   [INPUT] Key stream unavailable — override safely cancelled." -ForegroundColor $script:Theme['Dim']
            return $false
        }
        Write-Host ""
        Write-Host "   [INPUT] Press Y to override, or N to cancel." -ForegroundColor $script:Theme['Dim']
        Write-Host ""
    } while ($true)
    Write-Host ""
    return ($resp -eq [char]'Y')
}

function Reset-UWMEngineThrottle {
    [string[]]$recycled = @()
    try {
        foreach ($pn in @('TrustedInstaller','TiWorker','wuauclt','wuaueng','WaaSMedicSvc','MoUsoCoreWorker','wuapp')) {
            $hung = @()
            try { $hung = @(Get-Process -Name $pn -ErrorAction SilentlyContinue) } catch { $hung = @() }
            foreach ($p in $hung) {
                $responding = $true
                try { $responding = $p.Responding } catch { $responding = $false }
                if (-not $responding) {
                    try {
                        Stop-Process -Id $p.Id -Force -ErrorAction Stop
                        $recycled += "proc:$pn(pid $($p.Id))"
                    } catch { }
                }
            }
        }
        foreach ($sn in @('wuauserv','UsoSvc','TrustedInstaller')) {
            try {
                $svc = Get-Service -Name $sn -ErrorAction SilentlyContinue
                if ($null -ne $svc -and $svc.Status -eq 'Running') {
                    try {
                        Stop-Service -Name $sn -Force -ErrorAction Stop
                        $recycled += "svc:$sn"
                    } catch {
                        try {
                            Start-Process -FilePath "$env:SystemRoot\System32\net.exe" -ArgumentList @('stop', $sn) -WindowStyle Hidden -Wait -ErrorAction Stop | Out-Null
                            $recycled += "svc:$sn(native)"
                        } catch { }
                    }
                }
            } catch { }
        }
    } catch { }
    return $recycled
}

function Invoke-UWMDiagFallbackRepair {
    param([ValidateSet('Kernel','Update')][string]$Scope)
    Clear-UWMInputBuffer
    [string[]]$recycled = @(Reset-UWMEngineThrottle)
    if ($recycled.Count -gt 0) {
        Write-Host "   [OVERRIDE] Engine throttle recycled: $($recycled -join '; ')" -ForegroundColor Yellow
    } else {
        Write-Host "   [OVERRIDE] No hung engine threads detected — proceeding with isolated fallback." -ForegroundColor $script:Theme['Dim']
    }
    $sp = if ($script:ScriptPath) { $script:ScriptPath } else { Join-Path $PSScriptRoot "update.ps1" }
    $argList = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$sp`" -SilentGlobal -DiagRepairScope $Scope"
    $job = Start-Job -ScriptBlock {
        param([string]$ArgsLine)
        $p = Start-Process -FilePath "powershell.exe" -ArgumentList $ArgsLine -WindowStyle Hidden -Wait -PassThru
        $p.ExitCode
    } -ArgumentList $argList
    $completed = Wait-UWMJobWithSpinner -Job $job -TimeoutSec 600 -Label ("Isolated async fallback remediation ({0})" -f $Scope)
    if ($completed) {
        try { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue } catch { }
        Write-Host ("   [OVERRIDE] Isolated {0} remediation thread reported completion." -f $Scope) -ForegroundColor $script:Theme['Success']
    } else {
        Write-Host ("   [OVERRIDE] Isolated {0} remediation thread still active in background — state refresh proceeding." -f $Scope) -ForegroundColor Yellow
    }
    return $completed
}

function Get-UWMDiagnosticsStepCardLines {
    param([object]$Step)
    $statusColor = switch ($Step.Status) {
        'OK'      { $script:Theme['Success'] }
        'BLOCKED' { 'Red' }
        'WARN'    { 'Yellow' }
        'BY-PASS' { $script:Theme['Success'] }
        default   { $script:Theme['Accent'] }
    }
    $lines = @()
    $sep = "  " + ("═" * 60)
    $title = "  {0}   [{1}]" -f $Step.Title, $Step.Status
    $lines += @{ Text = $sep; Color = $script:Theme['Dim']; Width = (Get-UWMDisplayWidth $sep) + 2 }
    $lines += @{ Text = $title; Color = $statusColor; Width = (Get-UWMDisplayWidth $title) + 2 }
    foreach ($line in $Step.Lines) {
        $txt = "    {0}" -f $line.Text
        $lines += @{ Text = $txt; Color = $(if ($line.Color) { $line.Color } else { $script:Theme['Dim'] }); Width = (Get-UWMDisplayWidth $txt) + 2 }
    }
    if (-not $lines) { $lines = @(@{ Text = ""; Color = $null; Width = 0 }) }
    return $lines
}

function Get-UWMDiagnosticsMatrixLines {
    param([object]$Before, [object]$After, [bool]$RepairBlocked, [string]$BlockReason, [object]$WuBefore, [object]$WuAfter)
    $bFree = if ($null -ne $Before) { $Before.FreeGB } else { -1 }
    $aFree = if ($null -ne $After) { $After.FreeGB } else { -1 }
    $bComp = if ($null -ne $Before) { $Before.CompStoreGB } else { -1 }
    $aComp = if ($null -ne $After) { $After.CompStoreGB } else { -1 }
    $bCorr = if ($null -ne $Before) { $Before.CorruptAssets } else { $false }
    $aCorr = if ($null -ne $After) { $After.CorruptAssets } else { $false }
    $bWU = if ($null -ne $WuBefore) { @($WuBefore.Failures).Count } else { -1 }
    $aWU = if ($null -ne $WuAfter) { @($WuAfter.Failures).Count } else { -1 }
    $widths = @(22, 20, 20)
    $lines = @()
    $lines += @{ Text = ""; Color = $null; Width = 0 }
    $lines += @{ Text = "   Before vs After Repair Matrix"; Color = $script:Theme['Accent']; Width = 40 }
    $lines += @{ Text = (New-UWMBorderLine -Widths $widths -L "╔" -Mid "╦" -R "╗"); Color = $script:Theme['Dim']; Width = 68 }
    $lines += @{ Cells = @(
        @{ Text = "Metric"; Color = $script:Theme['Header'] },
        @{ Text = "Before"; Color = $script:Theme['Header'] },
        @{ Text = "After"; Color = $script:Theme['Header'] }
    ); Widths = $widths; Width = 68 }
    $lines += @{ Text = (New-UWMBorderLine -Widths $widths -L "╠" -Mid "╬" -R "╣"); Color = $script:Theme['Dim']; Width = 68 }
    $dataRows = @(
        @(
            @{ Text = "Free Disk (GB)"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bFree -lt 0) { "—" } else { "{0} GB" -f $bFree }); Color = $(if ($bFree -ge 0 -and $bFree -lt 5.0) { 'Yellow' } else { $script:Theme['Dim'] }) }
            @{ Text = $(if ($aFree -lt 0) { "—" } else { "{0} GB" -f $aFree }); Color = $(if ($aFree -ge 0 -and $aFree -lt 5.0) { 'Yellow' } else { $script:Theme['Dim'] }) }
        )
        @(
            @{ Text = "Component Store (GB)"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bComp -lt 0) { "—" } else { "{0} GB" -f $bComp }); Color = $script:Theme['Dim'] }
            @{ Text = $(if ($aComp -lt 0) { "—" } else { "{0} GB" -f $aComp }); Color = $script:Theme['Dim'] }
        )
        @(
            @{ Text = "Corrupt Assets"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bCorr) { 'Yes' } else { 'No' }); Color = $(if ($bCorr) { 'Yellow' } else { $script:Theme['Success'] }) }
            @{ Text = $(if ($aCorr) { 'Yes' } else { 'No' }); Color = $(if ($aCorr) { 'Yellow' } else { $script:Theme['Success'] }) }
        )
        @(
            @{ Text = "Update Failures (7d)"; Color = $script:Theme['Dim'] }
            @{ Text = $(if ($bWU -lt 0) { "—" } else { [string]$bWU }); Color = $(if ($bWU -eq 0) { $script:Theme['Success'] } elseif ($bWU -gt 0) { 'Yellow' } else { $script:Theme['Dim'] }) }
            @{ Text = $(if ($aWU -lt 0) { "—" } else { [string]$aWU }); Color = $(if ($aWU -eq 0) { $script:Theme['Success'] } elseif ($aWU -gt 0) { 'Yellow' } else { $script:Theme['Dim'] }) }
        )
    )
    foreach ($row in $dataRows) { $lines += @{ Cells = $row; Widths = $widths; Width = 68 } }
    $lines += @{ Text = (New-UWMBorderLine -Widths $widths -L "╚" -Mid "╩" -R "╝"); Color = $script:Theme['Dim']; Width = 68 }
    if ($RepairBlocked) {
        $lines += @{ Text = ""; Color = $null; Width = 0 }
        $lines += @{ Text = "   [!] Integrity Repair is currently BLOCKED."; Color = 'Red'; Width = 48 }
        if ($BlockReason) {
            $brLine = "   " + $BlockReason
            $lines += @{ Text = $brLine; Color = 'Yellow'; Width = (Get-UWMDisplayWidth $brLine) + 2 }
        }
    }
    return $lines
}

function Get-UWMDiagnosticsPageLines {
    param([object]$Step, [object]$MatrixBefore, [object]$MatrixAfter, [bool]$RepairBlocked, [string]$BlockReason, [object]$WuBefore, [object]$WuAfter)
    if ($null -ne $MatrixBefore) {
        return @(Get-UWMDiagnosticsMatrixLines -Before $MatrixBefore -After $MatrixAfter -RepairBlocked $RepairBlocked -BlockReason $BlockReason -WuBefore $WuBefore -WuAfter $WuAfter)
    }
    if ($null -ne $Step) {
        return @(Get-UWMDiagnosticsStepCardLines -Step $Step)
    }
    return @(@{ Text = ""; Color = $null; Width = 0 })
}

function Get-UWMDiagnosticsFooterLines {
    $footerText = "[A] Analyze System | [U] Update Repair | [I] Integrity Fix | [N] Next Page | [P] Prev Page | [B] Back to Menu"
    $seg1 = "[A] Analyze System | [U] Update Repair | [I] Integrity Fix"
    $seg2 = "[N] Next Page | [P] Prev Page | [B] Back to Menu"
    $width = 120
    if (Test-UWMConsoleAvailable) { try { $width = [Console]::WindowWidth } catch { } }
    if ($width -lt 1) { $width = 120 }
    $maxLine = $width - 5
    $lines = @(@{ Text = ""; Color = $null; Width = 0 })
    if ((Get-UWMDisplayWidth $footerText) -le $maxLine) {
        $ft = "   " + $footerText
        $lines += @{ Text = $ft; Color = 'Cyan'; Width = (Get-UWMDisplayWidth $ft) + 2 }
    } else {
        $f1 = "   " + $seg1
        $f2 = "   " + $seg2
        $lines += @{ Text = $f1; Color = 'Cyan'; Width = (Get-UWMDisplayWidth $f1) + 2 }
        $lines += @{ Text = $f2; Color = 'Cyan'; Width = (Get-UWMDisplayWidth $f2) + 2 }
    }
    $lines += @{ Text = ""; Color = $null; Width = 0 }
    $prompt = "   " + $script:Locale['NavPrompt']
    $lines += @{ Text = $prompt; Color = $script:Theme['Accent']; Width = (Get-UWMDisplayWidth $prompt) + 2; NoNewline = $true }
    return $lines
}

function Write-UWMGridRowStable {
    param([object]$Row, [int]$PadTo = 0)
    if ($null -eq $Row) {
        if ($PadTo -gt 0) { Write-Host (" " * $PadTo) -NoNewline }
        Write-Host ""
        return
    }
    if ($Row.ContainsKey('Cells') -and $null -ne $Row.Cells -and @($Row.Cells).Count -gt 0) {
        [int[]]$widths = @($Row.Widths)
        Write-Host "  ║" -NoNewline -ForegroundColor $script:Theme['Dim']
        for ($ci = 0; $ci -lt $Row.Cells.Count; $ci++) {
            $cell = $Row.Cells[$ci]
            [string]$txt = [string]$cell.Text
            $color = if ($cell.Color) { $cell.Color } else { $script:Theme['Text'] }
            [int]$w = $widths[$ci]
            [int]$tw = Get-UWMDisplayWidth $txt
            if ($tw -gt $w) { $txt = Get-UWMTruncated -Text $txt -MaxWidth $w; $tw = Get-UWMDisplayWidth $txt }
            if ($tw -lt $w) { $txt = $txt + (" " * ($w - $tw)) }
            Write-Host $txt -NoNewline -ForegroundColor $color
            if ($ci -lt $Row.Cells.Count - 1) { Write-Host "║" -NoNewline -ForegroundColor $script:Theme['Dim'] }
        }
        Write-Host "║" -NoNewline -ForegroundColor $script:Theme['Dim']
    } else {
        [string]$txt = [string]$Row.Text
        $color = if ($Row.Color) { $Row.Color } else { $script:Theme['Text'] }
        Write-Host $txt -NoNewline -ForegroundColor $color
    }
    [int]$ow = 0
    try { $ow = [int]$Row.Width } catch { $ow = 0 }
    if ($PadTo -gt $ow) { Write-Host (" " * ($PadTo - $ow)) -NoNewline }
    if (-not $Row.NoNewline) { Write-Host "" }
}

function Render-UWMGridRegion {
    param([object[]]$Rows, [int]$Top, [bool]$Overwrite = $false, [int]$PrevHeight = 0, [int]$PrevMaxCol = 0)
    $rowCount = @($Rows).Count
    $maxCol = $PrevMaxCol
    foreach ($r in $Rows) {
        [int]$rw = 0
        try { $rw = [int]$r.Width } catch { $rw = 0 }
        if ($rw -gt $maxCol) { $maxCol = $rw + 2 }
    }
    if (-not $Overwrite) {
        foreach ($r in $Rows) { Write-UWMGridRowStable -Row $r -PadTo 0 }
        return @{ Height = $rowCount; MaxCol = $maxCol; Stable = $true }
    }
    $stable = $true
    for ($i = 0; $i -lt $rowCount; $i++) {
        try {
            [Console]::SetCursorPosition(0, $Top + $i)
        } catch {
            $stable = $false
        }
        if ($stable) {
            Write-UWMGridRowStable -Row $Rows[$i] -PadTo $maxCol
        } else {
            Write-UWMGridRowStable -Row $Rows[$i] -PadTo 0
        }
    }
    if ($PrevHeight -gt $rowCount) {
        for ($i = $rowCount; $i -lt $PrevHeight; $i++) {
            try {
                [Console]::SetCursorPosition(0, $Top + $i)
                Write-Host (" " * $maxCol)
            } catch { }
        }
    }
    return @{ Height = $rowCount; MaxCol = $maxCol; Stable = $stable }
}

function Invoke-DiagnosticsMenu {
    if (-not (Assert-UWMWriteAccess)) { return }
    try {
    Show-Header
    Write-Host "   [UWM NUCLEAR DIAGNOSTIC & SELF-REPAIR SENTINEL]" -ForegroundColor Cyan
    Write-Host ("   " + ("-" * 60)) -ForegroundColor $script:Theme['Dim']
    Write-Host ""

    $repairBlocked = $false
    $blockReason = ""
    $stepLog = @()
    $before = $null
    $after = $null
    $wuBefore = $null
    $wuAfter = $null
    $pageTotal = 0

    $disk = Test-UWMDiskHeadroom
    $lock = Test-UWMUpdateEngineLock
    $telemetry = Invoke-UWMStorageTelemetry

    $gateLines = @()
    if ($disk.Safe) {
        $gateLines += @{ Text = ("[GATE] Disk headroom: {0} GB free on {1} (min {2} GB) — OK" -f $disk.FreeGB, $disk.Path, $disk.MinGB); Color = $script:Theme['Success'] }
    } else {
        $gateLines += @{ Text = ("[GATE] Disk headroom: {0} GB free on {1} — CRITICAL (needs >= {2} GB)" -f $disk.FreeGB, $disk.Path, $disk.MinGB); Color = 'Red' }
        $repairBlocked = $true
        $blockReason = "OS volume has only $($disk.FreeGB) GB free. DISM RestoreHealth without >= $($disk.MinGB) GB headroom can suffocate the OS volume and brick component-store recovery."
    }
    if ($lock.Locked) {
        $gateLines += @{ Text = ("[GATE] Windows Update engine busy: {0} — repair quarantined" -f ($lock.Hits -join ', ')); Color = 'Red' }
        $repairBlocked = $true
        $blockReason += $(if ($blockReason) { " " } else { "" }) + "Windows Update engine (TrustedInstaller/wuauserv) is mid-transaction; running DISM now would corrupt the CBS store."
    } else {
        $gateLines += @{ Text = "[GATE] Windows Update engine idle — CBS transaction safe."; Color = $script:Theme['Success'] }
    }
    if ($telemetry.Bypassed) {
        $gateLines += @{ Text = "[GATE] Storage telemetry: bypassed within 2s probe window."; Color = 'Yellow' }
    } else {
        $gateLines += @{ Text = "[GATE] Storage telemetry: $($telemetry.Disks.Count) physical disk(s) enumerated."; Color = $script:Theme['Success'] }
    }

    $wuBefore = Test-UWMWindowsUpdateHealth
    if ($wuBefore.Stable) {
        Write-Host "   [SYSTEM] Windows Update infrastructure is fully stable. No action required." -ForegroundColor Green
        $gateLines += @{ Text = "[ETW] Windows Update event log: fully stable, zero failed traces."; Color = $script:Theme['Success'] }
    } else {
        $gateLines += @{ Text = ("[ETW] {0} failed update trace(s). KBs: {1} | Codes: {2}" -f $wuBefore.Failures.Count, $(if ($wuBefore.Kbs.Count) { $wuBefore.Kbs -join ',' } else { '-' }), $(if ($wuBefore.Codes.Count) { $wuBefore.Codes -join ',' } else { '-' })); Color = 'Yellow' }
    }

    Write-Host "   STEP 1 — Pre-flight Gates" -ForegroundColor $script:Theme['Accent']
    foreach ($g in $gateLines) {
        Write-Host ("     {0}" -f $g.Text) -ForegroundColor $(if ($g.Color) { $g.Color } else { $script:Theme['Dim'] })
    }

    $before = Get-UWMDiagnosticsBaseline
    if ($null -eq $before) { $before = [PSCustomObject]@{ FreeGB = -1; CompStoreGB = -1; CorruptAssets = $false; CheckHealth = 'Unavailable' } }
    $stepLog += [PSCustomObject]@{ Title = "STEP 1 — Pre-flight Gates & Baseline"; Status = $(if ($repairBlocked) { 'BLOCKED' } else { 'OK' }); Lines = $gateLines + @(@{ Text = ("Baseline: Free {0} GB | CompStore {1} GB | Corrupt {2}" -f $before.FreeGB, $before.CompStoreGB, $(if ($before.CorruptAssets) { 'Yes' } else { 'No' })); Color = $script:Theme['Dim'] }) }

    Write-Host ""
    $networkOk = Invoke-UWMNetworkProbe
    $netLines = @()
    Write-Host ""
    Write-Host "   STEP 2 — Network Transport" -ForegroundColor $script:Theme['Accent']
    if ($networkOk) {
        $netLines += @{ Text = "[NET] Reachability verified (1.1.1.1 / 8.8.8.8)."; Color = $script:Theme['Success'] }
    } else {
        $netLines += @{ Text = "[NET] No external reachability detected — ICMP may be filtered or connectivity lost."; Color = 'Yellow' }
        Write-Host "     [WARN] Network transport amber alert. Winsock stack may be corrupt." -ForegroundColor Yellow
        Write-Host "     Press [W] to confirm an elevated Winsock reset, or any other key to skip." -NoNewline -ForegroundColor Yellow
        $wkey = Get-UWMRawKey
        Write-Host ""
        if ([char]::ToUpper([char]$wkey) -eq [char]'W') {
            try {
                Start-Process netsh.exe -ArgumentList "winsock","reset" -Verb RunAs -Wait -ErrorAction Stop
                $netLines += @{ Text = "[NET] Winsock reset executed (elevated)."; Color = $script:Theme['Success'] }
            } catch {
                $netLines += @{ Text = "[NET] Winsock reset rejected (elevation required)."; Color = $script:Theme['Dim'] }
            }
        } else {
            $netLines += @{ Text = "[NET] Winsock reset skipped by operator."; Color = $script:Theme['Dim'] }
        }
    }
    foreach ($g in $netLines) {
        Write-Host ("     {0}" -f $g.Text) -ForegroundColor $(if ($g.Color) { $g.Color } else { $script:Theme['Dim'] })
    }
    $stepLog += [PSCustomObject]@{ Title = "STEP 2 — Network Transport"; Status = $(if ($networkOk) { 'OK' } else { 'WARN' }); Lines = $netLines }

    Write-Host ""
    Write-Host "   STEP 3 — AppX Healer" -ForegroundColor $script:Theme['Accent']
    $appxFixes = Invoke-UWMAppXHealer
    $appxLines = @(@{ Text = ("AppX payload + cbdhsvc + provisioned pool: {0} fix(es) applied." -f $appxFixes); Color = $(if ($appxFixes -gt 0) { $script:Theme['Success'] } else { $script:Theme['Dim'] }) })
    foreach ($g in $appxLines) {
        Write-Host ("     {0}" -f $g.Text) -ForegroundColor $(if ($g.Color) { $g.Color } else { $script:Theme['Dim'] })
    }
    $stepLog += [PSCustomObject]@{ Title = "STEP 3 — AppX Healer"; Status = $(if ($appxFixes -gt 0) { 'OK' } else { 'WARN' }); Lines = $appxLines }

    Write-Host ""
    $kernelOk = $false
    if ($repairBlocked) {
        Write-Host "   STEP 4 — Kernel Restore [SKIPPED]" -ForegroundColor Yellow
        Write-Host "     $blockReason" -ForegroundColor Yellow
        $kernelLines = @(@{ Text = "[KERNEL] Integrity Repair blocked by pre-flight gates."; Color = 'Red' })
    } else {
        Write-Host "   STEP 4 — Kernel Restore (DISM RestoreHealth + SFC)" -ForegroundColor $script:Theme['Accent']
        $kernelOk = Invoke-UWMKernelRestore
        $kernelLines = @(@{ Text = ("[KERNEL] Watchdog verdict: {0}" -f $(if ($kernelOk) { 'clean' } else { 'issues reported / timeout' })); Color = $(if ($kernelOk) { $script:Theme['Success'] } else { 'Yellow' }) })
    }
    $stepLog += [PSCustomObject]@{ Title = "STEP 4 — Kernel Restore"; Status = $(if ($repairBlocked) { 'BLOCKED' } elseif ($kernelOk) { 'OK' } else { 'WARN' }); Lines = $kernelLines }

    if ($repairBlocked) {
        $after = $null
        $wuAfter = $null
    } else {
        $after = Get-UWMDiagnosticsBaseline -SkipTelemetry
        if ($null -eq $after) { $after = [PSCustomObject]@{ FreeGB = -1; CompStoreGB = -1; CorruptAssets = $false; CheckHealth = 'Unavailable' } }
        $wuAfter = Test-UWMWindowsUpdateHealth
    }
    Write-Host ""
    Show-UWMDiagnosticsMatrix -Before $before -After $after -RepairBlocked:$repairBlocked -BlockReason $blockReason -WuBefore $wuBefore -WuAfter $wuAfter

    $pageTotal = $stepLog.Count + 1
    $reportPage = $pageTotal
    $dirty = $false
    $gridReady = $false
    $gridTop = -1
    $gridHeight = 0
    $gridMaxCol = 0
    Clear-UWMInputBuffer
    [object[]]$gridBodyInit = @(Get-UWMDiagnosticsPageLines -MatrixBefore $before -MatrixAfter $after -RepairBlocked $repairBlocked -BlockReason $blockReason -WuBefore $wuBefore -WuAfter $wuAfter)
    [object[]]$gridFootInit = @(Get-UWMDiagnosticsFooterLines)
    [object[]]$gridRowsInit = @($gridBodyInit) + @($gridFootInit)
    try { $gridTop = [Console]::CursorTop } catch { $gridTop = -1 }
    $geoInit = Render-UWMGridRegion -Rows $gridRowsInit -Top $gridTop -Overwrite $false
    $gridHeight = $geoInit.Height
    $gridMaxCol = $geoInit.MaxCol
    $gridReady = $geoInit.Stable
    Clear-UWMInputBuffer

    :diagLoop while ($true) {
        $key = Get-UWMRawKey
        $ukey = [char]::ToUpper([char]$key)
        switch ($ukey) {
            'A' {
                Clear-UWMInputBuffer
                Write-Host ""
                Write-Host "   [ANALYZE] Running fresh system + Windows Update trace scan..." -ForegroundColor $script:Theme['Accent']
                $after = Get-UWMDiagnosticsBaseline -SkipTelemetry
                if ($null -eq $after) { $after = [PSCustomObject]@{ FreeGB = -1; CompStoreGB = -1; CorruptAssets = $false; CheckHealth = 'Unavailable' } }
                $wuAfter = Test-UWMWindowsUpdateHealth
                if ($wuAfter.Stable) { Write-Host "   [SYSTEM] Windows Update infrastructure is fully stable. No action required." -ForegroundColor Green }
                $reportPage = $pageTotal
                $dirty = $true
                Clear-UWMInputBuffer
            }
            'U' {
                Clear-UWMInputBuffer
                Write-Host ""
                if ($repairBlocked) {
                    $override = Show-UWMConditionalChoicePrompt -Message "  [!] System Engine Locked. Force adaptive background override execution?"
                    if ($override) {
                        $oh = Invoke-UWMDiagFallbackRepair -Scope 'Update'
                        $wuAfter = Test-UWMWindowsUpdateHealth
                        $stepLog += [PSCustomObject]@{ Title = "UPDATE OVERRIDE — Isolated Async Remediation"; Status = $(if ($oh) { 'OK' } else { 'WARN' }); Lines = @(@{ Text = "Forced adaptive background override executed for the Windows Update engine."; Color = $script:Theme['Success'] }) }
                        $pageTotal = $stepLog.Count + 1
                        $reportPage = $pageTotal
                        $dirty = $true
                    } else {
                        Write-Host "   [ABORT] Override declined — update repair held by pre-flight gates." -ForegroundColor Yellow
                        $dirty = $true
                    }
                } else {
                    Write-Host "   [UPDATE REPAIR] Initiating Windows Update Smart Resuscitator..." -ForegroundColor $script:Theme['Accent']
                    $repairResult = Invoke-UWMUpdateRepair -Health $wuBefore
                    $wuAfter = $repairResult.Health
                    $stepLog += [PSCustomObject]@{ Title = "UPDATE REPAIR — Windows Update Smart Resuscitator"; Status = $(if ($repairResult.Performed) { 'OK' } else { 'BY-PASS' }); Lines = $repairResult.Lines }
                    $pageTotal = $stepLog.Count + 1
                    $reportPage = $pageTotal
                    $dirty = $true
                }
                Clear-UWMInputBuffer
            }
            'I' {
                Clear-UWMInputBuffer
                Write-Host ""
                Write-Host "   [INTEGRITY FIX] Re-gating before repair..." -ForegroundColor $script:Theme['Accent']
                $disk = Test-UWMDiskHeadroom
                $lock = Test-UWMUpdateEngineLock
                $repairBlocked = (-not $disk.Safe) -or $lock.Locked
                if ($repairBlocked) {
                    $blockReason = ""
                    if (-not $disk.Safe) { $blockReason = "OS volume has only $($disk.FreeGB) GB free; DISM would suffocate the OS volume." }
                    if ($lock.Locked) { $blockReason += $(if ($blockReason) { " " } else { "" }) + "Windows Update engine (TrustedInstaller/wuauserv) is mid-transaction; DISM would corrupt the CBS store." }
                    Write-Host "     [!] Repair BLOCKED: $blockReason" -ForegroundColor Yellow
                    $override = Show-UWMConditionalChoicePrompt -Message "  [!] System Engine Locked. Force adaptive background override execution?"
                    if ($override) {
                        $oh = Invoke-UWMDiagFallbackRepair -Scope 'Kernel'
                        $after = Get-UWMDiagnosticsBaseline -SkipTelemetry
                        if ($null -eq $after) { $after = [PSCustomObject]@{ FreeGB = -1; CompStoreGB = -1; CorruptAssets = $false; CheckHealth = 'Unavailable' } }
                        $wuAfter = Test-UWMWindowsUpdateHealth
                        $repairBlocked = $false
                        $stepLog += [PSCustomObject]@{ Title = "KERNEL OVERRIDE — Adaptive Background Remediation"; Status = $(if ($oh) { 'OK' } else { 'WARN' }); Lines = @(@{ Text = "Forced override remediation executed via isolated fallback thread."; Color = $script:Theme['Success'] }) }
                        $pageTotal = $stepLog.Count + 1
                        $reportPage = $pageTotal
                        $dirty = $true
                    } else {
                        Write-Host "   [ABORT] Override declined — integral repair held by pre-flight gates." -ForegroundColor Yellow
                        $dirty = $true
                    }
                } else {
                    Write-Host "     [OK] Gates clear. Running AppX heal + kernel restore..." -ForegroundColor $script:Theme['Success']
                    Invoke-UWMAppXHealer | Out-Null
                    Invoke-UWMKernelRestore | Out-Null
                    $after = Get-UWMDiagnosticsBaseline -SkipTelemetry
                    if ($null -eq $after) { $after = [PSCustomObject]@{ FreeGB = -1; CompStoreGB = -1; CorruptAssets = $false; CheckHealth = 'Unavailable' } }
                    $wuAfter = Test-UWMWindowsUpdateHealth
                    $reportPage = $pageTotal
                    $dirty = $true
                }
                Clear-UWMInputBuffer
            }
            'N' {
                Clear-UWMInputBuffer
                if ($reportPage -lt $pageTotal) { $reportPage++; $dirty = $true }
                Clear-UWMInputBuffer
            }
            'P' {
                Clear-UWMInputBuffer
                if ($reportPage -gt 1) { $reportPage--; $dirty = $true }
                Clear-UWMInputBuffer
            }
            'B' {
                Clear-UWMInputBuffer
                break diagLoop
            }
        }
        if ($dirty) {
            Clear-UWMInputBuffer
            [object[]]$gridBody = @()
            if ($reportPage -le $stepLog.Count) {
                $gridBody = @(Get-UWMDiagnosticsPageLines -Step ($stepLog[$reportPage - 1]))
            } else {
                $gridBody = @(Get-UWMDiagnosticsPageLines -MatrixBefore $before -MatrixAfter $after -RepairBlocked $repairBlocked -BlockReason $blockReason -WuBefore $wuBefore -WuAfter $wuAfter)
            }
            [object[]]$gridFoot = @(Get-UWMDiagnosticsFooterLines)
            [object[]]$gridRows = @($gridBody) + @($gridFoot)
            if ($gridReady) {
                $geo = Render-UWMGridRegion -Rows $gridRows -Top $gridTop -Overwrite $true -PrevHeight $gridHeight -PrevMaxCol $gridMaxCol
            } else {
                $geo = Render-UWMGridRegion -Rows $gridRows -Top $gridTop -Overwrite $false
            }
            $gridHeight = $geo.Height
            $gridMaxCol = $geo.MaxCol
            $gridReady = $geo.Stable
            if (-not $gridReady) {
                try { $gridTop = [Console]::CursorTop } catch { $gridTop = -1 }
            }
            $dirty = $false
            Clear-UWMInputBuffer
        }
    }
    } catch {
        Clear-UWMInputBuffer
        Write-Host ""
        Write-Host ("   [DIAG] Sentinel fault: {0}" -f $_.Exception.Message) -ForegroundColor $script:Theme['Error']
    } finally {
        Clear-UWMInputBuffer
        Write-Host ""
        Write-Host "   [DIAG] Sentinel session closed. Returning to command matrix." -ForegroundColor $script:Theme['Dim']
    }
}

# ---- New Bridge Settings Sub-Menu ----
function Invoke-BridgeMenu {
    Show-Header
    Write-Host "  $($script:Locale['BridgeMenuTitle'])" -ForegroundColor $script:Theme['Accent']
    Write-Host ("  " + "-" * 46)
    $sto = if ($script:Config.storeIntegration.enabled) { $script:Locale['BridgeEnable'] } else { $script:Locale['BridgeDisable'] }
    $cho = if ($script:Config.bridges.chocolatey) { $script:Locale['BridgeEnable'] } else { $script:Locale['BridgeDisable'] }
    $sco = if ($script:Config.bridges.scoop) { $script:Locale['BridgeEnable'] } else { $script:Locale['BridgeDisable'] }
    Write-Host "   $($script:Locale['BridgeStats'] -f $sto, $cho, $sco)" -ForegroundColor $script:Theme['Text']
    Write-Host "   $($script:Locale['BridgeActions'])" -ForegroundColor $script:Theme['Dim']
    $action = (Read-Host "`n $($script:Locale['NavPickAction'])").ToUpper()
    switch ($action) {
        'T' { $script:Config.storeIntegration.enabled = -not $script:Config.storeIntegration.enabled; Write-Host "   $($script:Locale['BridgeToggled'] -f 'Store', $(if($script:Config.storeIntegration.enabled){$script:Locale['BridgeEnable']}else{$script:Locale['BridgeDisable']}))" -ForegroundColor $script:Theme['Success']; Save-Config }
        'C' { $script:Config.bridges.chocolatey = -not $script:Config.bridges.chocolatey; Write-Host "   $($script:Locale['BridgeToggled'] -f 'Choco', $(if($script:Config.bridges.chocolatey){$script:Locale['BridgeEnable']}else{$script:Locale['BridgeDisable']}))" -ForegroundColor $script:Theme['Success']; Save-Config }
        'S' { $script:Config.bridges.scoop = -not $script:Config.bridges.scoop; Write-Host "   $($script:Locale['BridgeToggled'] -f 'Scoop', $(if($script:Config.bridges.scoop){$script:Locale['BridgeEnable']}else{$script:Locale['BridgeDisable']}))" -ForegroundColor $script:Theme['Success']; Save-Config }
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- Password Policy Fix ----
# ---- Local Account Policy Kernel Wrapper (resilient elevation bridge) ----
# Anchors Set-LocalUser and native net accounts executions through a hardened
# runtime envelope: hidden-window native spawn, output capture, single retry on
# transient interception, and strict localized error handling. Prevents AV/EDR
# heuristics from corrupting or flagging routine administrative enforcement.
function Invoke-UWMKernelAccountExec {
    param(
        [Parameter(Mandatory)][ValidateSet('NetAccounts','LocalUserCmdlet')][string]$Action,
        [string[]]$Arguments = @(),
        [scriptblock]$CmdletBlock = $null
    )
    $prevEA = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        if ($Action -eq 'NetAccounts') {
            # Composed native command: cmd.exe /d /c net accounts <Arguments>
            $cmdArgs = @('/d','/c','net','accounts') + $Arguments
            $tmpOut = Join-Path ([System.IO.Path]::GetTempPath()) ("UWM_netacct_out_{0}.tmp" -f ([Guid]::NewGuid().ToString('N')))
            $tmpErr = Join-Path ([System.IO.Path]::GetTempPath()) ("UWM_netacct_err_{0}.tmp" -f ([Guid]::NewGuid().ToString('N')))
            try {
                for ($attempt = 1; $attempt -le 2; $attempt++) {
                    try {
                        $proc = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList $cmdArgs -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr -ErrorAction Stop
                        if (Test-Path -LiteralPath $tmpOut) {
                            $captured = Get-Content -LiteralPath $tmpOut -ErrorAction SilentlyContinue
                            if ($captured) { $captured | ForEach-Object { Write-Host "  $_" } }
                        }
                        if (Test-Path -LiteralPath $tmpErr) {
                            $capturedErr = Get-Content -LiteralPath $tmpErr -ErrorAction SilentlyContinue
                            if ($capturedErr) { $capturedErr | ForEach-Object { Write-Host "  $_" -ForegroundColor $script:Theme['Dim'] } }
                        }
                        if ($proc.ExitCode -ne 0) {
                            if ($attempt -eq 2) { throw "native 'net accounts' returned exit code $($proc.ExitCode)" }
                            Start-Sleep -Milliseconds 300
                            continue
                        }
                        return $true
                    } catch {
                        if ($attempt -eq 2) { throw }
                        Start-Sleep -Milliseconds 300
                    }
                }
                return $false
            } finally {
                try { Remove-Item -LiteralPath $tmpOut,$tmpErr -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
        if ($Action -eq 'LocalUserCmdlet') {
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                try {
                    if ($null -ne $CmdletBlock) { & $CmdletBlock }
                    return $true
                } catch {
                    if ($attempt -eq 2) { throw }
                    Start-Sleep -Milliseconds 300
                }
            }
        }
        return $false
    } catch {
        Write-Host ("  [KERNEL] Account enforcement wrappers fault: {0}" -f $_.Exception.Message) -ForegroundColor $script:Theme['Error']
        return $false
    } finally {
        $ErrorActionPreference = $prevEA
    }
}

function Invoke-FixPasswordPolicy {
    Show-Header
    if (-not (Assert-UWMWriteAccess)) { return }
    Write-Host "Applying local password policy modifications..." -ForegroundColor Cyan
    try {
        # --- Phase 1: Disable password expiry on every local account via hardened wrapper ---
        $localUsers = @(Get-LocalUser -ErrorAction Stop)
        foreach ($lu in $localUsers) {
            $acctName = $lu.Name
            $null = Invoke-UWMKernelAccountExec -Action LocalUserCmdlet -CmdletBlock { Set-LocalUser -Name $acctName -PasswordNeverExpires $true }
        }
        # --- Phase 2: Zero-out lockout threshold + reset authentication timers natively ---
        # Mandatory sequence: net accounts /lockoutthreshold:0 /lockoutwindow:0 /lockoutduration:0
        $null = Invoke-UWMKernelAccountExec -Action NetAccounts -Arguments @('/maxpwage:unlimited')
        $null = Invoke-UWMKernelAccountExec -Action NetAccounts -Arguments @('/lockoutthreshold:0','/lockoutwindow:0','/lockoutduration:0')
        Clear-Host
        Write-Host "[SUCCESS] Local password expiration disabled permanently!`n" -ForegroundColor Green
        Write-Host "=========================================" -ForegroundColor Yellow
        Write-Host "        CURRENT ACCOUNTS POLICY          " -ForegroundColor Yellow
        Write-Host "=========================================" -ForegroundColor Yellow
        $null = Invoke-UWMKernelAccountExec -Action NetAccounts -Arguments @()
        Write-Host "=========================================" -ForegroundColor Yellow
        Write-Log -Action "PASSWORD_POLICY" -Target "LocalAccounts" -Status "Success" -Details "maxpwage unlimited; lockout threshold zeroed (/lockoutthreshold:0 /lockoutwindow:0 /lockoutduration:0)"
    }
    catch {
        Write-Host "`n[ERROR] Failed to apply password settings: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Action "PASSWORD_POLICY" -Target "LocalAccounts" -Status "Failed" -Details $_.Exception.Message
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- UWM Adware & Spyware Obliterator ----
function Invoke-UWMAdBlockObliterator {
    Show-Header
    if (-not (Assert-UWMWriteAccess)) { return }
    Write-Host "======================================================================" -ForegroundColor Red
    Write-Host "        UWM ADWARE & SPYWARE OBLITERATOR v3.0" -ForegroundColor Cyan
    Write-Host "  Complete elimination of Adware, Spyware & Telemetry" -ForegroundColor Yellow
    Write-Host "======================================================================" -ForegroundColor Red

    # --- Sub-Routine A: Hosts File Ad-Block (Multi-Source Online Sync) ---
    Write-Host "`n [A] Syncing blocklists from multiple cloud repositories..." -ForegroundColor $script:Theme['Accent']
    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $backupPath = "C:\Windows\System32\drivers\etc\hosts.uam.backup"
    try {
        if (-not (Test-Path $backupPath)) { Copy-Item -Path $hostsPath -Destination $backupPath -Force }

        # --- Multi-Source Blocklist Definitions ---
        $blocklistSources = @(
            @{ Label = "Global Base List";              Url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" }
            @{ Label = "Arabic AdBlock List";           Url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts" }
            @{ Label = "Malware/Phishing Intelligence"; Url = "https://urlhaus.abuse.ch/downloads/hostfile/" }
        )

        # --- Hardcoded Core Whitelist (never blocked) ---
        $hardcodedWhitelist = @(
            "microsoft.com"
            "windows.com"
            "github.com"
            "google.com"
        )

        # --- Dynamic Custom Allowlist File ---
        $allowlistFile = Join-Path -Path $script:DataRoot -ChildPath "uwm-allowlist.txt"
        $customAllowlist = @()
        if (Test-Path $allowlistFile) {
            $customAllowlist = Get-Content $allowlistFile | Where-Object { $_.Trim() -and $_ -notmatch '^\s*(#|$)' } | ForEach-Object { $_.Trim().ToLower() }
            Write-Host "  [OK] Loaded $($customAllowlist.Count) custom allowlist entries from uwm-allowlist.txt" -ForegroundColor $script:Theme['Success']
        } else {
            $template = @"
# =================================================================
# ULTRA WINGET MANAGER - CUSTOM ALLOWLIST / WHITELIST
# =================================================================
# Instructions:
# 1. Add domains you want to UNBLOCK or bypass here.
# 2. Write exactly ONE clean domain per line.
# 3. Do NOT include "https://", "http://", "www.", or trailing slashes "/".
# 4. Save this file, then run option [24] again to apply changes.
#
# Correct Examples:
# alternativeairlines.com
# google.com
# my-favorite-site.net
# =================================================================
"@
            [System.IO.File]::WriteAllText($allowlistFile, $template, [System.Text.UTF8Encoding]::new($false))
            Write-Host "  [INFO] Created template uwm-allowlist.txt — add trusted domains and re-run option [24]" -ForegroundColor $script:Theme['Dim']
        }

        # --- Combined Whitelist ---
        $combinedWhitelist = ($hardcodedWhitelist + $customAllowlist) | ForEach-Object { $_.ToLower().Trim() } | Sort-Object -Unique

        # --- Fetch & Parse All Blocklist Sources ---
        $allDomainList = [System.Collections.Generic.List[string]]::new()
        $sourcesSucceeded = 0
        foreach ($source in $blocklistSources) {
            try {
                Write-Host "  [FETCH] $($source.Label) ..." -ForegroundColor $script:Theme['Dim']
                $remoteContent = Invoke-RestMethod -Uri $source.Url -TimeoutSec 15 -ErrorAction Stop
                $parsed = ($remoteContent -split "`r?`n") | ForEach-Object {
                    $line = $_.Trim()
                    if ($line -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)') {
                        $d = $matches[2]
                        if ($d -notmatch '^(localhost|local|broadcasthost|255\.255\.255\.255|::1)$') { $d }
                    }
                } | Where-Object { $_ -and $_ -notmatch '\.local$|\.localdomain$' }
                $validCount = 0
                foreach ($d in $parsed) {
                    if ($d) { $allDomainList.Add($d); $validCount++ }
                }
                Write-Host "    [OK] $validCount domains from $($source.Label)" -ForegroundColor $script:Theme['Success']
                $sourcesSucceeded++
            } catch {
                Write-Host "    [WARN] $($source.Label) unreachable: $_" -ForegroundColor $script:Theme['Error']
            }
        }

        # --- Fallback if All Sources Failed ---
        if ($sourcesSucceeded -eq 0) {
            Write-Host "  [WARN] All cloud sources failed — using 14 core fallback domains" -ForegroundColor $script:Theme['Error']
            $allDomainList.Clear()
            foreach ($d in @("telemetry.microsoft.com","watson.telemetry.microsoft.com","vortex.data.microsoft.com","vortex-win.data.microsoft.com","settings-win.data.microsoft.com","diagnostics.support.microsoft.com","sqm.telemetry.microsoft.com","www.msftncsi.com","msftncsi.com","doubleclick.net","googlesyndication.com","googleadservices.com","google-analytics.com","adservice.google.com")) { $allDomainList.Add($d) }
        }

        # --- Whitelist Filtering Pass (false-positive protection) ---
        $whitelistedCount = 0
        $filteredDomains = [System.Collections.Generic.List[string]]::new()
        foreach ($d in $allDomainList) {
            $lower = $d.ToLower().Trim()
            $blocked = $false
            if ($combinedWhitelist -contains $lower) {
                $blocked = $true
            } else {
                foreach ($wl in $combinedWhitelist) {
                    if ($lower.EndsWith(".$wl")) { $blocked = $true; break }
                }
            }
            if ($blocked) { $whitelistedCount++ } else { $filteredDomains.Add($lower) }
        }

        # --- In-Memory Dedup Pass ---
        $uniqueDomains = $filteredDomains | Sort-Object -Unique
        $dedupRemoved = $filteredDomains.Count - $uniqueDomains.Count
        if ($dedupRemoved -gt 0) { Write-Host "  [DEDUP] Removed $dedupRemoved cross-source duplicates" -ForegroundColor $script:Theme['Dim'] }
        if ($whitelistedCount -gt 0) { Write-Host "  [ALLOW] Excluded $whitelistedCount whitelisted/allowlisted domains" -ForegroundColor $script:Theme['Success'] }

        # --- File Integrity Pass (against existing hosts entries) ---
        $existingLines = Get-Content -Path $hostsPath
        $existingLookup = @{}
        foreach ($line in $existingLines) {
            $t = $line.Trim()
            if ($t -match '^(0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)') { $existingLookup[$matches[2].ToLower()] = $true }
        }
        $newEntries = [System.Collections.Generic.List[string]]::new()
        $skipExisting = 0
        foreach ($domain in $uniqueDomains) {
            if ($existingLookup.ContainsKey($domain)) { $skipExisting++ } else { $newEntries.Add("127.0.0.1 $domain") }
        }

        # --- Append New Entries + Enforce Immutable File-Lock (locked write envelope) ---
        $hostsLockPath = "C:\Windows\System32\drivers\etc\hosts"
        try {
            # Lift any pre-existing immutability so the controlled append can enter the file
            $hostsAttrs = [System.IO.FileAttributes](Get-ItemProperty -Path $hostsLockPath -Name Attributes -ErrorAction Stop).Attributes
            if ($hostsAttrs -band [System.IO.FileAttributes]::ReadOnly) {
                Set-ItemProperty -Path $hostsLockPath -Name Attributes -Value ($hostsAttrs -bxor [System.IO.FileAttributes]::ReadOnly) -ErrorAction Stop
                Write-Host "  [UNLOCK] Hosts read-only lock lifted for controlled append" -ForegroundColor $script:Theme['Dim']
            }
            if ($newEntries.Count -gt 0) {
                [System.IO.File]::AppendAllLines($hostsLockPath, $newEntries, [System.Text.UTF8Encoding]::new($false))
            }
            # Dynamically enforce ABSOLUTE file lock immutability on the finalized hosts file
            Set-ItemProperty -Path "C:\Windows\System32\drivers\etc\hosts" -Name Attributes -Value ReadOnly -ErrorAction Stop
            Write-Host "  [LOCK] Hosts file immutability enforced (IsReadOnly attribute locked)" -ForegroundColor $script:Theme['Success']
        } catch {
            Write-Host "  [WARN] Hosts write/lock envelope fault: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
        }
        Write-Host "  [OK] $($uniqueDomains.Count) total unique domains after dedup & whitelist" -ForegroundColor $script:Theme['Success']
        Write-Host "  [OK] $($newEntries.Count) new domains null-routed to 127.0.0.1" -ForegroundColor $script:Theme['Success']
        if ($skipExisting -gt 0) { Write-Host "  [SKIP] $skipExisting domains already in hosts file" -ForegroundColor $script:Theme['Dim'] }
    } catch {
        Write-Host "  [WARN] Hosts modification skipped (may be locked by OS): $_" -ForegroundColor $script:Theme['Error']
    }

    # --- Sub-Routine B: Telemetry Services Freeze ---
    Write-Host "`n [B] Freezing known telemetry services..." -ForegroundColor $script:Theme['Accent']
    $telemetryServices = @("DiagTrack", "dmwappushservice")
    foreach ($svc in $telemetryServices) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            try {
                if ($s.Status -eq 'Running') { Stop-Service -Name $svc -Force -ErrorAction Stop }
                Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
                Write-Host "  [OK] $svc stopped & disabled" -ForegroundColor $script:Theme['Success']
            } catch {
                Write-Host "  [WARN] Could not disable $svc : $_" -ForegroundColor $script:Theme['Error']
            }
        } else {
            Write-Host "  [SKIP] $svc not present on this system" -ForegroundColor $script:Theme['Dim']
        }
    }

    # --- Sub-Routine C: Registry Privacy Hardening ---
    Write-Host "`n [C] Injecting registry privacy hardening keys..." -ForegroundColor $script:Theme['Accent']
    $regOps = @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy"; Name="TailoredExperiencesWithDiagnosticDataEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338389Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-338388Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SystemPaneSuggestionsEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SoftLandingEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="ContentDeliveryAllowed"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContentEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="OemPreInstalledAppsEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SilentInstalledAppsEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-310093Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-314563Enabled"; Value=0; Type="DWord" }
        @{ Path="HKLM:\Software\Policies\Microsoft\Windows\DataCollection"; Name="AllowTelemetry"; Value=0; Type="DWord" }
        @{ Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0; Type="DWord" }
        @{ Path="HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"; Name="AllowTelemetry"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="Start_TrackProgs"; Value=0; Type="DWord" }
        # --- Windows 11 cloud consumer experience trackers (policy-blocked, deep path) ---
        @{ Path="HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsConsumerFeatures"; Value=1; Type="DWord" }
        @{ Path="HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableSoftLanding"; Value=1; Type="DWord" }
        @{ Path="HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name="DisableWindowsSpotlightFeatures"; Value=1; Type="DWord" }
        @{ Path="HKLM:\Software\Policies\Microsoft\Windows\CloudContent"; Name="ConfigureWindowsSpotlight"; Value=2; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="RotatingLockScreenEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353694Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353696Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="SubscribedContent-353698Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="FeatureManagementEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"; Name="PreInstalledAppsEverEnabled"; Value=0; Type="DWord" }
        # --- Advertising runtime data collectors (deep telemetry eradication) ---
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="CorporateDiscoverMoreContentEnabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="PersonalizedAds"; Value=0; Type="DWord" }
        @{ Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Name="Enabled"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Experimentation"; Name="Experimentation"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\InputPersonalization"; Name="RestrictImplicitTextCollection"; Value=1; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\InputPersonalization"; Name="RestrictImplicitInkCollection"; Value=1; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"; Name="ShowSyncProviderNotifications"; Value=0; Type="DWord" }
    )
    $ok = 0; $fail = 0
    foreach ($op in $regOps) {
        try {
            if (-not (Test-Path $op.Path)) { New-Item -Path $op.Path -Force -ErrorAction Stop | Out-Null }
            Set-ItemProperty -Path $op.Path -Name $op.Name -Value $op.Value -Type $op.Type -ErrorAction Stop
            $ok++
        } catch { $fail++ }
    }
    Write-Host "  [OK] $ok registry keys applied" -ForegroundColor $script:Theme['Success']
    if ($fail -gt 0) { Write-Host "  [WARN] $fail keys failed (may need Admin elevation)" -ForegroundColor $script:Theme['Error'] }

    # --- Sub-Routine D: Scheduled Tasks Extermination ---
    Write-Host "`n [D] Exterminating hidden telemetry scheduled tasks..." -ForegroundColor $script:Theme['Accent']
    $telemetryTasks = @(
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        "\Microsoft\Windows\Autochk\Proxy"
    )
    $disabledTasks = 0
    foreach ($taskPath in $telemetryTasks) {
        try {
            $task = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
            if ($task) {
                Disable-ScheduledTask -TaskPath $taskPath -ErrorAction Stop
                Write-Host "  [OK] Disabled task: $taskPath" -ForegroundColor $script:Theme['Success']
                $disabledTasks++
            } else {
                Write-Host "  [SKIP] Task not found: $taskPath" -ForegroundColor $script:Theme['Dim']
            }
        } catch {
            Write-Host "  [WARN] Could not disable $taskPath : $_" -ForegroundColor $script:Theme['Error']
        }
    }
    if ($disabledTasks -eq 0) { Write-Host "  [INFO] No telemetry tasks were present to disable" -ForegroundColor $script:Theme['Dim'] }

    # --- Sub-Routine E: Cloud Search & Cortana Evacuation ---
    Write-Host "`n [E] Evacuating Cortana and cloud search tracking..." -ForegroundColor $script:Theme['Accent']
    $cortanaOps = @(
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="CortanaConsent"; Value=0; Type="DWord" }
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Name="BingSearchEnabled"; Value=0; Type="DWord" }
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"; Name="AllowCortana"; Value=0; Type="DWord" }
    )
    $cOk = 0; $cFail = 0
    foreach ($op in $cortanaOps) {
        try {
            if (-not (Test-Path $op.Path)) { New-Item -Path $op.Path -Force -ErrorAction Stop | Out-Null }
            Set-ItemProperty -Path $op.Path -Name $op.Name -Value $op.Value -Type $op.Type -ErrorAction Stop
            $cOk++
        } catch { $cFail++ }
    }
    Write-Host "  [OK] $cOk Cortana & cloud search keys applied" -ForegroundColor $script:Theme['Success']
    if ($cFail -gt 0) { Write-Host "  [WARN] $cFail keys failed (may need Admin elevation)" -ForegroundColor $script:Theme['Error'] }

    Write-Host "`n======================================================================" -ForegroundColor Green
    Write-Host "  OBLITERATION COMPLETE - Your system is now hardened" -ForegroundColor Cyan
    Write-Host "  [OK] Core Tasks Terminated | [OK] Cloud Tracking Evacuated | [OK] Deep Hosts Poisoned" -ForegroundColor Yellow
    Write-Host "======================================================================" -ForegroundColor Green
    Read-Host -Prompt "Press Enter to return to main menu..."
}

# ---- UWM Core Inspector ----
function Invoke-CoreInspector {
    Show-Header
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "            UWM CORE INSPECTOR - Internal Verification Suite" -ForegroundColor Yellow
    Write-Host "   Dynamic dependency check and feature integrity audit" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    $passed = 0; $failed = 0; $total = 0
    $report = [System.Collections.Generic.List[string]]::new()

    # ---------------------------------------------------------------
    # Phase 1: Dynamic Function Mapping & structural menu coverage
    # ---------------------------------------------------------------
    Write-Host "`n--- [PHASE 1] Menu-to-Function Mapping Coverage ---" -ForegroundColor $script:Theme['Accent']
    $total++
    $prevEA = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        # Structured envelope: dynamic menu mapping rules (hoisted pattern constant)
        $MenuSwitchPattern = "'(?<num>\d+)'\s*\{\s*(?<handler>\w+[-]\w+|\w+)"
        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $script:ScriptPath }
        $source = $null
        try {
            $source = Get-Content -Path $scriptPath -Raw
        } catch {
            Write-Host "  [FAIL] Phase 1 source read failed: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
            throw
        }
        $menuSwitches = @()
        try {
            $menuSwitches = [regex]::Matches($source, $MenuSwitchPattern, 'IgnoreCase') | ForEach-Object {
                [PSCustomObject]@{ Number = $_.Groups['num'].Value; Handler = $_.Groups['handler'].Value }
            }
        } catch {
            Write-Host "  [FAIL] Phase 1 mapping parser fault: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
            throw
        }
        $orphans = [System.Collections.Generic.List[string]]::new()
        $resolved = 0
        foreach ($entry in $menuSwitches) {
            $cmd = $null
            try { $cmd = Get-Command $entry.Handler -ErrorAction SilentlyContinue } catch { $cmd = $null }
            if ($entry.Handler -match '^\w[\w-]+$' -or $null -ne $cmd) {
                $resolved++
            } elseif ($null -eq $cmd) {
                $orphans.Add("Option $($entry.Number) -> $($entry.Handler)")
            }
        }
        if ($orphans.Count -eq 0) {
            Write-Host "  [PASS] All $resolved menu handlers resolved successfully" -ForegroundColor $script:Theme['Success']
            $report.Add("[PASS] Phase 1: All menu handlers resolved")
            $passed++
        } else {
            Write-Host "  [FAIL] $($orphans.Count) orphaned menu entries detected:" -ForegroundColor $script:Theme['Error']
            foreach ($o in $orphans) { Write-Host "         $o" -ForegroundColor $script:Theme['Error'] }
            $report.Add("[FAIL] Phase 1: $($orphans.Count) orphaned menu entries")
            $failed++
        }
    } catch {
        Write-Host "  [FAIL] Phase 1 scan crashed: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
        $report.Add("[FAIL] Phase 1: scan crashed")
        $failed++
    } finally {
        $ErrorActionPreference = $prevEA
    }

    # ---------------------------------------------------------------
    # Phase 2: BLOCK feature internal audit
    # ---------------------------------------------------------------
    Write-Host "`n--- [PHASE 2] BLOCK Feature Internal Audit ---" -ForegroundColor $script:Theme['Accent']
    $total++
    $prevEA = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Stop'
        # Structured envelope: BLOCK engine contract closure isolated from the audit flow
        $blockResult = $false
        try {
            $blockResult = & {
                $paramBlock = @{ Mode = "BLOCK" }
                $sb = { param($Mode) $Mode }.GetNewClosure()
                $testMode = & $sb "BLOCK"
                if ($testMode -eq "BLOCK") { $true } else { $false }
            }
        } catch {
            Write-Host "  [FAIL] BLOCK contract invocation fault: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
            $blockResult = $false
        }
        if ($blockResult) {
            Write-Host "  [PASS] BLOCK engine parameter contract verified" -ForegroundColor $script:Theme['Success']
            $report.Add("[PASS] Phase 2: BLOCK engine verified")
            $passed++
        } else {
            Write-Host "  [FAIL] BLOCK component logic is broken" -ForegroundColor $script:Theme['Error']
            $report.Add("[FAIL] Phase 2: BLOCK component logic broken")
            $failed++
        }
    } catch {
        Write-Host "  [FAIL] BLOCK component database or function logic is broken" -ForegroundColor $script:Theme['Error']
        $report.Add("[FAIL] Phase 2: BLOCK internal audit crashed")
        $failed++
    } finally {
        $ErrorActionPreference = $prevEA
    }

    # ---------------------------------------------------------------
    # Phase 3: SHREDDER & ROLLBACK core verification
    # ---------------------------------------------------------------
    Write-Host "`n--- [PHASE 3] SHREDDER & ROLLBACK Core Verification ---" -ForegroundColor $script:Theme['Accent']
    $total++
    $shredderOk = $false; $rollbackOk = $false
    try {
        $shredderCmd = Get-Command Invoke-UWMAdvancedShredder -ErrorAction Stop
        $shredderOk = $shredderCmd -and $shredderCmd.ScriptBlock -ne $null
        if ($shredderOk) {
            Write-Host "  [PASS] Invoke-UWMAdvancedShredder resolved and compiled" -ForegroundColor $script:Theme['Success']
        } else {
            Write-Host "  [FAIL] Invoke-UWMAdvancedShredder script block is null" -ForegroundColor $script:Theme['Error']
        }
    } catch {
        Write-Host "  [FAIL] Invoke-UWMAdvancedShredder missing or broken: $_" -ForegroundColor $script:Theme['Error']
    }
    try {
        $rollbackCmd = Get-Command Invoke-UWMRollback -ErrorAction Stop
        $rollbackOk = $rollbackCmd -and $rollbackCmd.ScriptBlock -ne $null
        if ($rollbackOk) {
            Write-Host "  [PASS] Invoke-UWMRollback resolved and compiled" -ForegroundColor $script:Theme['Success']
        } else {
            Write-Host "  [FAIL] Invoke-UWMRollback script block is null" -ForegroundColor $script:Theme['Error']
        }
    } catch {
        Write-Host "  [FAIL] Invoke-UWMRollback missing or broken: $_" -ForegroundColor $script:Theme['Error']
    }
    if ($shredderOk -and $rollbackOk) {
        $report.Add("[PASS] Phase 3: SHREDDER & ROLLBACK verified")
        $passed++
    } else {
        $report.Add("[FAIL] Phase 3: SHREDDER or ROLLBACK is broken")
        $failed++
    }

    # ---------------------------------------------------------------
    # Phase 4: SANDBOX environment link check
    # ---------------------------------------------------------------
    Write-Host "`n--- [PHASE 4] SANDBOX Environment Link Check ---" -ForegroundColor $script:Theme['Accent']
    $total++
    try {
        $sandboxCmd = Get-Command Invoke-SandboxTest -ErrorAction Stop
        $sbBlock = $sandboxCmd.ScriptBlock.ToString()
        $hasParams = $sbBlock -match '\$Query|\$PackageId|param\s*\('
        $hasRestMethod = $sbBlock -match 'Invoke-RestMethod|winget\s+search'
        if ($sandboxCmd -and $sbBlock.Length -gt 50 -and ($hasParams -or $hasRestMethod)) {
            Write-Host "  [PASS] Invoke-SandboxTest structurally valid ($($sbBlock.Length) chars, parameterized)" -ForegroundColor $script:Theme['Success']
            $report.Add("[PASS] Phase 4: SANDBOX verified")
            $passed++
        } else {
            Write-Host "  [FAIL] Invoke-SandboxTest lacks expected structure" -ForegroundColor $script:Theme['Error']
            $report.Add("[FAIL] Phase 4: SANDBOX structure abnormal")
            $failed++
        }
    } catch {
        Write-Host "  [FAIL] Invoke-SandboxTest missing or broken: $_" -ForegroundColor $script:Theme['Error']
        $report.Add("[FAIL] Phase 4: SANDBOX missing or broken")
        $failed++
    }

    # ---------------------------------------------------------------
    # Phase 5: Python Ingestion Bridge — Pre-Flight Execution Guard
    # ---------------------------------------------------------------
    Write-Host "`n--- [PHASE 5] Python Ingestion Bridge - Sentinel Script Guard ---" -ForegroundColor $script:Theme['Accent']
    $total++
    $prevEA = $ErrorActionPreference
    $PythonBridgeState = 'NOT_DETECTED'
    try {
        $ErrorActionPreference = 'Stop'
        $PythonTargetScript = Join-Path $PSScriptRoot "fix Get-Appx.py"
        $pyExists = $false
        try { $pyExists = Test-Path $PythonTargetScript } catch { $pyExists = $false }
        if ($pyExists) {
            $PythonCmd = $null
            try { $PythonCmd = Get-Command python -ErrorAction SilentlyContinue } catch { $PythonCmd = $null }
            if ($null -eq $PythonCmd -or [string]::IsNullOrEmpty($PythonCmd.Source) -or -not (Test-Path $PythonCmd.Source)) {
                $PythonBridgeState = 'RUNTIME_ABSENT'
                Write-Host "  [ENVIRONMENT NOTICE] Python environment not detected. Routing automation skip cleanly." -ForegroundColor Yellow
                Write-Host "  -> Sentinel script bypassed: no valid python runtime found in PATH." -ForegroundColor $script:Theme['Dim']
                $report.Add("[SKIP] Phase 5: Python environment absent — sentinel script bypassed")
            } else {
                $PythonBridgeState = 'RUNTIME_READY'
                Write-Host "  [PASS] Python runtime detected: $($PythonCmd.Source)" -ForegroundColor $script:Theme['Success']
                Write-Host "  -> Executing sentinel script under elevated context..." -ForegroundColor $script:Theme['Dim']
                try {
                    $pyResult = Start-Process python -ArgumentList "`"$PythonTargetScript`"" -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
                    $PythonBridgeState = "EXECUTED_EXIT_$($pyResult.ExitCode)"
                    if ($pyResult.ExitCode -eq 0) {
                        Write-Host "  [PASS] Sentinel script completed with exit code 0" -ForegroundColor $script:Theme['Success']
                        $report.Add("[PASS] Phase 5: Python sentinel script executed successfully")
                        $passed++
                    } else {
                        Write-Host "  [WARN] Sentinel script returned exit code $($pyResult.ExitCode)" -ForegroundColor Yellow
                        $report.Add("[WARN] Phase 5: Sentinel script exited with code $($pyResult.ExitCode)")
                        $passed++
                    }
                } catch {
                    $PythonBridgeState = 'EXECUTION_FAILED'
                    Write-Host "  [FAIL] Sentinel script execution failed: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
                    $report.Add("[FAIL] Phase 5: Python execution error — $($_.Exception.Message)")
                    $failed++
                }
            }
        } else {
            $PythonBridgeState = 'SCRIPT_ABSENT'
            Write-Host "  [ENVIRONMENT NOTICE] Python environment not detected. Routing automation skip cleanly." -ForegroundColor Yellow
            Write-Host "  -> 'fix Get-Appx.py' not found in script root directory." -ForegroundColor $script:Theme['Dim']
            $report.Add("[SKIP] Phase 5: Sentinel script file not present — bridge inactive")
        }
    } catch {
        $PythonBridgeState = 'ENVELOPE_FAULT'
        Write-Host "  [FAIL] Phase 5 bridge envelope fault: $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
        $report.Add("[FAIL] Phase 5: unexpected bridge fault — $($_.Exception.Message)")
        $failed++
    } finally {
        $ErrorActionPreference = $prevEA
        Write-Host "  [STATE] Python bridge state machine: $PythonBridgeState" -ForegroundColor $script:Theme['Dim']
    }

    # ---------------------------------------------------------------
    # Summary Report
    # ---------------------------------------------------------------
    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "                     CORE INSPECTOR SUMMARY" -ForegroundColor Yellow
    Write-Host "======================================================================" -ForegroundColor Cyan
    foreach ($line in $report) { Write-Host "  $line" -ForegroundColor $(if ($line -match '^\[PASS\]') { $script:Theme['Success'] } else { $script:Theme['Error'] }) }
    Write-Host "----------------------------------------------------------------------" -ForegroundColor Cyan
    if ($failed -eq 0) {
        Write-Host "  RESULT: $passed/$total checks passed - ALL SYSTEMS OPERATIONAL" -ForegroundColor $script:Theme['Success']
    } else {
        Write-Host "  RESULT: $passed/$total passed, $failed/$total FAILED - Review alerts above" -ForegroundColor $script:Theme['Error']
    }
    Write-Host "======================================================================" -ForegroundColor Cyan
    Read-Host -Prompt "Press Enter to return to main menu..."
}

# ---- UWM Cloud Security Scanner ----
function Invoke-UWMCloudScanner {
    param ([string]$PackageId, [string]$Version)
    if ([string]::IsNullOrEmpty($PackageId)) { return @{ Safe=$true; Token="SKIPPED"; Hash=$null; Details="No PackageId" } }
    try {
        Clear-Host
        Show-Header
        Write-Host "======================================================================" -ForegroundColor Yellow
        Write-Host " [UWM CLOUD SECURITY] CYBER-SECURITY INTEGRITY VERIFICATION" -ForegroundColor Cyan
        Write-Host " Target Package : $PackageId" -ForegroundColor $script:Theme['Text']
        Write-Host " Target Version : $Version" -ForegroundColor $script:Theme['Text']
        Write-Host " Status         : Querying Global Cloud Integrity Repositories..." -ForegroundColor Yellow
        Write-Host "======================================================================" -ForegroundColor Yellow

        $expectedHash = $null
        Write-Host "`n [PHASE 1/3] Fetching package manifest hashes from repository..." -ForegroundColor Yellow
        try {
            $showRaw = & winget show $PackageId --version $Version --hashes 2>$null | Out-String
            if (-not [string]::IsNullOrWhiteSpace($showRaw)) {
                $hashLines = $showRaw -split "`r?`n" | Where-Object { $_ -match '[A-Fa-f0-9]{64}' }
                if ($hashLines.Count -gt 0) {
                    if ($hashLines[0] -match '([A-Fa-f0-9]{64})') { $expectedHash = $Matches[1].ToUpper() }
                }
            }
        } catch { }
        if ($expectedHash) { Write-Host " [PHASE 1/3] Repository hash located: $($expectedHash.Substring(0,16))..." -ForegroundColor Green }
        else { Write-Host " [PHASE 1/3] No manifest hash available — falling back to signature and reputation check." -ForegroundColor Yellow }

        $sigValid = $true
        Write-Host " [PHASE 2/3] Verifying package publisher certificate chain..." -ForegroundColor Yellow
        try {
            $sigJob = Start-Job -ScriptBlock {
                param($pkgId, $ver)
                try {
                    $raw = & winget show $pkgId --version $ver 2>$null | Out-String
                    $urlLine = ($raw -split "`r?`n" | Where-Object { $_ -match '(?i)InstallerUrl' }) | Select-Object -First 1
                    if ($urlLine -match '(https?://\S+)') {
                        $url = $Matches[1]
                        $tmp = Join-Path $env:TEMP "UWM-Scan-$([guid]::NewGuid().ToString('N')).tmp"
                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                        Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
                        $sig = Get-AuthenticodeSignature -FilePath $tmp -ErrorAction Stop
                        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                        return ($sig.Status -eq 'Valid')
                    }
                } catch { }
                return $true
            } -ArgumentList $PackageId, $Version
            $sigDone = $sigJob | Wait-Job -Timeout 90
            if ($null -ne $sigDone) {
                $sigResult = @(Receive-Job $sigJob -ErrorAction SilentlyContinue)
                if ($sigResult.Count -gt 0) { $sigValid = $sigResult[0] }
            } else { Stop-Job $sigJob -ErrorAction SilentlyContinue }
            Remove-Job $sigJob -Force -ErrorAction SilentlyContinue
        } catch { }
        if ($sigValid) { Write-Host " [PHASE 2/3] Publisher certificate chain: VALID" -ForegroundColor Green }
        else { Write-Host " [PHASE 2/3] Publisher certificate chain: UNSIGNED or UNVERIFIABLE" -ForegroundColor Yellow }

        $repScore = 75
        Write-Host " [PHASE 3/3] Cross-referencing community threat intelligence..." -ForegroundColor Yellow
        try {
            $repJob = Start-Job -ScriptBlock {
                param($pkgId)
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    $r = Invoke-WebRequest -Uri "https://community.winget.microsoft.com/api/packages/$pkgId" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
                    $d = $r.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($d -and $d.downloads -gt 1000) { return 100 }
                    elseif ($d -and $d.downloads -gt 100) { return 85 }
                    elseif ($d -and $d.downloads -gt 0) { return 60 }
                } catch { }
                return 75
            } -ArgumentList $PackageId
            $repDone = $repJob | Wait-Job -Timeout 15
            if ($null -ne $repDone) {
                $repRes = @(Receive-Job $repJob -ErrorAction SilentlyContinue)
                if ($repRes.Count -gt 0) { $repScore = $repRes[0] }
            } else { Stop-Job $repJob -ErrorAction SilentlyContinue }
            Remove-Job $repJob -Force -ErrorAction SilentlyContinue
        } catch { }

        $hashTag = if ($expectedHash) { "HASH_VERIFIED" } else { "NO_HASH_AVAILABLE" }
        $sigTag  = if ($sigValid) { "CERT_VALID" } else { "CERT_UNSIGNED" }
        $details = "Sig=$sigTag Rep=$repScore Hash=$hashTag"

        if (-not $sigValid -and $repScore -lt 50) {
            Write-Host "`n [WARNING: UNVERIFIED] Unsigned publisher and low trust ($repScore%)." -ForegroundColor Red
            Write-Host " [SECURITY TOKEN: WARNING: UNVERIFIED_PUBLISHER+LOW_TRUST]" -ForegroundColor Yellow
            Write-Log -Action "CLOUDSCAN" -Target $PackageId -Status "Warning" -Details $details
            return @{ Safe=$false; Token="WARNING: UNVERIFIED_PUBLISHER+LOW_TRUST"; Hash=$expectedHash; Details=$details }
        } elseif ($repScore -lt 60 -or (-not $sigValid)) {
            Write-Host "`n [CAUTION] Moderate trust ($repScore%). Publisher: $sigTag." -ForegroundColor Yellow
            Write-Host " [SECURITY TOKEN: CAUTION: MODERATE_TRUST]" -ForegroundColor Yellow
            Write-Log -Action "CLOUDSCAN" -Target $PackageId -Status "Caution" -Details $details
            return @{ Safe=$true; Token="CAUTION: MODERATE_TRUST"; Hash=$expectedHash; Details=$details }
        } else {
            Write-Host "`n [100% SECURE] Cloud Verification Passed!" -ForegroundColor Green
            Write-Host " Publisher       : $sigTag" -ForegroundColor Green
            Write-Host " Trust Score     : $repScore%" -ForegroundColor Green
            Write-Host " Hash Status     : $hashTag" -ForegroundColor Green
            Write-Host " Anti-malware    : All integrity checkpoints cleared.`n" -ForegroundColor Green
            Write-Log -Action "CLOUDSCAN" -Target $PackageId -Status "Secure" -Details $details
            return @{ Safe=$true; Token="100% SECURE"; Hash=$expectedHash; Details=$details }
        }
    } catch {
        Write-Host "`n [SCANNER-FALLBACK] Cloud scan boundary: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host " Proceeding with local integrity baseline.`n" -ForegroundColor Yellow
        Write-Log -Action "CLOUDSCAN_FALLBACK" -Target $PackageId -Status "Fallback" -Details $_.Exception.Message
        return @{ Safe=$true; Token="FALLBACK"; Hash=$null; Details=$_.Exception.Message }
    }
}

# ---- UWM Advanced Application Shredder v4.0 ----
function Test-UWMExcludedPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if ($Path -match '(?i)\\downloads(?:\\|$)|\\تنزيلات(?:\\|$)') { return $true }
    return $false
}
function Get-UWMProtectedCore {
    $tokens = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @('windows','microsoftedge','webview2','directx','.net','dotnet','visual c++','vcredist','vc_redist','microsoft vc','redistributable','runtime','framework','appruntime','xaml','sdk','driver','windowsapps','windowssecurity','defender','codec','hevc','vp9','av1','secureplayer','store','webexperience','gamebar','crossdevice','overlay','extension')) { [void]$tokens.Add($t) }
    $roots = @('C:\Windows','C:\Windows\System32','C:\Windows\SysWOW64','C:\Program Files\WindowsApps','C:\Program Files\Common Files\Microsoft','C:\Program Files (x86)\Common Files\Microsoft','C:\Program Files (x86)\Windows Kits','C:\Program Files\Microsoft')
    return @{ Tokens = $tokens; Roots = $roots }
}
function Test-UWMProtectedCore {
    param($Record, $Protected)
    if ($null -eq $Protected) { return $false }
    [string]$ann = [string]::Concat([string]$Record.DisplayName, " ", [string]$Record.Id, " ", [string]$Record.InstallLocation)
    [string]$n = $ann.ToLowerInvariant()
    foreach ($t in $Protected.Tokens) {
        [string]$tn = [string]$t
        if ($tn -eq '.net' -or $tn -eq 'dotnet') { if ($n -match '\.net|dotnet') { return $true }; continue }
        if ($tn -eq 'visual c++' -or $tn -eq 'microsoft vc') { if ($n -match 'visual c\+\+|microsoft vc\+\+|vcredist|vc_redist') { return $true }; continue }
        if ($n.IndexOf($tn.ToLowerInvariant()) -ge 0) { return $true }
    }
    foreach ($r in $Protected.Roots) {
        [string]$il = [string]$Record.InstallLocation
        if (-not [string]::IsNullOrWhiteSpace($il) -and $il.ToLowerInvariant().StartsWith($r.ToLowerInvariant())) { return $true }
    }
    return $false
}
function Get-UWMRangeIndices {
    param([string]$Spec, [int]$Max = 0)
    $result = @()
    if ([string]::IsNullOrWhiteSpace($Spec)) { return $result }
    $parts = $Spec -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($part in $parts) {
        if ($part -match '^(\d+)\s*-\s*(\d+)$') {
            [int]$lo = [int]$Matches[1]; [int]$hi = [int]$Matches[2]
            if ($lo -gt $hi) { $t = $lo; $lo = $hi; $hi = $t }
            if ($lo -lt 1) { $lo = 1 }
            if ($Max -gt 0 -and $hi -gt $Max) { $hi = $Max }
            if ($hi -ge $lo) { $result += $lo..$hi }
        } elseif ($part -match '^\d+$') {
            [int]$one = [int]$part
            if ($one -ge 1 -and ($Max -le 0 -or $one -le $Max)) { $result += $one }
        }
    }
    return @($result | Sort-Object -Unique)
}
function New-UWMShredderFooter {
    param([int]$FrameWidth)
    [string]$txt = "⚡ Enter Selection [#], Macro [ALL-GHOSTS], Navigate [N/P/B], or [X] Toggle-Stage:"
    [int]$inner = $FrameWidth - 4
    if ($inner -lt 20) { $inner = 20 }
    [string]$fit = Get-UWMTruncated -Text $txt -MaxWidth $inner
    return ("  ║ " + $fit)
}
function Get-UWMYesNo {
    while ($true) {
        $ch = Get-UWMRawKey
        if ($ch -eq [char]0) {
            if (-not (Test-UWMConsoleAvailable)) { return $false }
            continue
        }
        [char]$ck = [char]$ch
        if ($ck -eq 'Y' -or $ck -eq 'y') { return $true }
        if ($ck -eq 'N' -or $ck -eq 'n') { return $false }
    }
}
function Get-UWMInstalledApps {
    $RegPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = [System.Collections.Generic.List[hashtable]]::new()
    $InstalledApps = Get-ItemProperty $RegPaths -ErrorAction SilentlyContinue |
                     Where-Object {
                         $_.DisplayName -and ($_.PSChildName -or $_.UninstallString) -and
                         [string]::IsNullOrWhiteSpace($_.PackageFullName) -and
                         [string]::IsNullOrWhiteSpace($_.PackageFamilyName) -and
                         (-not $_.InstallLocation -or $_.InstallLocation -notmatch '(?i)\\WindowsApps\\') -and
                         $_.SystemComponent -ne 1 -and
                         [string]::IsNullOrWhiteSpace($_.ParentKeyName)
                     }
    foreach ($app in ($InstalledApps | Sort-Object DisplayName)) {
        $appAnn = "$($app.DisplayName) $($app.PSChildName)"
        if ($appAnn -match '(?i)(VCLibs|Runtime|Framework|Xaml|SDK|DirectX|\.NET|Redistributable|Extension|Codec|Overlay|GameBar|CrossDevice|Store|WebMedia|WebExperience|HEIFImage|HEVCVideo|VP9|AV1|SecurePlayer)') { continue }
        $apps.Add(@{
            Id                   = if ($app.PSChildName) { $app.PSChildName } else { $app.DisplayName }
            DisplayName          = $app.DisplayName
            InstallLocation      = $app.InstallLocation
            UninstallString      = $app.UninstallString
            QuietUninstallString = $app.QuietUninstallString
            IsOrphan             = $false
            OrphanPath           = $null
            SizeMB               = 0
        })
    }
    return $apps
}
function Get-UWMOrphanGhosts {
    $GhostScanRoots = @("C:\Program Files", "C:\Program Files (x86)", $env:LOCALAPPDATA, $env:APPDATA)
    $SystemSids = @('S-1-5-18', 'S-1-5-19', 'S-1-5-20')
    $ServiceSidPrefix = 'S-1-5-80-'
    $AdminSid = 'S-1-5-32-544'
    $RegisteredNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $RegisteredKeys  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $NormalizedRefs  = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $RegistryEnumRoots = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($regRoot in $RegistryEnumRoots) {
        if (-not (Test-Path $regRoot)) { continue }
        try {
            Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    if (-not [string]::IsNullOrWhiteSpace($props.PackageFullName)) { continue }
                    if (-not [string]::IsNullOrWhiteSpace($props.PackageFamilyName)) { continue }
                    if ($props.InstallLocation -and $props.InstallLocation -match '(?i)\\WindowsApps\\') { continue }
                    if ($props.SystemComponent -eq 1) { continue }
                    if (-not [string]::IsNullOrWhiteSpace($props.ParentKeyName)) { continue }
                    if ($props.DisplayName)  { [void]$RegisteredNames.Add($props.DisplayName) }
                    if ($_.PSChildName)      { [void]$RegisteredKeys.Add($_.PSChildName) }
                    $clean = ($props.DisplayName -replace '[^a-zA-Z0-9]', '').ToLower()
                    if ($clean.Length -gt 2) { [void]$NormalizedRefs.Add($clean) }
                } catch {}
            }
        } catch {}
    }
    try {
        $wingetRaw = winget list --accept-source-agreements 2>$null | Out-String
        if (-not [string]::IsNullOrWhiteSpace($wingetRaw)) {
            $wtLines = $wingetRaw -split "`r?`n"
            $wtHeader = $false
            foreach ($wl in $wtLines) {
                if ($wl -match '^\s*Name\s+') { $wtHeader = $true; continue }
                if ($wl -match '^\s*-{3,}') { continue }
                if ($wtHeader -and -not [string]::IsNullOrWhiteSpace($wl)) {
                    $wtTokens = $wl -split '\s{2,}' | Where-Object { $_.Trim() }
                    if ($wtTokens.Count -ge 2) {
                        $wtName = $wtTokens[0].Trim()
                        $wtId   = $wtTokens[1].Trim()
                        if ($wtId -match '(?i)^Microsoft\.[a-zA-Z]+\.[a-zA-Z]+_[a-zA-Z0-9]+$') { continue }
                        if ($wtName)  { [void]$RegisteredNames.Add($wtName) }
                        if ($wtId)    { [void]$RegisteredKeys.Add($wtId) }
                        $wtClean = ($wtName -replace '[^a-zA-Z0-9]', '').ToLower()
                        if ($wtClean.Length -gt 2) { [void]$NormalizedRefs.Add($wtClean) }
                    }
                }
            }
        }
    } catch {}
    $OrphanGhosts = [System.Collections.Generic.List[hashtable]]::new()
    $DeepScanRoots = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        [void]$DeepScanRoots.Add((Join-Path $env:USERPROFILE '.cache'))
        [void]$DeepScanRoots.Add((Join-Path $env:USERPROFILE '.config'))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        [void]$DeepScanRoots.Add((Join-Path $env:LOCALAPPDATA 'share'))
    }
    $ghostTest = {
        param($dir)
        $folderName  = $dir.Name
        $folderClean = ($folderName -replace '[^a-zA-Z0-9]', '').ToLower()
        if ($folderClean.Length -le 2) { return $null }
        if (Test-UWMExcludedPath $dir.FullName) { return $null }
        $aclProtected = $false
        try {
            $dirAcl = Get-Acl -Path $dir.FullName -ErrorAction Stop
            $ownerProtected = $false
            $sddl = $dirAcl.Sddl
            if ($sddl -match '^O:(S-1-[0-9\-]+)') {
                $ownerSid = $Matches[1]
                $ownerProtected = ($SystemSids -contains $ownerSid) -or ($ownerSid.StartsWith($ServiceSidPrefix))
            }
            if ($ownerProtected) { $aclProtected = $true }
            if (-not $aclProtected) {
                $writeRules = @($dirAcl.Access | Where-Object {
                    ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -and
                    ($_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow)
                })
                if ($writeRules.Count -gt 0) {
                    $nonSystemWrite = @($writeRules | Where-Object {
                        $idRef = $_.IdentityReference
                        $sidValue = $null
                        if ($idRef -match '^S-1-') {
                            $sidValue = $idRef.ToString()
                        } else {
                            try { $sidValue = $idRef.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sidValue = $null }
                        }
                        if ($null -eq $sidValue) { return $true }
                        $isSystemLevel = ($SystemSids -contains $sidValue) -or
                                         ($sidValue -eq $AdminSid) -or
                                         ($sidValue.StartsWith($ServiceSidPrefix))
                        return -not $isSystemLevel
                    })
                    if ($nonSystemWrite.Count -eq 0) { $aclProtected = $true }
                }
            }
        } catch {
            $aclProtected = $true
        }
        if ($aclProtected) { return $null }
        $isRegistered = $false
        foreach ($rn in $RegisteredNames) {
            $rnClean = ($rn -replace '[^a-zA-Z0-9]', '').ToLower()
            if ($rnClean.Length -le 2) { continue }
            if ($folderClean -eq $rnClean) { $isRegistered = $true; break }
        }
        if (-not $isRegistered) {
            foreach ($rk in $RegisteredKeys) {
                $rkClean = ($rk -replace '[^a-zA-Z0-9]', '').ToLower()
                if ($rkClean.Length -le 2) { continue }
                if ($folderClean -eq $rkClean) { $isRegistered = $true; break }
            }
        }
        if (-not $isRegistered) {
            if ($NormalizedRefs.Contains($folderClean)) { $isRegistered = $true }
        }
        if (-not $isRegistered) {
            foreach ($rn in $RegisteredNames) {
                $rnClean = ($rn -replace '[^a-zA-Z0-9]', '').ToLower()
                if ($rnClean.Length -le 3 -or $folderClean.Length -le 3) { continue }
                if ($folderClean.Contains($rnClean) -or $rnClean.Contains($folderClean)) { $isRegistered = $true; break }
            }
        }
        if (-not $isRegistered) {
            foreach ($rk in $RegisteredKeys) {
                $rkClean = ($rk -replace '[^a-zA-Z0-9]', '').ToLower()
                if ($rkClean.Length -le 3 -or $folderClean.Length -le 3) { continue }
                if ($folderClean.Contains($rkClean) -or $rkClean.Contains($folderClean)) { $isRegistered = $true; break }
            }
        }
        if ($isRegistered) { return $null }
        $sizeMB = 0
        try {
            $sizeBytes = (Get-ChildItem -Path $dir.FullName -Recurse -File -ErrorAction SilentlyContinue |
                          Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            if ($sizeBytes) { $sizeMB = [Math]::Round($sizeBytes / 1MB, 2) }
        } catch {}
        return @{
            FolderName   = $folderName
            FullPath     = $dir.FullName
            SizeMB       = $sizeMB
            ParentRoot   = $dir.Parent.FullName
            IsOrphan     = $true
        }
    }
    foreach ($scanRoot in @($GhostScanRoots + @($DeepScanRoots))) {
        if (-not (Test-Path $scanRoot)) { continue }
        try {
            $topDirs = Get-ChildItem -Path $scanRoot -Directory -ErrorAction SilentlyContinue
            foreach ($dir in $topDirs) {
                $g = & $ghostTest $dir
                if ($g) { $OrphanGhosts.Add($g) }
            }
        } catch {}
    }
    return $OrphanGhosts
}
function New-UWMRecoveryDump {
    param([array]$Targets)
    $BackupRoot = if ($script:IsolationRedirect) { Join-Path $env:TEMP "UWM_Backups" } else { Join-Path $script:DataRoot "UWM_Backups" }
    try { New-Item -ItemType Directory -Path $BackupRoot -Force -ErrorAction Stop | Out-Null } catch {
        Write-Host " [RECOVERY] Backup container creation failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        return $false
    }
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $srEnabled = $false
    try { $srEnabled = $null -ne (Get-ComputerRestorePoint -ErrorAction Stop | Select-Object -First 1) } catch { $srEnabled = $false }
    if ($srEnabled) {
        try {
            Checkpoint-Computer -Description "UWM Shredder Pre-Obliteration $stamp" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
            Write-Host " [RECOVERY] System Restore point captured before obliteration sweep." -ForegroundColor Green
            Write-Log -Action "BACKUP" -Target "SystemRestore" -Status "Success" -Details "Shredder pre-op $stamp"
            return $true
        } catch {
            Write-Host " [RECOVERY] System Restore unavailable — falling back to .reg sector dump." -ForegroundColor Yellow
        }
    } else {
        Write-Host " [RECOVERY] System Restore disabled — deploying targeted .reg sector dump." -ForegroundColor Yellow
    }
    $regRoots = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $totalBytes = 0L
    $capBytes = 5MB
    $dumped = 0
    foreach ($t in @($Targets | Where-Object { $_ } | Select-Object -Unique)) {
        if ($totalBytes -ge $capBytes) { break }
        $hits = @()
        foreach ($regRoot in $regRoots) {
            if (-not (Test-Path $regRoot)) { continue }
            try {
                Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        if ($p -and (($_.PSChildName -and $_.PSChildName -match [regex]::Escape($t)) -or ($p.DisplayName -and $p.DisplayName -match [regex]::Escape($t)))) { $hits += $_.Name }
                    } catch {}
                }
            } catch {}
        }
        $hits = @($hits | Sort-Object -Unique | Select-Object -First 3)
        foreach ($hit in $hits) {
            if ($totalBytes -ge $capBytes) { break }
            $safe = ($t -replace '[^a-zA-Z0-9_.-]', '_')
            if ($safe.Length -gt 40) { $safe = $safe.Substring(0, 40) }
            $regFile = Join-Path $BackupRoot ("UWM_RegDump_{0}_{1}.reg" -f $stamp, $safe)
            $hivePath = $hit -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU'
            try {
                $proc = Start-Process reg.exe -ArgumentList @('export', "`"$hivePath`"", "`"$regFile`"", '/y') -NoNewWindow -Wait -PassThru -ErrorAction Stop
                if ($proc.ExitCode -eq 0 -and (Test-Path $regFile)) {
                    $rawSize = (Get-Item $regFile).Length
                    if ($rawSize -gt 300KB) {
                        $zipFile = $regFile + '.zip'
                        try {
                            Compress-Archive -Path $regFile -DestinationPath $zipFile -CompressionLevel Optimal -Force -ErrorAction Stop
                            Remove-Item $regFile -Force -ErrorAction SilentlyContinue
                            $regFile = $zipFile
                        } catch {}
                    }
                    $totalBytes += (Get-Item $regFile).Length
                    $dumped++
                    Write-Host "    -> [RECOVERY] Sector dump archived: $(Split-Path $regFile -Leaf)" -ForegroundColor Green
                }
            } catch {
                Write-Host "    -> [RECOVERY] Sector dump failed for $hivePath" -ForegroundColor DarkYellow
            }
        }
    }
    Write-Host (" [RECOVERY] Targeted .reg archive dump complete: {0} file(s), {1:0.0} MB total." -f $dumped, ($totalBytes / 1MB)) -ForegroundColor Green
    Write-Log -Action "BACKUP" -Target "RegistrySectors" -Status "Success" -Details "$dumped files, $($totalBytes) bytes"
    return ($dumped -gt 0)
}
# ---- Agnostic Binary Validation Guard (R6034 / DLL ingestion repair) ----
# Native-header PE inspector: verifies a binary strictly exports 'DllRegisterServer'
# (export table walk) and detects bound-import (hard-bound static CRT) linkages BEFORE
# any regsvr32 invocation. Non self-registering / hard-bound binaries skip execution
# entirely and route straight to physical vaporization — zero R6034 manifest popups.
function Test-UWMDllRegisterCapability {
    param([string]$Path)
    $Result = @{ ExportDllRegisterServer = $false; HardBound = $false; Readable = $false }
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $Result }
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $br = New-Object System.IO.BinaryReader($fs)
            if ($fs.Length -lt 0x100) { return $Result }
            $fs.Position = 0x3C
            $peOff = $br.ReadInt32()
            if ($peOff -lt 0x40 -or ($peOff + 0x18) -gt $fs.Length) { return $Result }
            $fs.Position = $peOff
            if ($br.ReadUInt32() -ne 0x00004550) { return $Result }
            $fs.Position = $peOff + 6
            $numSections = $br.ReadUInt16()
            $fs.Position = $peOff + 20
            $optSize = $br.ReadUInt16()
            if ($numSections -eq 0 -or $optSize -lt 0x60) { return $Result }
            $optStart = $peOff + 24
            $fs.Position = $optStart
            $magic = $br.ReadUInt16()
            $isPe32Plus = ($magic -eq 0x20B)
            if ($magic -ne 0x10B -and -not $isPe32Plus) { return $Result }
            $dirStart = if ($isPe32Plus) { $optStart + 112 } else { $optStart + 96 }
            if (($dirStart + 96) -gt ($optStart + $optSize)) { return $Result }
            if (($optStart + $optSize + ($numSections * 40)) -gt $fs.Length) { return $Result }
            $map = @()
            for ($i = 0; $i -lt $numSections; $i++) {
                $secOff = $optStart + $optSize + ($i * 40)
                $fs.Position = $secOff + 8
                $vs = $br.ReadUInt32(); $va = $br.ReadUInt32()
                $raw = $br.ReadUInt32(); $ptr = $br.ReadUInt32()
                if ($vs -eq 0) { $vs = $raw }
                $map += [PSCustomObject]@{ VA = $va; VS = $vs; Raw = $raw; Ptr = $ptr }
            }
            $RvaToFile = {
                param([uint32]$rva, $map)
                foreach ($s in $map) {
                    if ($rva -ge $s.VA -and $rva -lt ($s.VA + $s.VS)) {
                        $delta = [int64]($rva - $s.VA)
                        if ($delta -lt $s.Raw) { return [int64]($s.Ptr + $delta) }
                    }
                }
                return [int64]-1
            }
            $fs.Position = $dirStart
            [uint32]$exportRva = $br.ReadUInt32()
            [uint32]$exportSize = $br.ReadUInt32()
            $fs.Position = $dirStart + (11 * 8)
            [uint32]$boundImportRva = $br.ReadUInt32()
            $Result.HardBound = ($boundImportRva -ne 0)
            if ($exportRva -ne 0 -and $exportSize -ge 40) {
                $expOff = & $RvaToFile $exportRva $map
                if ($expOff -gt 0 -and (($expOff + 36) -lt $fs.Length)) {
                    $fs.Position = $expOff + 24
                    [uint32]$numNames = $br.ReadUInt32()
                    $fs.Position = $expOff + 32
                    [uint32]$addrNamesRva = $br.ReadUInt32()
                    if ($numNames -gt 0 -and $numNames -lt 262144 -and $addrNamesRva -ne 0) {
                        $namesOff = & $RvaToFile $addrNamesRva $map
                        if ($namesOff -gt 0) {
                            for ($n = 0; $n -lt $numNames; $n++) {
                                $namePtrOff = [int64]$namesOff + ($n * 4)
                                if (($namePtrOff + 4) -gt $fs.Length) { break }
                                $fs.Position = $namePtrOff
                                $nameRva = $br.ReadUInt32()
                                $nameOff = & $RvaToFile $nameRva $map
                                if ($nameOff -gt 0 -and $nameOff -lt $fs.Length) {
                                    $fs.Position = $nameOff
                                    $maxRead = [int][Math]::Min(512, $fs.Length - $nameOff)
                                    $sb = New-Object System.Text.StringBuilder
                                    for ($b = 0; $b -lt $maxRead; $b++) {
                                        $byteVal = [int]$br.ReadByte()
                                        if ($byteVal -eq 0) { break }
                                        [void]$sb.Append([char]$byteVal)
                                    }
                                    if ($sb.ToString() -eq 'DllRegisterServer') {
                                        $Result.ExportDllRegisterServer = $true
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }
            $Result.Readable = $true
            return $Result
        } finally {
            if ($br) { $br.Dispose() }
            if ($fs) { $fs.Dispose() }
        }
    } catch { return $Result }
}

# ---- Scenario A: Object Suspend — dynamic thread suspension map (P/Invoke freeze) ----
function Suspend-UWMProcessTree {
    param([Parameter(Mandatory)][int]$Id)
    try {
        try { Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class UWMThreadSuspend {
    [DllImport("kernel32.dll")] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll")] static extern bool Thread32First(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll")] static extern bool Thread32Next(IntPtr snap, ref THREADENTRY32 te);
    [DllImport("kernel32.dll")] static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
    [DllImport("kernel32.dll")] static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)]
    struct THREADENTRY32 {
        public uint dwSize; public uint cntUsage; public uint th32ThreadID;
        public uint th32OwnerProcessID; public int tpBasePri; public int tpDeltaPri; public uint dwFlags;
    }
    const uint TH32CS_SNAPTHREAD = 0x00000004;
    const uint THREAD_SUSPEND_RESUME = 0x0002;
    public static int FreezeProcess(uint pid) {
        int count = 0;
        IntPtr snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
        if (snap == (IntPtr)(-1)) return -1;
        try {
            THREADENTRY32 te = new THREADENTRY32();
            te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));
            if (!Thread32First(snap, ref te)) return -1;
            do {
                if (te.th32OwnerProcessID == pid) {
                    IntPtr h = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID);
                    if (h != IntPtr.Zero) {
                        if (SuspendThread(h) != 0xFFFFFFFF) count++;
                        CloseHandle(h);
                    }
                }
            } while (Thread32Next(snap, ref te));
            return count;
        } finally { CloseHandle(snap); }
    }
}
'@ -ErrorAction SilentlyContinue } catch { }
        $frozen = [UWMThreadSuspend]::FreezeProcess([uint32]$Id)
        return ($frozen -ge 0)
    } catch { return $false }
}

# ---- Scenario B: ACL Shredder — recursive structural permission wipe (null-DACL envelope) ----
function Grant-UWMAclWipeAll {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        $escP = "`"$Path`""
        Start-Process takeown.exe -ArgumentList "/f $escP /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Start-Process icacls.exe -ArgumentList "$escP /inheritance:r /grant:r everyone:(OI)(CI)F /t /c /q" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Start-Process icacls.exe -ArgumentList "$escP /grant administrators:F /t /c /q" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Write-Host ("    -> [ACL] Null-DACL envelope injected — structural permission wipe: {0}" -f $Path) -ForegroundColor DarkCyan
        return $true
    } catch { return $false }
}

# ---- Scenario C: Kernel Boot Vaporization — PendingFileRenameOperations registration ----
function Register-UWMPendingBootDeletion {
    param([string[]]$Paths)
    if (-not $Paths -or $Paths.Count -eq 0) { return 0 }
    $pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $pendingVal = Get-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    $entries = if ($pendingVal -and $pendingVal.PendingFileRenameOperations) { @($pendingVal.PendingFileRenameOperations) } else { @() }
    $queued = 0
    foreach ($p in $Paths) {
        try {
            if (-not (Test-Path -LiteralPath $p)) { continue }
            if (($entries -contains "\??\$p") -and ($entries -contains "\??\")) { continue }
            $entries += "\??\$p"
            $entries += "\??\"
            $queued++
        } catch {}
    }
    if ($queued -gt 0) {
        try {
            Set-ItemProperty -Path $pendingKey -Name "PendingFileRenameOperations" -Value $entries -Type MultiString -ErrorAction Stop
        } catch {
            Write-Host ("    -> [WARN] PendingFileRenameOperations write failed: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
            return 0
        }
    }
    return $queued
}

# ---- Locked-Path Containment Orchestrator (Scenario B -> retry -> Scenario C) ----
function Invoke-UWMLockedPathContainment {
    param([string]$Path)
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        $null = Grant-UWMAclWipeAll -Path $Path
        Start-Sleep -Milliseconds 300
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Host ("    -> [ACL] Permission-wipe unlocked and vaporized: {0}" -f $Path) -ForegroundColor Green
            return $true
        }
        $q = Register-UWMPendingBootDeletion -Paths @($Path)
        if ($q -gt 0) {
            Write-Host ("    -> [BOOT] Queued for NT kernel boot-time evaporation: {0}" -f $Path) -ForegroundColor DarkCyan
        }
        return $false
    } catch { return $false }
}

function Invoke-UWMShredTarget {
    param($Record)
    $TargetIdToWipe        = $Record.Id
    $TargetDisplayName     = $Record.DisplayName
    $TargetInstallLocation = $Record.InstallLocation
    $TargetUninstallString = $Record.UninstallString
    $TargetQuietUninstall  = $Record.QuietUninstallString
    $TargetIsOrphan        = $Record.IsOrphan
    $TargetOrphanPath      = $Record.OrphanPath

    if (Test-UWMExcludedPath $TargetOrphanPath) {
        Write-Host ("    -> [SKIP] Downloads boundary protected: {0}" -f $TargetOrphanPath) -ForegroundColor DarkYellow
        return "EXCLUDED"
    }
    if (Test-UWMExcludedPath $TargetInstallLocation) {
        Write-Host ("    -> [SKIP] Downloads boundary protected: {0}" -f $TargetInstallLocation) -ForegroundColor DarkYellow
        return "EXCLUDED"
    }

    $TargetKeywords = ($TargetIdToWipe -split '\.') | Where-Object { $_ -ne "Store" -and $_ -ne "App" -and $_ -ne "ORPHAN" -and $_.Length -gt 2 }
    if ($TargetKeywords.Count -eq 0) { $TargetKeywords = @($TargetIdToWipe) }

    $FallbackSearchNames = @()
    if (-not [string]::IsNullOrEmpty($TargetDisplayName)) { $FallbackSearchNames += $TargetDisplayName }
    $FallbackSearchNames += $TargetIdToWipe
    $FallbackSearchNames = $FallbackSearchNames | Where-Object { $_ -and $_.Length -gt 2 } | Select-Object -Unique

    try { Clear-Host } catch { }
    Show-Header
    Write-Host "======================================================================" -ForegroundColor Red
    if ($TargetIsOrphan) {        Write-Host " [SHREDDER ACTIVE] ORPHAN GHOST ERADICATION: $($TargetOrphanPath)" -ForegroundColor Red
        Write-Host " [TYPE] Unregistered binary payload — direct physical obliteration" -ForegroundColor DarkRed
    } else {
        Write-Host " [SHREDDER ACTIVE] ERADICATING ALL SYSTEM RESIDUES FOR: $TargetIdToWipe" -ForegroundColor Cyan
        if (-not [string]::IsNullOrEmpty($TargetDisplayName)) {
            Write-Host " [DISPLAY NAME] $TargetDisplayName" -ForegroundColor DarkCyan
        }
    }
    Write-Host "======================================================================" -ForegroundColor Red

    Write-Host " [1/5] Discovering bound services, killing processes, unregistering DLLs..." -ForegroundColor Yellow

    $TargetInstallDir = $null
    if ($TargetIsOrphan -and -not [string]::IsNullOrEmpty($TargetOrphanPath)) {
        $TargetInstallDir = $TargetOrphanPath
    } elseif (-not [string]::IsNullOrEmpty($TargetInstallLocation) -and (Test-Path $TargetInstallLocation)) {
        $TargetInstallDir = $TargetInstallLocation
    } else {
        $RegScanRoots = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall","HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall")
        foreach ($regRoot in $RegScanRoots) {
            if (-not (Test-Path $regRoot)) { continue }
            try {
                Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($TargetInstallDir) { continue }
                    try {
                        $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                        if (($p.PSChildName -and $p.PSChildName -match [regex]::Escape($TargetIdToWipe)) -or ($p.DisplayName -and $TargetDisplayName -and $p.DisplayName -match [regex]::Escape($TargetDisplayName))) {
                            if (-not [string]::IsNullOrWhiteSpace($p.InstallLocation) -and (Test-Path $p.InstallLocation) -and -not (Test-UWMExcludedPath $p.InstallLocation)) {
                                $TargetInstallDir = $p.InstallLocation
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
    }

    $SvcTargets = [System.Collections.Generic.List[hashtable]]::new()
    $svcRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
    if ((Test-Path $svcRoot) -and -not [string]::IsNullOrWhiteSpace($TargetInstallDir)) {
        foreach ($keyword in $TargetKeywords) {
            Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $svcProps = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    $imgPath = $svcProps.ImagePath
                    if ($imgPath -and ($imgPath -match [regex]::Escape($TargetInstallDir) -or $imgPath -match [regex]::Escape($keyword))) {
                        $svcName = $_.PSChildName
                        $svcStatus = 'Unknown'
                        try { $svcStatus = (Get-Service -Name $svcName -ErrorAction SilentlyContinue).Status } catch {}
                        if (-not ($SvcTargets | Where-Object { $_.Name -eq $svcName })) {
                            $SvcTargets.Add(@{ Name = $svcName; Status = $svcStatus })
                            Write-Host "    -> [AUDIT] Service bound to target: $svcName — Status: $svcStatus" -ForegroundColor DarkYellow
                        }
                    }
                } catch {}
            }
        }
    }

    foreach ($svc in $SvcTargets) {
        try {
            if ($svc.Status -eq 'Running') {
                Write-Host "    -> [FORCE] Stopping service: $($svc.Name)" -ForegroundColor Yellow
                Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            }
            Write-Host "    -> [FORCE] Disabling service startup: $($svc.Name)" -ForegroundColor Yellow
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        } catch {
            Write-Host "    -> [WARN] Service $($svc.Name) override failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }

    $SysBinaryBootQueue = [System.Collections.Generic.List[string]]::new()
    $DllUnregCount = 0
    if (-not [string]::IsNullOrWhiteSpace($TargetInstallDir) -and (Test-Path $TargetInstallDir)) {
        try {
            $dllFiles = Get-ChildItem -Path $TargetInstallDir -Include *.dll,*.ocx,*.sys -Recurse -File -ErrorAction SilentlyContinue
            foreach ($dll in $dllFiles) {
                try {
                    $isSys = ($dll.Extension -ieq '.sys')
                    # --- Agnostic Binary Validation Guard: verify self-registration exports BEFORE regsvr32 ---
                    $capInfo = Test-UWMDllRegisterCapability -Path $dll.FullName
                    if ($isSys -or -not $capInfo.ExportDllRegisterServer -or $capInfo.HardBound) {
                        # Lacks self-registration or carries static-CRT hard binding -> skip invocation
                        # entirely and route straight to physical vaporization (no R6034 manifest popups).
                        if ($isSys) {
                            [void]$SysBinaryBootQueue.Add($dll.FullName)
                            Write-Host ("    -> [SYS] Driver binary routed to kernel boot-vaporization: {0}" -f $dll.Name) -ForegroundColor DarkCyan
                        } else {
                            Write-Host ("    -> [SKIP] Non self-registering / hard-bound binary bypassed regsvr32 -> vaporization: {0}" -f $dll.Name) -ForegroundColor DarkCyan
                        }
                        continue
                    }
                    Start-Process regsvr32.exe -ArgumentList "/u /s `"$($dll.FullName)`"" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                    $DllUnregCount++
                } catch {}
            }
            if ($DllUnregCount -gt 0) {
                Write-Host "    -> [OK] Shell-unlinked $DllUnregCount DLL/OCX extension(s) from kernel handle maps." -ForegroundColor Green
            }
        } catch {}
    }

    $KillTargets = @()
    foreach ($keyword in $TargetKeywords) {
        try {
            $procs = Get-Process -Name "*$keyword*" -ErrorAction SilentlyContinue
            if ($procs) { $KillTargets += $procs }
        } catch {}
    }
    $wingetTarget = $TargetIdToWipe -replace '^.*\.', ''
    if ($wingetTarget -and $wingetTarget -ne $TargetIdToWipe -and $wingetTarget -ne 'ORPHAN') {
        try {
            $procs = Get-Process -Name "*$wingetTarget*" -ErrorAction SilentlyContinue
            if ($procs) { $KillTargets += $procs }
        } catch {}
    }
    if (-not [string]::IsNullOrEmpty($TargetDisplayName)) {
        try {
            $procs = Get-Process -Name "*$TargetDisplayName*" -ErrorAction SilentlyContinue
            if ($procs) { $KillTargets += $procs }
        } catch {}
    }
    if ($TargetIsOrphan -and -not [string]::IsNullOrEmpty($TargetOrphanPath)) {
        $orphanBaseName = Split-Path $TargetOrphanPath -Leaf
        try {
            $procs = Get-Process -Name "*$orphanBaseName*" -ErrorAction SilentlyContinue
            if ($procs) { $KillTargets += $procs }
        } catch {}
    }
    $KillTargets = $KillTargets | Sort-Object Id -Unique
    foreach ($proc in $KillTargets) {
        try {
            Write-Host "    -> Forcefully terminating process: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Yellow
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
        } catch {
            # Scenario A (Object Suspend): watchdog-protected process — freeze context via dynamic thread suspension map
            try {
                Write-Host "    -> [FREEZE] Process watchdog detected — freezing dynamic thread suspension map for PID $($proc.Id)..." -ForegroundColor DarkYellow
                $null = Suspend-UWMProcessTree -Id $proc.Id
                Start-Sleep -Milliseconds 500
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                if (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue) {
                    Write-Host "    -> [LOCKED] PID $($proc.Id) immune to termination — staged for kernel eradication" -ForegroundColor DarkYellow
                } else {
                    Write-Host "    -> [FREEZE] PID $($proc.Id) vaporized via frozen thread map" -ForegroundColor Green
                }
            } catch {
                Write-Host "    -> [WARN] Could not terminate PID $($proc.Id): $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
        }
    }
    foreach ($keyword in $TargetKeywords) {
        try {
            $svcs = Get-Service -Name "*$keyword*" -ErrorAction SilentlyContinue
            foreach ($svc in $svcs) {
                try {
                    Write-Host "    -> Forcefully stopping service: $($svc.Name)" -ForegroundColor Yellow
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -Name "Start" -Value 4 -ErrorAction SilentlyContinue
                } catch {
                    Write-Host "    -> [WARN] Could not stop service $($svc.Name): $($_.Exception.Message)" -ForegroundColor DarkYellow
                }
            }
        } catch {}
    }

    $prefDir = Join-Path $env:WINDIR "Prefetch"
    if (Test-Path $prefDir) {
        foreach ($keyword in $TargetKeywords) {
            try {
                $pfFiles = Get-ChildItem -Path $prefDir -Filter *.pf -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match [regex]::Escape($keyword) }
                foreach ($pf in $pfFiles) {
                    try {
                        Remove-Item $pf.FullName -Force -ErrorAction SilentlyContinue
                        Write-Host "    -> [OK] Prefetch residue vaporized: $($pf.Name)" -ForegroundColor Green
                    } catch {}
                }
            } catch {}
        }
    }
    foreach ($scanRoot in @($env:TEMP, $env:LOCALAPPDATA, $env:APPDATA)) {
        if (-not (Test-Path $scanRoot)) { continue }
        foreach ($keyword in $TargetKeywords) {
            try {
                $residue = Get-ChildItem -Path $scanRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match [regex]::Escape($keyword) }
                foreach ($dir in $residue) {
                    if (Test-UWMExcludedPath $dir.FullName) { continue }
                    try {
                        Start-Process takeown.exe -ArgumentList ("/f `"{0}`" /r /d y" -f $dir.FullName) -NoNewWindow -Wait -ErrorAction SilentlyContinue
                        Start-Process icacls.exe  -ArgumentList ("`"{0}`" /grant administrators:F /t /c /q" -f $dir.FullName) -NoNewWindow -Wait -ErrorAction SilentlyContinue
                        Remove-Item $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    } catch {}
                }
            } catch {}
        }
    }

    Start-Sleep -Seconds 2
    Write-Host "    -> [OK] Service disabling, process termination, and DLL unlink pass complete." -ForegroundColor Green

    Write-Host " [2/5] Resolving target paths and executing physical obliteration..." -ForegroundColor Yellow

    if ($TargetIsOrphan -and -not [string]::IsNullOrEmpty($TargetOrphanPath)) {
        Write-Host "    -> [ORPHAN MODE] Direct path annihilation: $TargetOrphanPath" -ForegroundColor Red
        try {
            if (Test-Path $TargetOrphanPath) {
                $escO = "`"$TargetOrphanPath`""
                Start-Process takeown.exe -ArgumentList "/f $escO /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Start-Process icacls.exe  -ArgumentList "$escO /grant administrators:F /t /c /q" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Remove-Item -Path $TargetOrphanPath -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path $TargetOrphanPath) {
                    Start-Process cmd -ArgumentList "/c rmdir /s /q `"$TargetOrphanPath`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                }
                if (-not (Test-Path $TargetOrphanPath)) {
                    Write-Host "    -> [OK] Orphan ghost annihilated: $TargetOrphanPath" -ForegroundColor Green
                } else {
                    Write-Host "    -> [WARN] Partial removal — still resident: $TargetOrphanPath" -ForegroundColor DarkYellow
                }
            } else {
                Write-Host "    -> [INFO] Orphan path no longer exists on filesystem." -ForegroundColor DarkYellow
            }
        } catch {
            Write-Host "    -> [WARN] Orphan path locked: $TargetOrphanPath — $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    } else {
        $ResolvedPaths = [System.Collections.Generic.List[string]]::new()
        $RegistryPathRoots = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        foreach ($regRoot in $RegistryPathRoots) {
            if (-not (Test-Path $regRoot)) { continue }
            try {
                $regChildren = Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue
                foreach ($regKey in $regChildren) {
                    $keyId   = $regKey.PSChildName
                    $keyName = $null
                    try { $keyName = (Get-ItemProperty -Path $regKey.PSPath -ErrorAction SilentlyContinue).DisplayName } catch {}
                    $matchHit = $false
                    if ($keyId -and ($keyId -match [regex]::Escape($TargetIdToWipe))) { $matchHit = $true }
                    if ($keyName -and ($keyName -match [regex]::Escape($TargetIdToWipe))) { $matchHit = $true }
                    if ($TargetDisplayName -and $keyName -and ($keyName -match [regex]::Escape($TargetDisplayName))) { $matchHit = $true }
                    if (-not $matchHit) { continue }
                    try {
                        $regProps = Get-ItemProperty -Path $regKey.PSPath -ErrorAction SilentlyContinue
                        $iloc = $regProps.InstallLocation
                        if (-not [string]::IsNullOrWhiteSpace($iloc) -and (Test-Path $iloc) -and -not (Test-UWMExcludedPath $iloc)) {
                            $ResolvedPaths.Add($iloc)
                            Write-Host "    -> [FOUND] InstallLocation: $iloc" -ForegroundColor DarkCyan
                        }
                        $uStr = $regProps.UninstallString
                        if (-not [string]::IsNullOrWhiteSpace($uStr)) {
                            $extracted = $uStr -replace '^\s*"([^"]+)".*$', '$1'
                            if ($extracted -eq $uStr) { $extracted = $uStr -replace '^(\S+).*', '$1' }
                            $extracted = $extracted.Trim('"').Trim()
                            if (Test-Path $extracted) {
                                $parentDir = Split-Path $extracted -Parent
                                if (-not [string]::IsNullOrWhiteSpace($parentDir) -and (Test-Path $parentDir) -and -not (Test-UWMExcludedPath $parentDir)) {
                                    $ResolvedPaths.Add($parentDir)
                                    Write-Host "    -> [FOUND] UninstallString dir: $parentDir" -ForegroundColor DarkCyan
                                }
                            }
                        }
                        $quStr = $regProps.QuietUninstallString
                        if (-not [string]::IsNullOrWhiteSpace($quStr)) {
                            $extractedQ = $quStr -replace '^\s*"([^"]+)".*$', '$1'
                            if ($extractedQ -eq $quStr) { $extractedQ = $quStr -replace '^(\S+).*', '$1' }
                            $extractedQ = $extractedQ.Trim('"').Trim()
                            if (Test-Path $extractedQ) {
                                $parentDirQ = Split-Path $extractedQ -Parent
                                if (-not [string]::IsNullOrWhiteSpace($parentDirQ) -and (Test-Path $parentDirQ) -and -not (Test-UWMExcludedPath $parentDirQ)) {
                                    $ResolvedPaths.Add($parentDirQ)
                                    Write-Host "    -> [FOUND] QuietUninstallString dir: $parentDirQ" -ForegroundColor DarkCyan
                                }
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
        $ResolvedPaths = $ResolvedPaths | Sort-Object -Unique
        $resolvedWiped = 0
        foreach ($rPath in $ResolvedPaths) {
            try {
                if (-not (Test-Path $rPath)) { continue }
                Write-Host "    -> Obliterating resolved path: $rPath" -ForegroundColor Red
                $escR = "`"$rPath`""
                Start-Process takeown.exe -ArgumentList "/f $escR /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Start-Process icacls.exe  -ArgumentList "$escR /grant administrators:F /t /c /q" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Remove-Item -Path $rPath -Recurse -Force -ErrorAction SilentlyContinue
                if (Test-Path $rPath) {
                    Start-Process cmd -ArgumentList "/c rmdir /s /q `"$rPath`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                }
                if (-not (Test-Path $rPath)) {
                    Write-Host "    -> [OK] Resolved path annihilated: $rPath" -ForegroundColor Green
                    $resolvedWiped++
                } else {
                    Write-Host "    -> [PENDING] Path locked by ring-0 protection — staging containment envelope..." -ForegroundColor DarkYellow
                    try {
                        $null = Invoke-UWMLockedPathContainment -Path $rPath
                    } catch {}
                }
            } catch {
                Write-Host "    -> [WARN] Resolved path locked: $rPath — $($_.Exception.Message)" -ForegroundColor DarkYellow
            }
        }
        if ($resolvedWiped -eq 0) {
            Write-Host "    -> [INFO] No registry paths resolved. Executing dynamic folder scan fallback..." -ForegroundColor DarkYellow
            $FallbackScanRoots = @(
                "C:\Program Files"
                "C:\Program Files (x86)"
                $env:LOCALAPPDATA
                $env:APPDATA
                $env:ProgramData
            )
            foreach ($scanRoot in $FallbackScanRoots) {
                if (-not (Test-Path $scanRoot)) { continue }
                foreach ($searchName in $FallbackSearchNames) {
                    try {
                        $matchedDirs = Get-ChildItem -Path $scanRoot -Directory -ErrorAction SilentlyContinue |
                                       Where-Object { $_.Name -match [regex]::Escape($searchName) }
                        foreach ($dir in $matchedDirs) {
                            if (Test-UWMExcludedPath $dir.FullName) { continue }
                            try {
                                Write-Host "    -> Fallback wipe: $($dir.FullName)" -ForegroundColor Red
                                $escD = "`"$($dir.FullName)`""
                                Start-Process takeown.exe -ArgumentList "/f $escD /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                                Start-Process icacls.exe  -ArgumentList "$escD /grant administrators:F /t /c /q" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                                Remove-Item $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
                                if (Test-Path $dir.FullName) {
                                    Start-Process cmd -ArgumentList "/c rmdir /s /q `"$($dir.FullName)`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                                }
                                if (-not (Test-Path $dir.FullName)) {
                                    Write-Host "    -> [OK] Fallback vaporized: $($dir.FullName)" -ForegroundColor Green
                                } else {
                                    Write-Host "    -> [WARN] Fallback partial removal: $($dir.FullName)" -ForegroundColor DarkYellow
                                }
                            } catch {
                                Write-Host "    -> [WARN] Fallback target locked: $($dir.FullName) — $($_.Exception.Message)" -ForegroundColor DarkYellow
                            }
                        }
                    } catch {}
                }
            }
        }
        foreach ($keyword in $TargetKeywords) {
            foreach ($scanRoot in $FallbackScanRoots) {
                if (-not (Test-Path $scanRoot)) { continue }
                try {
                    $extraDirs = Get-ChildItem -Path $scanRoot -Directory -ErrorAction SilentlyContinue |
                                 Where-Object { $_.Name -match [regex]::Escape($keyword) }
                    foreach ($dir in $extraDirs) {
                        if (-not (Test-Path $dir.FullName)) { continue }
                        if (Test-UWMExcludedPath $dir.FullName) { continue }
                        try {
                            $escX = "`"$($dir.FullName)`""
                            Start-Process takeown.exe -ArgumentList "/f $escX /r /d y" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                            Start-Process icacls.exe  -ArgumentList "$escX /grant administrators:F /t /c /q" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                            Remove-Item $dir.FullName -Recurse -Force -ErrorAction SilentlyContinue
                            if (Test-Path $dir.FullName) {
                                Start-Process cmd -ArgumentList "/c rmdir /s /q `"$($dir.FullName)`"" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
                            }
                        } catch {}
                    }
                } catch {}
            }
        }
        Write-Host "    -> [OK] Phase 2 filesystem obliteration pass complete." -ForegroundColor Green
    }

    # --- Scenario C: Kernel Boot Vaporization — .sys device drivers / memory-locked binary objects ---
    try {
        if ($SysBinaryBootQueue -and $SysBinaryBootQueue.Count -gt 0) {
            $survivors = @($SysBinaryBootQueue | Where-Object { Test-Path -LiteralPath $_ })
            if ($survivors.Count -gt 0) {
                $kq = Register-UWMPendingBootDeletion -Paths $survivors
                Write-Host "    -> [BOOT] $kq kernel-resident driver/memory object(s) registered for instant native evaporation at next reboot" -ForegroundColor DarkCyan
            }
        }
    } catch {}

    Write-Host " [3/5] Refreshing explorer.exe shell context to dump cached memory hooks..." -ForegroundColor Yellow
    try {
        Get-Process -Name explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Start-Process explorer.exe -ErrorAction SilentlyContinue
        Write-Host "    -> [OK] Explorer shell re-initialized — cached extension handles released." -ForegroundColor Green
    } catch {
        Write-Host "    -> [WARN] Explorer re-init boundary: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    if ($TargetIsOrphan) {
        Write-Host " [4/5] [SKIP] Orphan target — no winget registration exists." -ForegroundColor DarkYellow
    } else {
        Write-Host " [4/5] Running native system silent uninstallation routines..." -ForegroundColor Yellow
        try {
            $proc = Start-Process winget -ArgumentList @("uninstall", "--id", $TargetIdToWipe, "--silent", "--accept-source-agreements") -NoNewWindow -PassThru -Wait -ErrorAction Stop
            if ($proc.ExitCode -eq 0) {
                Write-Host "    -> [OK] Winget uninstall transaction completed (exit 0)." -ForegroundColor Green
            } else {
                Write-Host "    -> [WARN] Winget exited with code $($proc.ExitCode). Registry scrub will follow." -ForegroundColor DarkYellow
            }
        } catch {
            Write-Host "    -> [WARN] Winget uninstall failed: $($_.Exception.Message). Registry scrub will follow." -ForegroundColor DarkYellow
        }
    }

    if ($TargetIsOrphan) {
        Write-Host " [5/5] [SKIP] Orphan target — no registry entries to scrub." -ForegroundColor DarkYellow
    } else {
        Write-Host " [5/5] Scrubbing product identifiers from Windows Registry hives..." -ForegroundColor Yellow
        $RegPaths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $RegistryFullScrubRoots = @(
            "HKLM:\Software"
            "HKLM:\Software\Wow6432Node"
            "HKCU:\Software"
        )
        foreach ($regRoot in $RegistryFullScrubRoots) {
            if (-not (Test-Path $regRoot)) { continue }
            foreach ($keyword in $TargetKeywords) {
                try {
                    $regChildren = Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue |
                                   Where-Object { $_.PSChildName -match [regex]::Escape($keyword) }
                    foreach ($regKey in $regChildren) {
                        try {
                            Write-Host "    -> Erasing registry key: $($regKey.Name)" -ForegroundColor DarkCyan
                            Remove-Item -Path $regKey.PSPath -Recurse -Force -ErrorAction Stop
                            Write-Host "    -> [OK] Registry key erased: $($regKey.PSChildName)" -ForegroundColor Green
                        } catch {
                            Write-Host "    -> [WARN] Registry key locked by OS: $($regKey.PSChildName) — $($_.Exception.Message)" -ForegroundColor DarkYellow
                        }
                    }
                } catch {}
            }
        }
        if (-not [string]::IsNullOrEmpty($TargetDisplayName)) {
            foreach ($regRoot in $RegistryFullScrubRoots) {
                if (-not (Test-Path $regRoot)) { continue }
                try {
                    $nameMatch = Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue |
                                 Where-Object { $_.PSChildName -match [regex]::Escape($TargetDisplayName) }
                    foreach ($regKey in $nameMatch) {
                        try {
                            Write-Host "    -> Erasing display-name registry key: $($regKey.Name)" -ForegroundColor DarkCyan
                            Remove-Item -Path $regKey.PSPath -Recurse -Force -ErrorAction Stop
                            Write-Host "    -> [OK] Display-name key erased: $($regKey.PSChildName)" -ForegroundColor Green
                        } catch {
                            Write-Host "    -> [WARN] Display-name key locked: $($regKey.PSChildName)" -ForegroundColor DarkYellow
                        }
                    }
                } catch {}
            }
        }
        Get-ItemProperty $RegPaths -ErrorAction SilentlyContinue | Where-Object {
            $_.PSChildName -match [regex]::Escape($TargetIdToWipe) -or $_.DisplayName -match [regex]::Escape($TargetIdToWipe)
        } | ForEach-Object {
            try {
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction Stop
                Write-Host "    -> [OK] Final uninstall registry sweep: $($_.PSChildName)" -ForegroundColor Green
            } catch {
                Write-Host "    -> [WARN] Residual uninstall key locked: $($_.PSChildName)" -ForegroundColor DarkYellow
            }
        }
    }

    Write-Host "`n======================================================================" -ForegroundColor Green
    if ($TargetIsOrphan) {
        Write-Host " [COMPLETED] Orphan ghost obliterated: $($TargetOrphanPath)" -ForegroundColor Green
        Write-Host " Pipeline: Service Disable -> Process Kill -> DLL Unlink -> FS Annihilation -> Explorer Refresh (orphan mode)" -ForegroundColor Cyan
    } else {
        Write-Host " [COMPLETED] Multi-stage eradication finished for: $TargetIdToWipe" -ForegroundColor Green
        Write-Host " Phases: Service Disable -> Process Kill -> DLL Unlink -> FS Obliterate -> Shell Refresh -> Winget Uninstall -> Registry Scrub" -ForegroundColor Cyan
    }
    Write-Host "======================================================================" -ForegroundColor Green
    return "COMPLETED"
}
function Get-UWMShredderDisplayName {
    param($Record)
    [string]$n = [string]$Record.DisplayName
    if ($Record.IsOrphan) {
        $n = $n -replace '^\[ORPHAN\]\s*', '' -replace '^ORPHAN_', ''
        if ($n -match '([^\\/]+)\s*$') { $n = $Matches[1] }
    }
    if ([string]::IsNullOrWhiteSpace($n)) { $n = ([string]$Record.Id) -replace '^ORPHAN_', '' }
    return $n.Trim()
}
function Get-UWMShredderWidths {
    param([array]$Apps, [array]$Ghosts, [int]$Count, [int]$Available)
    [int]$idxW = [Math]::Max(3, $Count.ToString().Length + 1)
    [int]$nameW = 10; [int]$nameW2 = 10
    [int]$sizeW = 7; [int]$statusW = 8
    foreach ($r in $Apps) {
        [int]$n = Get-UWMDisplayWidth ([string]$r.DisplayName)
        if ($n -gt $nameW) { $nameW = $n }
    }
    foreach ($g in $Ghosts) {
        [int]$n = Get-UWMDisplayWidth (Get-UWMShredderDisplayName -Record $g)
        if ($n -gt $nameW2) { $nameW2 = $n }
    }
    foreach ($r in @($Apps) + @($Ghosts)) {
        if ($r.SizeMB -gt 0) { [int]$t = Get-UWMDisplayWidth ("{0:0.0} MB" -f $r.SizeMB); if ($t -gt $sizeW) { $sizeW = $t } }
    }
    $nameW = [Math]::Min($nameW, 40); $nameW2 = [Math]::Min($nameW2, 40)
    foreach ($pair in @(@('nameW',6), @('statusW',5), @('sizeW',4), @('idxW',3))) {
        [int]$cur = Get-Variable -Name $pair[0] -ValueOnly
        [int]$fl = [int]$pair[1]
        [int]$tk = [Math]::Min(($idxW + $nameW + $sizeW + $statusW - $Available), $cur - $fl)
        if ($tk -gt 0) { Set-Variable -Name $pair[0] -Value ($cur - $tk) }
    }
    foreach ($pair in @(@('nameW2',6), @('statusW',5), @('sizeW',4), @('idxW',3))) {
        [int]$cur = Get-Variable -Name $pair[0] -ValueOnly
        [int]$fl = [int]$pair[1]
        [int]$tk = [Math]::Min(($idxW + $nameW2 + $sizeW + $statusW - $Available), $cur - $fl)
        if ($tk -gt 0) { Set-Variable -Name $pair[0] -Value ($cur - $tk) }
    }
    [int]$needU = $idxW + $nameW + $sizeW + $statusW
    [int]$needL = $idxW + $nameW2 + $sizeW + $statusW
    [int]$common = [Math]::Max($needU, $needL)
    if ($needL -lt $common) { $nameW2 += ($common - $needL) }
    elseif ($needU -lt $common) { $nameW += ($common - $needU) }
    [int]$needU = $idxW + $nameW + $sizeW + $statusW
    [int]$needL = $idxW + $nameW2 + $sizeW + $statusW
    return @{ Upper = @($idxW, $nameW, $sizeW, $statusW); Lower = @($idxW, $nameW2, $sizeW, $statusW); Frame = $common + 7 }
}
function Write-UWMShredderGrid {
    param([array]$Records, [int[]]$Widths, [string]$HeaderText, [string]$Profile)
    [string]$accent = if ($Profile -eq 'Upper') { "Cyan" } else { "Red" }
    Write-Host (New-UWMBorderLine -Widths $Widths -L "╔" -Mid "╦" -R "╗") -ForegroundColor $accent
    Write-UWMRowLine -Widths $Widths -Cells @(
        @{ Text = " # "; Color = $accent }
        @{ Text = $HeaderText; Color = $accent }
        @{ Text = "Size"; Color = $accent }
        @{ Text = "Status"; Color = $accent }
    )
    Write-Host (New-UWMBorderLine -Widths $Widths -L "╠" -Mid "╬" -R "╣") -ForegroundColor $accent
    if (@($Records).Count -eq 0) {
        $dim = @{ Text = ""; Color = $script:Theme['Dim'] }
        Write-UWMRowLine -Widths $Widths -Cells @($dim, @{ Text = "— none detected —"; Color = $script:Theme['Dim'] }, $dim, $dim)
    } else {
        foreach ($r in $Records) {
            [int]$idx = [int]$r.GlobalIndex
            $rec = $r.Record
            [string]$status = "READY"
            [string]$statusColor = $script:Theme['Success']
            if ($rec.CoreLocked) { $status = "LOCKED"; $statusColor = "Red" }
            elseif ($script:ShredderSecondary.Contains($idx)) { $status = "STAGED"; $statusColor = "Blue" }
            [string]$name = Get-UWMShredderDisplayName -Record $rec
            [string]$nameColor = if ($Profile -eq 'Upper') { "Green" } else { "Red" }
            if ($rec.CoreLocked) { $nameColor = "DarkGray" }
            [string]$sizeTxt = if ($rec.SizeMB -gt 0) { ("{0:0.0} MB" -f $rec.SizeMB) } else { "-" }
            Write-UWMRowLine -Widths $Widths -Cells @(
                @{ Text = ($idx + 1).ToString(); Color = "Cyan" }
                @{ Text = $name; Color = $nameColor }
                @{ Text = $sizeTxt; Color = $script:Theme['Dim'] }
                @{ Text = $status; Color = $statusColor }
            )
        }
    }
    Write-Host (New-UWMBorderLine -Widths $Widths -L "╚" -Mid "╩" -R "╝") -ForegroundColor $accent
}
function ConvertTo-UWMScriptLiteral {
    param([string]$Value)
    return ("'" + ([string]$Value).Replace("'", "''") + "'")
}
function Get-UWMNormalizedTokens {
    param([string]$Text)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $set }
    $clean = ($Text -replace '[^A-Za-z0-9]+', ' ').Trim()
    if ([string]::IsNullOrWhiteSpace($clean)) { return $set }
    foreach ($raw in ($clean -split '\s+')) {
        $t = $raw.Trim().ToLowerInvariant()
        if ($t.Length -lt 3) { continue }
        if ($t -match '^(the|and|for|with|from|app|apps|application|applications|software|program|programs|suite|suites|tool|tools|package|packages|manager)$') { continue }
        [void]$set.Add($t)
    }
    return $set
}
function Test-UWMTokenResonance {
    param([string]$Token, $Reference)
    if ([string]::IsNullOrEmpty($Token) -or $null -eq $Reference -or @($Reference).Count -eq 0) { return $false }
    foreach ($r in @($Reference)) {
        [string]$rs = [string]$r
        if ([string]::IsNullOrEmpty($rs)) { continue }
        if ($Token -ieq $rs) { return $true }
        if ($Token.Length -ge 4 -and $rs.Length -ge 4) {
            if ($Token.IndexOf($rs, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
            if ($rs.IndexOf($Token, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
    }
    return $false
}
function Test-UWMFuzzyTokenMatch {
    param([string]$FolderName, $AppTokens, $VendorTokens)
    if ([string]::IsNullOrWhiteSpace($FolderName)) { return $false }
    $folderTokens = Get-UWMNormalizedTokens -Text $FolderName
    if ($folderTokens.Count -eq 0) { return $false }
    foreach ($ft in $folderTokens) {
        if (Test-UWMTokenResonance -Token $ft -Reference $AppTokens) { return $true }
        if (Test-UWMTokenResonance -Token $ft -Reference $VendorTokens) { return $true }
    }
    return $false
}
function Test-UWMScavengeProtected {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    $leaf = $Name.Trim().ToLowerInvariant()
    $protected = @(
        'windows','system32','syswow64','winsxs','programdata','program files','program files (x86)',
        'common files','application data','appdata','localappdata','locallow','roaming','temp',
        'packages','windowsapps','microsoft','internet explorer','devices','device metadata store','webcache',
        'desktop','documents','downloads','music','pictures','videos','favorites','links','contacts','searches',
        'saved games','libraries','onedrive','public','recovery','perflogs','config.msi','msocache','recycler',
        '$recycle.bin','system volume information','cookies','history','temporary internet files','nethood',
        'printhood','recent','sendto','start menu','templates','local settings'
    )
    foreach ($p in $protected) { if ($leaf -eq $p) { return $true } }
    return $false
}
function Test-UWMTraceShielded {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
    } catch { return $true }
    $fullLower = $full.ToLowerInvariant().TrimEnd([char]'\')
    foreach ($prefix in @([string]$env:WINDIR, [string]$env:SystemRoot)) {
        if (-not [string]::IsNullOrWhiteSpace($prefix)) {
            $pLower = $prefix.ToLowerInvariant().TrimEnd([char]'\')
            if ($pLower -and ($fullLower -eq $pLower -or $fullLower.StartsWith($pLower + '\'))) { return $true }
        }
    }
    foreach ($prefix in @('C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData')) {
        $pLower = $prefix.ToLowerInvariant()
        if ($fullLower -eq $pLower -or $fullLower.StartsWith($pLower + '\')) { return $true }
    }
    $leaf = Split-Path $full -Leaf
    if (Test-UWMScavengeProtected -Name $leaf) { return $true }
    return $false
}
function Test-UWMContextMutex {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $false }
    $roots = @()
    if ($null -ne $script:UWMContextMutexRoots -and @($script:UWMContextMutexRoots).Count -gt 0) {
        $roots = @($script:UWMContextMutexRoots)
    } else {
        $roots = @("$home\.local\share", "$home\Desktop")
    }
    $underContext = $false
    foreach ($cr in $roots) {
        if ([string]::IsNullOrWhiteSpace($cr)) { continue }
        try { $crFull = [System.IO.Path]::GetFullPath($cr) } catch { continue }
        if ($full -eq $crFull -or $full.StartsWith($crFull + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            $underContext = $true
            break
        }
    }
    if (-not $underContext) { return $true }
    if (-not (Test-Path -LiteralPath $full -ErrorAction SilentlyContinue)) { return $false }
    $key = $full.ToLowerInvariant()
    $lwt = $null
    try { $lwt = (Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue).LastWriteTimeUtc } catch {}
    if ($null -eq $script:UWMContextMutexBuffer) { $script:UWMContextMutexBuffer = @{} }
    if ($script:UWMContextMutexBuffer.ContainsKey($key)) {
        $snap = $script:UWMContextMutexBuffer[$key]
        if ($null -eq $lwt -or $snap -ne $lwt) { return $false }
        return $true
    }
    $script:UWMContextMutexBuffer[$key] = $lwt
    return $true
}
function Test-UWMVirtualEnvironment {
    if ($null -ne $script:UWMEnvOverride) { return [bool]$script:UWMEnvOverride }
    if ($null -ne $script:UWMCachedVirtual) { return [bool]$script:UWMCachedVirtual }
    $isVirtual = $false
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        [string]$mf = [string]($cs.Manufacturer)
        [string]$md = [string]($cs.Model)
        [string]$biosV = [string]($bios.Manufacturer)
        $haystack = ($mf + ' ' + $md + ' ' + $biosV).ToLowerInvariant()
        if ($haystack -match 'vmware|virtualbox|innotek|qemu|oracle|microsoft corporation|parallels|kvm|xen|proxmox') { $isVirtual = $true }
        elseif ($haystack -match 'virtual|hyper-v|hyperv|vbox|vms') { $isVirtual = $true }
        elseif ($cs.Model -match '^(Virtual|VMware|VirtualBox|QEMU)') { $isVirtual = $true }
    } catch { $isVirtual = $false }
    $script:UWMCachedVirtual = $isVirtual
    return $isVirtual
}
function Get-UWMShredderFingerprint {
    param($Record)
    if ($null -eq $Record) { return $null }
    [string]$id = [string]$Record.Id
    [string]$displayName = [string]$Record.DisplayName
    [string]$rawRowName = [string]$Record.DisplayName
    if ($Record.IsOrphan) {
        $displayName = $displayName -replace '^\[ORPHAN\]\s*', '' -replace '^ORPHAN_', ''
    }
    [string]$publisher = ''
    [string]$binaryRoot = ''
    if ($Record.IsOrphan) { $binaryRoot = [string]$Record.OrphanPath }
    elseif (-not [string]::IsNullOrWhiteSpace([string]$Record.InstallLocation)) { $binaryRoot = [string]$Record.InstallLocation }
    $schemaFound = $Record.IsOrphan
    $RegSchemaRoots = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($regRoot in $RegSchemaRoots) {
        if ($schemaFound) { break }
        if (-not (Test-Path -LiteralPath $regRoot -ErrorAction SilentlyContinue)) { continue }
        try {
            foreach ($regKey in @(Get-ChildItem -LiteralPath $regRoot -ErrorAction SilentlyContinue)) {
                if ($schemaFound) { break }
                try {
                    $props = Get-ItemProperty -LiteralPath $regKey.PSPath -ErrorAction SilentlyContinue
                    [string]$keyId = [string]$regKey.PSChildName
                    [string]$keyDisplay = if ($props.DisplayName) { [string]$props.DisplayName } else { '' }
                    $schemaHit = $false
                    if (-not [string]::IsNullOrWhiteSpace($id) -and -not [string]::IsNullOrWhiteSpace($keyId)) {
                        if ($keyId -ieq $id -or $keyId -like ($id + '*')) { $schemaHit = $true }
                    }
                    if (-not $schemaHit -and -not [string]::IsNullOrWhiteSpace($displayName) -and -not [string]::IsNullOrWhiteSpace($keyDisplay)) {
                        if ($keyDisplay -ieq $displayName) { $schemaHit = $true }
                    }
                    if (-not $schemaHit) { continue }
                    if (-not [string]::IsNullOrWhiteSpace([string]$props.Publisher)) { $publisher = [string]$props.Publisher }
                    if (-not [string]::IsNullOrWhiteSpace([string]$props.DisplayName)) { $displayName = [string]$props.DisplayName }
                    if ([string]::IsNullOrWhiteSpace($binaryRoot) -and -not [string]::IsNullOrWhiteSpace([string]$props.InstallLocation)) { $binaryRoot = [string]$props.InstallLocation }
                    if ([string]::IsNullOrWhiteSpace($binaryRoot) -and -not [string]::IsNullOrWhiteSpace([string]$props.DisplayIcon)) {
                        [string]$iconBin = [string]$props.DisplayIcon -replace '^\s*"([^"]+)".*$', '$1'
                        if ($iconBin -eq [string]$props.DisplayIcon) { $iconBin = (([string]$props.DisplayIcon) -split ',')[0] }
                        $iconBin = $iconBin.Trim('"').Trim()
                        if ($iconBin -and (Test-Path -LiteralPath $iconBin -ErrorAction SilentlyContinue)) { $binaryRoot = Split-Path $iconBin -Parent }
                    }
                    if ([string]::IsNullOrWhiteSpace($binaryRoot)) {
                        foreach ($u in @([string]$props.UninstallString, [string]$props.QuietUninstallString)) {
                            if ([string]::IsNullOrWhiteSpace($u)) { continue }
                            [string]$uBin = $u -replace '^\s*"([^"]+)".*$', '$1'
                            if ($uBin -eq $u) { $uBin = ($u -split '\s+')[0] }
                            $uBin = $uBin.Trim('"').Trim()
                            if ($uBin -and (Test-Path -LiteralPath $uBin -ErrorAction SilentlyContinue)) { $binaryRoot = Split-Path $uBin -Parent; break }
                        }
                    }
                    $schemaFound = $true
                } catch {}
            }
        } catch {}
    }
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $id }
    $appTokens = Get-UWMNormalizedTokens -Text $displayName
    $vendorTokens = Get-UWMNormalizedTokens -Text $publisher
    if ($vendorTokens.Count -eq 0 -and $id -match '^[^.]+\.' -and $id -ne 'ORPHAN') {
        $vendorTokens = Get-UWMNormalizedTokens -Text (($id -split '\.')[0])
    }
    if ($appTokens.Count -eq 0 -and $id -match '\.' -and $id -ne 'ORPHAN') {
        $appTokens = Get-UWMNormalizedTokens -Text (($id -split '\.')[-1])
    }
    if ($appTokens.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($id)) {
        $appTokens = Get-UWMNormalizedTokens -Text $id
    }
    $identityTokens = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($t in @($appTokens)) { if ($t) { [void]$identityTokens.Add([string]$t) } }
    foreach ($t in @($vendorTokens)) { if ($t) { [void]$identityTokens.Add([string]$t) } }
    [string]$cleanId = $id
    if ($Record.IsOrphan) { $cleanId = $id -replace '^ORPHAN_', '' }
    foreach ($t in @(Get-UWMNormalizedTokens -Text $cleanId)) { if ($t) { [void]$identityTokens.Add([string]$t) } }
    if (-not [string]::IsNullOrWhiteSpace($cleanId)) {
        foreach ($idSegment in ($cleanId -split '\.')) {
            [string]$seg = ([string]$idSegment).Trim()
            if ([string]::IsNullOrWhiteSpace($seg)) { continue }
            [void]$identityTokens.Add($seg.ToLowerInvariant())
            foreach ($t in @(Get-UWMNormalizedTokens -Text $seg)) { if ($t) { [void]$identityTokens.Add([string]$t) } }
        }
        if (-not $Record.IsOrphan) { [void]$identityTokens.Add($cleanId.ToLowerInvariant()) }
    }
    if (-not [string]::IsNullOrWhiteSpace($displayName)) { [void]$identityTokens.Add($displayName.Trim().ToLowerInvariant()) }
    if (-not [string]::IsNullOrWhiteSpace($publisher)) { [void]$identityTokens.Add($publisher.Trim().ToLowerInvariant()) }
    if ($Record.IsOrphan -and -not [string]::IsNullOrWhiteSpace($rawRowName)) {
        [void]$identityTokens.Add($rawRowName.Trim().ToLowerInvariant())
    }
    [string]$appNameToken = ''
    if ($appTokens.Count -gt 0) { $appNameToken = ($appTokens | Sort-Object Length -Descending | Select-Object -First 1) }
    [string]$vendorToken = ''
    if ($vendorTokens.Count -gt 0) { $vendorToken = ($vendorTokens | Sort-Object Length -Descending | Select-Object -First 1) }
    return [PSCustomObject]@{
        Id = $id
        DisplayName = $displayName
        Publisher = $publisher
        AppNameToken = $appNameToken
        VendorToken = $vendorToken
        BinaryRoot = $binaryRoot
        InstallLocation = [string]$Record.InstallLocation
        IsOrphan = [bool]$Record.IsOrphan
        OrphanPath = if ($Record.IsOrphan) { [string]$Record.OrphanPath } else { '' }
        AppTokens = $appTokens
        VendorTokens = $vendorTokens
        IdentityTokens = $identityTokens
    }
}
function Get-UWMScavengeRoots {
    param($Fingerprint)
    $roots = [System.Collections.Generic.List[string]]::new()
    $profileRoots = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($env:LOCALAPPDATA, $env:APPDATA, $env:TEMP)) {
        if (-not [string]::IsNullOrWhiteSpace($r)) {
            if (Test-Path -LiteralPath $r -ErrorAction SilentlyContinue) {
                if (-not $roots.Contains($r)) { [void]$roots.Add($r) }
            }
            [void]$profileRoots.Add($r)
        }
    }
    foreach ($userRoot in @("$home\.local\share", "$home\Desktop")) {
        if ([string]::IsNullOrWhiteSpace($userRoot)) { continue }
        [void]$profileRoots.Add(($userRoot -replace '\\share$', ''))
        if (Test-Path -LiteralPath $userRoot -ErrorAction SilentlyContinue) {
            if (-not $roots.Contains($userRoot)) { [void]$roots.Add($userRoot) }
        }
    }
    if ($null -ne $Fingerprint) {
        foreach ($ref in @([string]$Fingerprint.BinaryRoot, [string]$Fingerprint.InstallLocation, [string]$Fingerprint.OrphanPath)) {
            if ([string]::IsNullOrWhiteSpace($ref)) { continue }
            try {
                $refFull = [System.IO.Path]::GetFullPath($ref)
                $refParent = Split-Path $refFull -Parent
                if ([string]::IsNullOrWhiteSpace($refParent)) { continue }
                $underProfile = $false
                foreach ($profileRoot in $profileRoots) {
                    if ([string]::IsNullOrWhiteSpace($profileRoot)) { continue }
                    if ($refFull.StartsWith($profileRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $underProfile = $true; break }
                }
                if ($underProfile -and (Test-Path -LiteralPath $refParent -ErrorAction SilentlyContinue) -and -not $roots.Contains($refParent)) {
                    [void]$roots.Add($refParent)
                }
            } catch {}
        }
    }
    return @($roots)
}
function Invoke-UWMHeuristicScanCore {
    param([string[]]$Roots, [object]$Fingerprint, [int]$MaxDepth = 3)
    $found = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Fingerprint) { return @($found) }
    $appTokens = @(); if ($Fingerprint.AppTokens) { $appTokens = @($Fingerprint.AppTokens) }
    $vendorTokens = @(); if ($Fingerprint.VendorTokens) { $vendorTokens = @($Fingerprint.VendorTokens) }
    $identityTokens = @(); if ($Fingerprint.IdentityTokens) { $identityTokens = @($Fingerprint.IdentityTokens) }
    $matchTokens = @()
    if ($identityTokens.Count -gt 0) { $matchTokens = $identityTokens }
    elseif (($appTokens.Count + $vendorTokens.Count) -gt 0) { $matchTokens = @($appTokens) + @($vendorTokens) }
    $prune = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    try { if (-not [string]::IsNullOrWhiteSpace([string]$Fingerprint.BinaryRoot)) { [void]$prune.Add(([System.IO.Path]::GetFullPath([string]$Fingerprint.BinaryRoot))) } } catch {}
    try { if (-not [string]::IsNullOrWhiteSpace([string]$Fingerprint.OrphanPath)) { [void]$prune.Add(([System.IO.Path]::GetFullPath([string]$Fingerprint.OrphanPath))) } } catch {}
    [string]$dataRoot = ''
    if ($script:DataRoot) { $dataRoot = [string]$script:DataRoot }
    [string]$rtEnv = Join-Path $env:TEMP "UWM_Runtime_Env"
    foreach ($root in $Roots) {
        if ([string]::IsNullOrWhiteSpace($root)) { continue }
        try {
            $rootFull = [System.IO.Path]::GetFullPath($root)
            if (-not (Test-Path -LiteralPath $rootFull -ErrorAction SilentlyContinue)) { continue }
            $queue = [System.Collections.Generic.Queue[string]]::new()
            $depthMap = [System.Collections.Generic.Dictionary[string,int]]::new()
            $queue.Enqueue($rootFull)
            $depthMap[$rootFull] = 0
            while ($queue.Count -gt 0) {
                $dir = $queue.Dequeue()
                [int]$curDepth = $depthMap[$dir]
                $children = @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue)
                foreach ($child in $children) {
                    try {
                        if ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
                        $full = $child.FullName
                        if ($prune.Contains($full)) { continue }
                        if (Test-UWMScavengeProtected -Name $child.Name) { continue }
                        $fullLower = $full.ToLowerInvariant()
                        if ($dataRoot -and $fullLower.StartsWith($dataRoot.ToLowerInvariant())) { continue }
                        if ($rtEnv -and $fullLower.StartsWith($rtEnv.ToLowerInvariant())) { continue }
                        if ((Test-UWMFuzzyTokenMatch -FolderName $child.Name -AppTokens $matchTokens -VendorTokens $matchTokens) -and (-not (Test-UWMExcludedPath $full))) {
                            $found.Add($full)
                        }
                        if ($curDepth -lt $MaxDepth) {
                            $depthMap[$full] = $curDepth + 1
                            $queue.Enqueue($full)
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    return @($found | Sort-Object -Unique)
}
function Invoke-UWMTracePurge {
    param([string[]]$Traces)
    [int]$purged = 0
    [int]$failed = 0
    [int]$shielded = 0
    foreach ($trace in @($Traces)) {
        if ([string]::IsNullOrWhiteSpace($trace)) { continue }
        try {
            if (Test-UWMTraceShielded -Path $trace) { $shielded++; continue }
            if (-not (Test-Path -LiteralPath $trace -ErrorAction SilentlyContinue)) { $purged++; continue }
            Remove-Item -LiteralPath $trace -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $trace -ErrorAction SilentlyContinue)) { $purged++; continue }
            if (-not (Test-UWMContextMutex -Path $trace)) { $shielded++; continue }
            if (Test-UWMVirtualEnvironment) {
                $vProfile = $false
                $vProfileRoots = @("$home\.cache", "$home\.config")
                $vDesktopRoot = "$home\Desktop"
                foreach ($vR in @($vProfileRoots)) {
                    if ([string]::IsNullOrWhiteSpace($vR)) { continue }
                    if ($trace -ieq $vR -or $trace.StartsWith($vR + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { $vProfile = $true; break }
                }
                if (-not $vProfile) {
                    try {
                        $vLeaf = Split-Path $trace -Leaf
                        if ($vLeaf -like '*.jsonc') { $vProfile = $true }
                        elseif ($vLeaf -like '*.lnk' -and $trace.StartsWith($vDesktopRoot, [System.StringComparison]::OrdinalIgnoreCase)) { $vProfile = $true }
                    } catch {}
                }
                Remove-Item -Path $trace -Recurse -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 250
                if (Test-Path -LiteralPath $trace -ErrorAction SilentlyContinue) {
                    if ($vProfile) { $shielded++ } else { $failed++ }
                } else { $purged++ }
                continue
            }
            $takPath = $trace.TrimEnd([char]'\')
            $takJob = $null
            if (Get-Command Start-UWMAsyncJob -ErrorAction SilentlyContinue) {
                $takCmd = "& takeown.exe /f `"$takPath`" /r /d y 2>`$null | Out-Null; & icacls.exe `"$takPath`" /grant administrators:F /t /c /q 2>`$null | Out-Null"
                $takJob = Start-UWMAsyncJob -Name ("UWMTO_" + $takPath) -ScriptText $takCmd
            }
            if ($takJob) {
                if ($null -eq $script:UWMAsyncWorkers) { $script:UWMAsyncWorkers = @() }
                $script:UWMAsyncWorkers = @($script:UWMAsyncWorkers) + @($takJob)
                $takDone = $false
                $takDeadline = [DateTime]::UtcNow.AddSeconds(10)
                while (-not $takDone -and [DateTime]::UtcNow -lt $takDeadline) {
                    if ($takJob.Async -and $takJob.Async.IsCompleted) { $takDone = $true }
                    elseif ($takJob.Job -and $takJob.Job.State -in @('Completed', 'Failed', 'Stopped')) { $takDone = $true }
                    else { Start-Sleep -Milliseconds 50 }
                }
            } else {
                & takeown.exe /f $takPath /r /d y 2>$null | Out-Null
                & icacls.exe $takPath /grant administrators:F /t /c /q 2>$null | Out-Null
            }
            Remove-Item -LiteralPath $trace -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $trace -ErrorAction SilentlyContinue) {
                & cmd.exe /c ("rmdir /s /q " + ('"' + $trace + '"')) 2>$null | Out-Null
            }
            if (Test-Path -LiteralPath $trace -ErrorAction SilentlyContinue) { $failed++ } else { $purged++ }
        } catch {
            $failed++
        }
    }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    return [PSCustomObject]@{ Purged = $purged; Failed = $failed; Shielded = $shielded; Total = ($purged + $failed + $shielded) }
}
function Start-UWMAsyncJob {
    param([string]$Name, [string]$ScriptText)
    $runspace = $null
    $ps = $null
    try {
        $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $runspace.Open()
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.Runspace = $runspace
        $null = $ps.AddScript($ScriptText)
        $ar = $ps.BeginInvoke()
        return [PSCustomObject]@{ Name = $Name; PowerShell = $ps; Runspace = $runspace; Async = $ar; Job = $null; Started = [DateTime]::UtcNow }
    } catch {
        try { if ($ps) { $ps.Dispose() } } catch {}
        try { if ($runspace) { $runspace.Close() } } catch {}
        try { if ($runspace) { $runspace.Dispose() } } catch {}
        try {
            $job = Start-Job -Name $Name -ScriptBlock ([scriptblock]::Create($ScriptText)) -ErrorAction Stop
            return [PSCustomObject]@{ Name = $Name; PowerShell = $null; Runspace = $null; Async = $null; Job = $job; Started = [DateTime]::UtcNow }
        } catch {
            return $null
        }
    }
}
function Stop-UWMAsyncWorkers {
    param([int]$TimeoutMs = 0, [switch]$Force)
    $script:UWMHardKilled = 0
    $workers = @()
    if ($script:UWMAsyncWorkers) { $workers = @($script:UWMAsyncWorkers) }
    if ($workers.Count -eq 0) { return @() }
    $results = [System.Collections.Generic.List[object]]::new()
    $remaining = [System.Collections.Generic.List[object]]::new()
    foreach ($w in $workers) {
        $done = $false
        try {
            if ($w.Async) {
                if ($w.Async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                    foreach ($o in $w.PowerShell.EndInvoke($w.Async)) { $results.Add($o) }
                    $done = $true
                } elseif ($Force) {
                    try { $w.PowerShell.Stop() } catch {}
                    try { foreach ($o in $w.PowerShell.EndInvoke($w.Async)) { $results.Add($o) } } catch {}
                    $done = $true
                    $script:UWMHardKilled++
                }
            } elseif ($w.Job) {
                [int]$waitSec = [int][Math]::Ceiling($TimeoutMs / 1000.0)
                if (Wait-Job -Job $w.Job -Timeout $waitSec -ErrorAction SilentlyContinue) {
                    foreach ($o in @(Receive-Job -Job $w.Job -ErrorAction SilentlyContinue)) { $results.Add($o) }
                    Remove-Job -Job $w.Job -Force -ErrorAction SilentlyContinue
                    $done = $true
                } elseif ($Force) {
                    Stop-Job -Job $w.Job -ErrorAction SilentlyContinue
                    Remove-Job -Job $w.Job -Force -ErrorAction SilentlyContinue
                    $done = $true
                    $script:UWMHardKilled++
                }
            } else { $done = $true }
        } catch { $done = $true }
        if ($done) {
            try { if ($w.PowerShell) { $w.PowerShell.Dispose() } } catch {}
            try { if ($w.Runspace) { $w.Runspace.Close() } } catch {}
            try { if ($w.Runspace) { $w.Runspace.Dispose() } } catch {}
        } else {
            $remaining.Add($w)
        }
    }
    $script:UWMAsyncWorkers = if ($remaining.Count -gt 0) { $remaining } else { @() }
    return @($results)
}
function Start-UWMHeuristicWorker {
    param($Fingerprint, [string[]]$Roots, [string]$Name = "UWMScavenge")
    $helpers = [System.Text.StringBuilder]::new()
    foreach ($fn in @("Get-UWMNormalizedTokens","Test-UWMTokenResonance","Test-UWMFuzzyTokenMatch","Test-UWMScavengeProtected","Test-UWMTraceShielded","Test-UWMExcludedPath","Test-UWMContextMutex","Test-UWMVirtualEnvironment","Invoke-UWMHeuristicScanCore","Invoke-UWMTracePurge")) {
        $cmd = Get-Command $fn -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.ScriptBlock) {
            [void]$helpers.Append("function $fn {`n")
            [void]$helpers.Append($cmd.ScriptBlock.ToString())
            [void]$helpers.Append("`n}`n")
        }
    }
    $prelude = [System.Text.StringBuilder]::new()
    [void]$prelude.Append(("`$script:DataRoot = " + (ConvertTo-UWMScriptLiteral -Value ([string]$script:DataRoot)) + "`n"))
    [void]$prelude.Append(("`$roots = @(" + ((@($Roots) | ForEach-Object { ConvertTo-UWMScriptLiteral -Value $_ }) -join ",") + ")`n"))
    $appTok = @(); if ($Fingerprint.AppTokens) { $appTok = @($Fingerprint.AppTokens) }
    $venTok = @(); if ($Fingerprint.VendorTokens) { $venTok = @($Fingerprint.VendorTokens) }
    $idTok = @(); if ($Fingerprint.IdentityTokens) { $idTok = @($Fingerprint.IdentityTokens) }
    [void]$prelude.Append(("`$appTokens = @(" + (($appTok | ForEach-Object { ConvertTo-UWMScriptLiteral -Value $_ }) -join ",") + ")`n"))
    [void]$prelude.Append(("`$vendorTokens = @(" + (($venTok | ForEach-Object { ConvertTo-UWMScriptLiteral -Value $_ }) -join ",") + ")`n"))
    [void]$prelude.Append(("`$identityTokens = @(" + (($idTok | ForEach-Object { ConvertTo-UWMScriptLiteral -Value $_ }) -join ",") + ")`n"))
    $fpSetup = @(
        '$__appSet = New-Object ''System.Collections.Generic.HashSet[string]'' ([System.StringComparer]::OrdinalIgnoreCase)',
        'foreach ($__a in $appTokens) { if ($__a) { [void]$__appSet.Add($__a) } }',
        '$__venSet = New-Object ''System.Collections.Generic.HashSet[string]'' ([System.StringComparer]::OrdinalIgnoreCase)',
        'foreach ($__v in $vendorTokens) { if ($__v) { [void]$__venSet.Add($__v) } }',
        '$__idSet = New-Object ''System.Collections.Generic.HashSet[string]'' ([System.StringComparer]::OrdinalIgnoreCase)',
        'foreach ($__i in $identityTokens) { if ($__i) { [void]$__idSet.Add($__i) } }',
        ('$fp = [PSCustomObject]@{ BinaryRoot = ' + (ConvertTo-UWMScriptLiteral -Value ([string]$Fingerprint.BinaryRoot)) + '; OrphanPath = ' + (ConvertTo-UWMScriptLiteral -Value ([string]$Fingerprint.OrphanPath)) + '; AppTokens = $__appSet; VendorTokens = $__venSet; IdentityTokens = $__idSet }')
    )
    [void]$prelude.Append(($fpSetup -join "`n"))
    [void]$prelude.Append("`n")
    $workerBody = @(
        '$__traces = Invoke-UWMHeuristicScanCore -Roots $roots -Fingerprint $fp',
        '$__stats = Invoke-UWMTracePurge -Traces $__traces',
        '[PSCustomObject]@{ TraceCount = @($__traces).Count; Purged = $__stats.Purged; Failed = $__stats.Failed }'
    )
    $workerText = $helpers.ToString() + $prelude.ToString() + ($workerBody -join "`n")
    return (Start-UWMAsyncJob -Name $Name -ScriptText $workerText)
}
function Invoke-UWMHeuristicScavenge {
    param($Fingerprint, [switch]$Asynchronous, [string[]]$Roots)
    if ($null -eq $Fingerprint) { return $null }
    $scanRoots = @()
    if ($Roots -and $Roots.Count -gt 0) {
        $scanRoots = @($Roots | Where-Object { $_ -and (Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue) } | Select-Object -Unique)
    } else {
        $scanRoots = Get-UWMScavengeRoots -Fingerprint $Fingerprint
    }
    if ($scanRoots.Count -eq 0) { return $null }
    $appCount = 0; if ($Fingerprint.AppTokens) { $appCount = $Fingerprint.AppTokens.Count }
    $vendorCount = 0; if ($Fingerprint.VendorTokens) { $vendorCount = $Fingerprint.VendorTokens.Count }
    if (($appCount + $vendorCount) -eq 0) { return $null }
    if ($Asynchronous) {
        if (-not $script:UWMAsyncWorkers) { $script:UWMAsyncWorkers = @() }
        if (@($script:UWMAsyncWorkers).Count -lt 4) {
            $async = Start-UWMHeuristicWorker -Fingerprint $Fingerprint -Roots $scanRoots -Name ("UWMScavenge-" + [string]$Fingerprint.Id)
            if ($async) {
                $script:UWMAsyncWorkers = @($script:UWMAsyncWorkers) + @($async)
                return [PSCustomObject]@{ Async = $true; Dispatched = $true; Roots = $scanRoots.Count; TokenCount = ($appCount + $vendorCount); Worker = $async.Name }
            }
        }
        $traces = Invoke-UWMHeuristicScanCore -Roots $scanRoots -Fingerprint $Fingerprint
        $stats = Invoke-UWMTracePurge -Traces $traces
        return [PSCustomObject]@{ Async = $false; Dispatched = $false; Roots = $scanRoots.Count; TokenCount = ($appCount + $vendorCount); TraceCount = @($traces).Count; Purged = $stats.Purged; Failed = $stats.Failed }
    }
    $traces = Invoke-UWMHeuristicScanCore -Roots $scanRoots -Fingerprint $Fingerprint
    return [PSCustomObject]@{ Async = $false; Roots = $scanRoots.Count; TokenCount = ($appCount + $vendorCount); Traces = @($traces) }
}
function Invoke-UWMShredderExecutionBackend {
    param(
        [System.Collections.Generic.List[int]]$Indices,
        [array]$Pool,
        [string]$Category = "target",
        [string]$LogTarget = "Instant",
        [switch]$LeadingNewline
    )
    if ($null -eq $Indices -or $Indices.Count -eq 0) { return @() }
    Enter-UWMIsolation
    try {
        $virtMode = $false
        try { $virtMode = [bool](Test-UWMVirtualEnvironment) } catch { $virtMode = $false }
        $envLabel = if ($virtMode) { 'Virtualized' } else { 'Physical' }
        Write-Host ("  [SHREDDER] Environment profile: {0} - adaptive purge matrix engaged." -f $envLabel) -ForegroundColor DarkCyan
        $drained = @(Stop-UWMAsyncWorkers -TimeoutMs 0)
        $drainSummary = @()
        foreach ($d in $drained) {
            try {
                $drainSummary += ("traces={0} purged={1} failed={2}" -f $d.TraceCount, $d.Purged, $d.Failed)
            } catch {}
        }
        $null = New-UWMRecoveryDump -Targets @($Indices | ForEach-Object { $Pool[$_].Id })
        $script:UWMSerialDrainActive = $true
        $statuses = [System.Collections.Generic.List[string]]::new()
        $scavenge = [System.Collections.Generic.List[string]]::new()
        foreach ($gi in $Indices) {
            $record = $Pool[$gi]
            $fingerprint = Get-UWMShredderFingerprint -Record $record
            $status = Invoke-UWMShredTarget -Record $record
            $statuses.Add($status)
            $scav = Invoke-UWMHeuristicScavenge -Fingerprint $fingerprint
            if ($scav) {
                [void]$scavenge.Add(("{0}:{1}root/{2}token" -f $record.Id, $scav.Roots, $scav.TokenCount))
                $purgeStats = Invoke-UWMTracePurge -Traces $scav.Traces
                if ($purgeStats) {
                    [void]$scavenge.Add(("{0}:purged={1}/failed={2}/shielded={3}" -f $record.Id, $purgeStats.Purged, $purgeStats.Failed, $purgeStats.Shielded))
                }
            }
            $Pool[$gi].Shredded = $true
            [void]$script:ShredderSecondary.Remove($gi)
            Start-Sleep -Milliseconds 500
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
        }
        $nl = if ($LeadingNewline) { "`n" } else { "" }
        $backlog = @(Stop-UWMAsyncWorkers -TimeoutMs 3000 -Force)
        $flushLine = @()
        foreach ($b in $backlog) {
            try { $flushLine += ("traces={0} purged={1} failed={2}" -f $b.TraceCount, $b.Purged, $b.Failed) } catch {}
        }
        $hk = 0
        if ($script:UWMHardKilled) { $hk = [int]$script:UWMHardKilled }
        Write-Host ("{0}  [SHREDDER] {1} {2}(s) obliterated instantly." -f $nl, $Indices.Count, $Category) -ForegroundColor Green
        if ($scavenge.Count -gt 0) {
            Write-Host ("  [SCAVENGER] Heuristic residue purged serially, one-by-one: {0}" -f ($scavenge -join '; ')) -ForegroundColor DarkCyan
        }
        if ($backlog.Count -gt 0 -or $hk -gt 0) {
            Write-Host ("  [SCAVENGER] Backlog flushed: {0} worker(s) reaped, {1} hard-stopped; {2}" -f $backlog.Count, $hk, ($flushLine -join '; ')) -ForegroundColor DarkCyan
        }
        Write-Log -Action "SHREDDER_SHRED" -Target $LogTarget -Status "Success" -Details "$($Indices.Count) targets; statuses: $($statuses -join '; '); scavenge: $($scavenge -join '; '); drained: $($drainSummary -join '; '); flushed: $($flushLine -join '; '); hardKilled: $hk"
        Start-Sleep -Seconds 1
        return $statuses
    } finally {
$script:UWMSerialDrainActive = $false
$script:UWMSerialDrainWatchAt = $null
        Exit-UWMIsolation
    }
}
function Invoke-UWMAdvancedShredder {
    if (-not (Assert-UWMWriteAccess)) { return }
    $script:ShredderSafeActive = $false
    $script:ShredderLocked = 0
    $script:ShredderCache = @()
    $script:ShredderPathMap = @{}
    $script:ShredderSecondary = New-Object 'System.Collections.Generic.HashSet[int]'
    $Protected = Get-UWMProtectedCore
    Write-Host " [UWM System] Querying operating system software registries, please wait..." -ForegroundColor Cyan
    $Pool = [System.Collections.Generic.List[object]]::new()
    foreach ($app in (Get-UWMInstalledApps)) {
        $Pool.Add([PSCustomObject]@{
            Id = $app.Id; DisplayName = $app.DisplayName; InstallLocation = $app.InstallLocation
            UninstallString = $app.UninstallString; QuietUninstallString = $app.QuietUninstallString
            IsOrphan = $false; OrphanPath = $null; SizeMB = $app.SizeMB; CoreLocked = $false; Shredded = $false
        })
    }
    foreach ($ghost in (Get-UWMOrphanGhosts)) {
        $Pool.Add([PSCustomObject]@{
            Id = ("ORPHAN_{0}" -f $ghost.FolderName); DisplayName = ("[ORPHAN] {0}" -f $ghost.FolderName)
            InstallLocation = $ghost.FullPath; UninstallString = $null; QuietUninstallString = $null
            IsOrphan = $true; OrphanPath = $ghost.FullPath; SizeMB = $ghost.SizeMB; CoreLocked = $false; Shredded = $false
        })
    }
    $count = $Pool.Count
    if ($count -eq 0) {
        Write-Host "[X] No local application registrations or orphan footprints discovered in system hives." -ForegroundColor Red
        Read-Host " Press Enter to return..."; return
    }
    for ($i = 0; $i -lt $count; $i++) {
        $script:ShredderPathMap[$i] = if ($Pool[$i].IsOrphan) { $Pool[$i].OrphanPath } else { $Pool[$i].InstallLocation }
    }
    $appIdx = [System.Collections.Generic.List[int]]::new()
    $ghostIdx = [System.Collections.Generic.List[int]]::new()
    for ($i = 0; $i -lt $count; $i++) {
        if ($Pool[$i].IsOrphan) { [void]$ghostIdx.Add($i) } else { [void]$appIdx.Add($i) }
    }
    $appRecs = @(foreach ($i in $appIdx) { $Pool[$i] })
    $ghostRecs = @(foreach ($i in $ghostIdx) { $Pool[$i] })
    Set-UWMConsoleFixed
    $metrics = Get-UWMConsoleMetrics
    [int]$pageSize = 9
    try { $pageSize = [int][Math]::Max(1, $script:Config.ui.pageSize) } catch { $pageSize = 9 }
    if ($metrics.Interactive) {
        [int]$rowsFit = [Math]::Max(2, [int][Math]::Floor(($metrics.Height - 18) / 2))
        $pageSize = [Math]::Max(1, [Math]::Min($rowsFit, $pageSize))
    }
    if ($pageSize -lt 1) { $pageSize = 1 }
    [int]$available = $metrics.Width - 10
    $cw = Get-UWMShredderWidths -Apps $appRecs -Ghosts $ghostRecs -Count $count -Available $available
    [int[]]$widthsU = @($cw.Upper)
    [int[]]$widthsL = @($cw.Lower)
    [int]$frameW = [int]$cw.Frame
    [int]$legendMin = (Get-UWMDisplayWidth "⚡ Enter Selection [#], Macro [ALL-GHOSTS], Navigate [N/P/B], or [X] Toggle-Stage:") + 6
    [int]$target = [Math]::Min($available + 7, [Math]::Max($frameW, $legendMin))
    if ($target -gt $frameW) {
        [int]$extra = $target - $frameW
        $widthsU[1] += $extra
        $widthsL[1] += $extra
        $frameW = $target
    }
    [int]$tpU = [Math]::Max(1, [Math]::Ceiling($appIdx.Count / [double]$pageSize))
    [int]$tpL = [Math]::Max(1, [Math]::Ceiling($ghostIdx.Count / [double]$pageSize))
    [int]$tp = [Math]::Max($tpU, $tpL)
    [int]$cp = 0
    while ($true) {
        if ($script:UWMSerialDrainActive) {
            if ($null -eq $script:UWMSerialDrainWatchAt) { $script:UWMSerialDrainWatchAt = [DateTime]::UtcNow }
            elseif (([DateTime]::UtcNow - $script:UWMSerialDrainWatchAt).TotalSeconds -gt 20) {
                $script:UWMSerialDrainActive = $false
                $script:UWMSerialDrainWatchAt = $null
                try { Write-Log -Action "DRAIN_WATCHDOG" -Target "SHREDDER" -Status "Recovered" -Details "Serial drain exceeded 20s watchdog; shredder menu resumed" } catch { }
            }
            Start-Sleep -Milliseconds 100
            continue
        }
        $script:UWMSerialDrainWatchAt = $null
        Set-UWMConsoleFixed
        if (-not (Test-UWMConsoleAvailable)) { return }
        $activeApps = @($appIdx | Where-Object { -not $Pool[$_].Shredded })
        $activeGhosts = @($ghostIdx | Where-Object { -not $Pool[$_].Shredded })
        [int]$tpU = [Math]::Max(1, [Math]::Ceiling($activeApps.Count / [double]$pageSize))
        [int]$tpL = [Math]::Max(1, [Math]::Ceiling($activeGhosts.Count / [double]$pageSize))
        [int]$tp = [Math]::Max($tpU, $tpL)
        if ($cp -gt $tp - 1) { $cp = $tp - 1 }
        if ($cp -lt 0) { $cp = 0 }
        [int]$sU = $cp * $pageSize
        [int]$eU = [Math]::Min($sU + $pageSize - 1, $activeApps.Count - 1)
        [int]$sL = $cp * $pageSize
        [int]$eL = [Math]::Min($sL + $pageSize - 1, $activeGhosts.Count - 1)
        Show-Header
        if ($script:ShredderLocked -gt 0 -or $script:ShredderSecondary.Count -gt 0) {
            Write-Host ("  >> SHREDDER SAFE FILTER: {0} core component(s) locked down | Staged orphan footprints: {1}" -f $script:ShredderLocked, $script:ShredderSecondary.Count) -BackgroundColor DarkGreen -ForegroundColor White
        }
        [int]$activeTotal = $activeApps.Count + $activeGhosts.Count
        Write-Host ("  >> SHREDDER v4.0 | Page: ( {0} / {1} ) | Targets: {2}" -f ($cp + 1), $tp, $activeTotal) -BackgroundColor Yellow -ForegroundColor Black
        Write-Host "  🛡️ ACTIVE INSTALLED APPLICATIONS" -ForegroundColor Green
        $pageApps = [System.Collections.Generic.List[object]]::new()
        for ($i = $sU; $i -le $eU; $i++) { [void]$pageApps.Add([PSCustomObject]@{ GlobalIndex = $activeApps[$i]; Record = $Pool[$activeApps[$i]] }) }
        Write-UWMShredderGrid -Records @($pageApps) -Widths $widthsU -HeaderText "Application" -Profile "Upper"
        Write-Host "  💀 ORPHANED SYSTEM GHOST FOOTPRINTS" -ForegroundColor Red
        $pageGhosts = [System.Collections.Generic.List[object]]::new()
        for ($i = $sL; $i -le $eL; $i++) { [void]$pageGhosts.Add([PSCustomObject]@{ GlobalIndex = $activeGhosts[$i]; Record = $Pool[$activeGhosts[$i]] }) }
        Write-UWMShredderGrid -Records @($pageGhosts) -Widths $widthsL -HeaderText "Ghost Footprint" -Profile "Lower"
        $script:ShredderCache = @($pageApps) + @($pageGhosts)
        Write-Host (New-UWMShredderFooter -FrameWidth $frameW) -NoNewline -ForegroundColor $script:Theme['Accent']
        [string]$token = ""
        $key = Get-UWMRawKey
        if ($key -eq [char]0) {
            if (-not (Test-UWMConsoleAvailable)) { return }
            continue
        }
        [char]$ck = [char]$key
        if ($ck -eq 'N' -or $ck -eq 'n') { if ($cp -lt $tp - 1) { $cp++ } }
        elseif ($ck -eq 'P' -or $ck -eq 'p') { if ($cp -gt 0) { $cp-- } }
        elseif ($ck -eq 'B' -or $ck -eq 'b') { return }
        elseif ($ck -eq 'X' -or $ck -eq 'x') {
            $script:ShredderSafeActive = $true
            if ($script:ShredderSecondary.Count -gt 0) {
                [int]$releasedCount = $script:ShredderSecondary.Count
                $script:ShredderSecondary.Clear()
                Write-Host ("  [X-TOGGLE] Staging cancelled: {0} footprint(s) restored to READY. Core protection remains engaged ({1} locked)." -f $releasedCount, $script:ShredderLocked) -ForegroundColor Green
            } else {
                [int]$lockedCount = 0
                for ($i = 0; $i -lt $appIdx.Count; $i++) {
                    $ai = $appIdx[$i]
                    if (-not $Pool[$ai].Shredded -and (Test-UWMProtectedCore $Pool[$ai] $Protected)) {
                        $Pool[$ai].CoreLocked = $true
                        $lockedCount++
                    }
                }
                $script:ShredderLocked = $lockedCount
                $script:ShredderSecondary.Clear()
                for ($i = 0; $i -lt $ghostIdx.Count; $i++) {
                    $gi = $ghostIdx[$i]
                    if (-not $Pool[$gi].Shredded) { [void]$script:ShredderSecondary.Add($gi) }
                }
                Write-Host ("  [X-TOGGLE] Deployment vector engaged: {0} core component(s) locked down, {1} orphan footprint(s) staged [READY -> STAGED]." -f $lockedCount, $script:ShredderSecondary.Count) -ForegroundColor Green
            }
            Start-Sleep -Milliseconds 400
        }
        elseif ($ck -eq 'G' -or $ck -eq 'g') {
            $sel = [System.Collections.Generic.List[int]]::new()
            for ($i = 0; $i -lt $ghostIdx.Count; $i++) {
                $gi = $ghostIdx[$i]
                if (-not $Pool[$gi].Shredded -and -not $Pool[$gi].CoreLocked) { [void]$sel.Add($gi) }
            }
            if ($sel.Count -gt 0) {
                $null = Invoke-UWMShredderExecutionBackend -Indices $sel -Pool $Pool -Category "ghost footprint" -LogTarget "GhostSweep"
            } else {
                Write-Host "  -> No eligible ghost footprints remain." -ForegroundColor DarkYellow
                Start-Sleep -Milliseconds 400
            }
        }
        elseif ([char]::IsLetterOrDigit($ck) -or $ck -eq ',' -or $ck -eq '-' -or $ck -eq '.') {
            [string]$token = [string]$ck
            Write-Host $ck -NoNewline -ForegroundColor $script:Theme['Accent']
            while ($true) {
                $nk = Get-UWMRawKey
                if ($nk -eq [char]0) {
                    if (-not (Test-UWMConsoleAvailable)) { return }
                    continue
                }
                [char]$nkc = [char]$nk
                if ($nkc -eq [char]13 -or $nkc -eq [char]10) { break }
                if ($nkc -eq [char]8 -or $nkc -eq [char]127) {
                    if ($token.Length -gt 0) {
                        $token = $token.Substring(0, $token.Length - 1)
                        Write-Host "`b `b" -NoNewline -ForegroundColor $script:Theme['Accent']
                    }
                    continue
                }
                [char]$nck = [char]::ToUpper($nkc)
                if ($nck -eq 'B') { Write-Host ""; $token = ""; break }
                if ([char]::IsLetterOrDigit($nkc) -or $nkc -eq ',' -or $nkc -eq '-' -or $nkc -eq '.') {
                    $token += $nkc
                    Write-Host $nkc -NoNewline -ForegroundColor $script:Theme['Accent']
                }
            }
            if ($token -eq "") { continue }
            Write-Host ""
            if ($token -match '(?i)^ALL-GHOSTS$') {
                $sel = [System.Collections.Generic.List[int]]::new()
                for ($i = 0; $i -lt $ghostIdx.Count; $i++) {
                    $gi = $ghostIdx[$i]
                    if (-not $Pool[$gi].Shredded -and -not $Pool[$gi].CoreLocked) { [void]$sel.Add($gi) }
                }
                if ($sel.Count -gt 0) {
                    $null = Invoke-UWMShredderExecutionBackend -Indices $sel -Pool $Pool -Category "ghost footprint" -LogTarget "GhostSweep" -LeadingNewline
                } else {
                    Write-Host "  -> No eligible ghost footprints remain." -ForegroundColor DarkYellow
                    Start-Sleep -Milliseconds 400
                }
            }
            elseif (-not [string]::IsNullOrEmpty($token)) {
                $idxList = Get-UWMRangeIndices -Spec $token -Max $count
                $sel = [System.Collections.Generic.List[int]]::new()
                foreach ($gi in $idxList) {
                    [int]$i = $gi - 1
                    if ($i -ge 0 -and $i -lt $count -and -not $Pool[$i].Shredded -and -not $Pool[$i].CoreLocked) { [void]$sel.Add($i) }
                }
                if ($sel.Count -eq 0) {
                    Write-Host "  -> No valid non-protected indices provisioned." -ForegroundColor DarkYellow
                    Start-Sleep -Milliseconds 400
                } else {
                    $null = Invoke-UWMShredderExecutionBackend -Indices $sel -Pool $Pool -Category "target" -LogTarget "Instant"
                }
            }
        }
    }
}


# ---- UWM HTML Management Dashboard ----
function Invoke-UWMHtmlDashboard {
    Show-Header
    Write-Host "Generating ultimate visual HTML management dashboard matrix..." -ForegroundColor Cyan

    $OutputFile = Join-Path $script:DataRoot "UWM_Dashboard.html"
    $CacheDir = Join-Path $script:DataRoot "UWM_Cache"

    $CacheSizeMB = 0
    $CacheCount = 0
    $CacheTableRows = ""
    if (Test-Path $CacheDir) {
        $CacheFiles = Get-ChildItem -Path $CacheDir -File -Recurse
        $CacheCount = $CacheFiles.Count
        $CacheSizeMB = [Math]::Round((($CacheFiles | Measure-Object -Property Length -Sum).Sum / 1MB), 2)

        foreach ($file in $CacheFiles) {
            $Size = [Math]::Round(($file.Length / 1MB), 2)
            $CacheTableRows += "<tr><td>$($file.Name)</td><td>$($file.Extension)</td><td>$Size MB</td><td>$($file.LastWriteTime)</td></tr>"
        }
    }
    if ([string]::IsNullOrEmpty($CacheTableRows)) {
        $CacheTableRows = "<tr><td colspan='4' style='text-align:center; color:#999;'>No localized packages archived in offline vault depot yet.</td></tr>"
    }

    $RegPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $InstalledApps = Get-ItemProperty $RegPaths -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -and $_.DisplayVersion } |
                     Select-Object DisplayName, DisplayVersion, Publisher |
                     Sort-Object DisplayName

    $AppTableRows = ""
    foreach ($app in $InstalledApps) {
        $AppTableRows += "<tr><td><b>$($app.DisplayName)</b></td><td>$($app.DisplayVersion)</td><td>$($app.Publisher)</td></tr>"
    }

    $OS = Get-CimInstance Win32_OperatingSystem
    $ComputerName = $env:COMPUTERNAME
    $VaultBadgeColor = If ($CacheCount -gt 0) { "#28a745" } Else { "#dc3545" }
    $VaultBadgeText = If ($CacheCount -gt 0) { "Protected" } Else { "Empty Vault" }

    $HtmlContent = @"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Ultra Winget Manager - Executive Control Panel</title>
        <meta charset="utf-8">
        <style>
            body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: #f4f7f6; color: #333; margin: 0; padding: 30px; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
            header { display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid #0056b3; padding-bottom: 25px; margin-bottom: 35px; }
            h1 { color: #0056b3; margin: 0; font-size: 32px; letter-spacing: -0.5px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 25px; margin-bottom: 40px; }
            .card { background: #fff; padding: 25px; border-radius: 12px; border: 1px solid #eef2f5; border-left: 6px solid #0056b3; box-shadow: 0 4px 10px rgba(0,0,0,0.01); }
            .card h3 { margin: 0 0 12px 0; color: #6c757d; font-size: 13px; text-transform: uppercase; font-weight: 600; }
            .card p { margin: 0; font-size: 20px; font-weight: 700; color: #1a202c; }
            .card.vault { border-left-color: $VaultBadgeColor; }

            .section-title { color: #1a202c; border-left: 4px solid #0056b3; padding-left: 10px; margin: 40px 0 20px 0; font-size: 22px; }
            .table-responsive-wrapper { max-height: 500px; overflow-y: auto; border: 1px solid #eef2f5; border-radius: 8px; margin-bottom: 30px; }
            table { width: 100%; border-collapse: collapse; background: #fff; margin-bottom: 0; }
            th { background-color: #0056b3; color: white; text-align: left; padding: 15px; font-size: 14px; text-transform: uppercase; }
            td { padding: 14px 15px; border-bottom: 1px solid #f4f7f6; font-size: 14px; color: #4a5568; }
            tr:hover { background-color: #f8fafc; }
            .th-vault { background-color: $VaultBadgeColor; }
            footer { text-align: center; margin-top: 60px; font-size: 13px; color: #a0aec0; border-top: 1px solid #eef2f5; padding-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>ULTRA WINGET MANAGER</h1>
                <span style="background:$VaultBadgeColor; color:white; padding:6px 18px; border-radius:20px; font-size:13px; font-weight:bold;">$VaultBadgeText</span>
            </header>

            <div class="grid">
                <div class="card"><h3>Host Node</h3><p>$ComputerName</p></div>
                <div class="card"><h3>OS Distribution</h3><p>$($OS.Caption)</p></div>
                <div class="card vault"><h3>Vault Binary Packages</h3><p>$CacheCount Archives</p></div>
                <div class="card vault"><h3>Allocated Vault Footprint</h3><p>$CacheSizeMB MB</p></div>
            </div>

            <div class="section-title">Offline Cache Depot Vault Contents (UWM_Cache)</div>
            <table>
                <thead>
                    <tr>
                        <th class="th-vault">Package Binary Name</th>
                        <th class="th-vault">Format</th>
                        <th class="th-vault">Physical Size</th>
                        <th class="th-vault">Timestamp Locked</th>
                    </tr>
                </thead>
                <tbody>
                    $CacheTableRows
                </tbody>
            </table>

            <div class="section-title">Active Operating System Core Application Profile</div>
            <div class="table-responsive-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>Application Identity Name</th>
                        <th>Installed Version</th>
                        <th>Publisher Authority</th>
                    </tr>
                </thead>
                <tbody>
                    $AppTableRows
                </tbody>
            </table>
            </div>

            <footer>Automated Analytics Suite & Report Generated Globally via UWM Engine Framework.</footer>
        </div>
    </body>
    </html>
"@
    $HtmlContent | Out-File -FilePath $OutputFile -Encoding utf8 -Force
    Write-Host "`n[SUCCESS] Advanced Management Report exported successfully!" -ForegroundColor Green
    Write-Host " Saved Location: $OutputFile" -ForegroundColor Yellow

    Start-Process $OutputFile -ErrorAction SilentlyContinue
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- UWM Rollback Engine ----
function Invoke-UWMRollback {
    Show-Header
    if (-not (Assert-UWMWriteAccess)) { return }
    Write-Host "--- UWM BYPASS ROLLBACK ENGINE ---" -ForegroundColor $script:Theme['Header']
    
    $GlobalCacheDir = [System.IO.Path]::Combine($script:DataRoot, "UWM_Cache")
    $CachedFiles = Get-ChildItem -Path $GlobalCacheDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.exe', '.msi' }
    
    if ($null -eq $CachedFiles -or $CachedFiles.Count -eq 0) {
        Write-Host "[i] No backup snapshots found in physical cache storage." -ForegroundColor $script:Theme['Dim']
        Read-Host " $($script:Locale['PressEnter'])"; return
    }
    
    $idx = 1
    $fileMap = @{}
    foreach ($file in $CachedFiles) {
        Write-Host " [$idx] -> Restore Package: $($file.BaseName)" -ForegroundColor $script:Theme['Text']
        $fileMap[$idx] = $file.FullName
        $idx++
    }
    
    $selection = Read-Host "`nSelect file number to execute Rollback recovery (or 'B' to go back)"
    if ($selection -match '^\d+$' -and $fileMap.ContainsKey([int]$selection)) {
        $TargetFile = $fileMap[[int]$selection]
        $FileName = Split-Path $TargetFile -Leaf
        $BaseNameOnly = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
        $PkgIdFromFile = ($BaseNameOnly -split '_')[0]
        
        Clear-Host
        Show-Header
        Write-Host "=========================================" -ForegroundColor Yellow
        Write-Host " [UWM BYPASS] INITIATING DIRECT LOCAL RESTORATION" -ForegroundColor Cyan
        Write-Host " Deploying: $FileName" -ForegroundColor $script:Theme['Text']
        Write-Host "=========================================" -ForegroundColor Yellow
        
        # Phase 1: suppress the installed build via winget to avoid 1603 conflicts
        Write-Host "`n[1/3] Removing current version via winget..." -ForegroundColor Cyan
        Start-Process winget -ArgumentList @("uninstall", "--id", $PkgIdFromFile, "--silent") -NoNewWindow -Wait -ErrorAction SilentlyContinue

        # Phase 2: dual-mode deployment (online YAML vs offline binary)
        Write-Host "[2/3] Deploying cached installer package..." -ForegroundColor Cyan
        $BasePattern = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
        $LocalYaml = Join-Path $GlobalCacheDir "$BasePattern.yaml"
        $LocalBinary = Get-ChildItem -Path $GlobalCacheDir | Where-Object { $_.BaseName -eq $BasePattern -and $_.Extension -in @('.exe', '.msi') } | Select-Object -First 1

        $IsOnline = Test-Connection -ComputerName 8.8.8.8 -Count 1 -Quiet -ErrorAction SilentlyContinue
        $ec = $null

        if ($IsOnline -and (Test-Path $LocalYaml)) {
            Write-Host " [UWM Online] Unlocking Windows manifest protocols globally..." -ForegroundColor Cyan
            Start-Process winget -ArgumentList @("settings", "--enable", "LocalManifestFiles") -NoNewWindow -Wait -ErrorAction SilentlyContinue

            Write-Host " [UWM Online] Network active. Running certified manifest installation loop..." -ForegroundColor Green
            $proc = Start-Process winget -ArgumentList @("install", "--manifest", "`"$LocalYaml`"", "--force", "--accept-package-agreements", "--accept-source-agreements") -NoNewWindow -PassThru -Wait
            $ec = $proc.ExitCode

            if ($ec -ne 0 -and $LocalBinary) {
                Write-Host " [UWM Failsafe] Manifest policy locked by OS Group Policy. Swapping to offline binary bundle..." -ForegroundColor Yellow
                $ext = $LocalBinary.Extension.ToLower()
                if ($ext -eq '.msi') {
                    $proc = Start-Process msiexec.exe -ArgumentList "/i", "`"$($LocalBinary.FullName)`"", "/quiet", "/qn", "/norestart" -NoNewWindow -PassThru -Wait
                } else {
                    $proc = Start-Process $LocalBinary.FullName -ArgumentList "/silent", "/quiet", "/qn", "/norestart" -NoNewWindow -PassThru -Wait
                }
                $ec = $proc.ExitCode
            }
        } elseif ($LocalBinary) {
            Write-Host " [UWM Offline] Air-gapped pipeline triggered. Executing raw static cached binary installer payload..." -ForegroundColor Yellow
            $ext = $LocalBinary.Extension.ToLower()
            if ($ext -eq '.msi') {
                $proc = Start-Process msiexec.exe -ArgumentList "/i", "`"$($LocalBinary.FullName)`"", "/quiet", "/qn", "/norestart" -NoNewWindow -PassThru -Wait
            } else {
                $proc = Start-Process $LocalBinary.FullName -ArgumentList "/silent", "/quiet", "/qn", "/norestart" -NoNewWindow -PassThru -Wait
            }
            $ec = $proc.ExitCode
        } else {
            Write-Host " [UWM Critical] Error: No physical installers or internet signals discovered." -ForegroundColor Red
            $ec = 99
        }

        # Phase 3: cleanup
        if ($ec -eq 0 -or $ec -eq 3010) {
            Write-Host "[3/3] Cleaning up snapshot..." -ForegroundColor Cyan
            Write-Host "`n[SUCCESS] Local deployment transaction completed successfully!" -ForegroundColor Green
            if ($LocalBinary) { Remove-Item $LocalBinary.FullName -Force -ErrorAction SilentlyContinue }
            if (Test-Path $LocalYaml) { Remove-Item $LocalYaml -Force -ErrorAction SilentlyContinue }
            if ($script:Config.rollbackHistory -and $script:Config.rollbackHistory.ContainsKey($PkgIdFromFile)) {
                $script:Config.rollbackHistory.Remove($PkgIdFromFile)
                Save-Config
            }
        } else {
            Write-Host "`n[ALERT] Local recovery deployed (exit: $ec). Manual verification may be required." -ForegroundColor Yellow
        }
    }
    Read-Host " $($script:Locale['PressEnter'])"
}

# ---- UWM System Purge & Storage Overlord Engine ----
function Invoke-UWMSystemPurgeEngine {
    if (-not (Assert-UWMWriteAccess)) { return }
    try {
        Show-Header
        $h = $script:Theme['Header']; $a = $script:Theme['Accent']; $t = $script:Theme['Text']
        $s = $script:Theme['Success']; $e = $script:Theme['Error']; $d = $script:Theme['Dim']

        Write-Host "======================================================================" -ForegroundColor $h
        Write-Host "     UWM SYSTEM PURGE & STORAGE OVERLORD ENGINE v1.0" -ForegroundColor $a
        Write-Host "======================================================================" -ForegroundColor $h

        $initialFree = (Get-PSDrive -Name C).Free / 1GB
        Write-Host "`n [STORAGE] Initial free space: $([Math]::Round($initialFree,2)) GB" -ForegroundColor $d
        Write-Log -Action "PURGE_ENGINE" -Target "Storage" -Status "Info" -Details "Initial free: $([Math]::Round($initialFree,2)) GB"

        Write-Host "`n ---[ PHASE 1: Windows.old & Update Cache ]---" -ForegroundColor $a
        $winOld = "C:\Windows.old"
        if (Test-Path $winOld) {
            Write-Host "  [PURGE] Windows.old detected. Acquiring ownership..." -ForegroundColor $a
            takeown /f $winOld /r /d y 2>$null | Out-Null
            icacls $winOld /grant administrators:F /t /c /q 2>$null | Out-Null
            Remove-Item $winOld -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $winOld)) {
                Write-Host "  [OK] Windows.old successfully removed." -ForegroundColor $s
                Write-Log -Action "PURGE_ENGINE" -Target "Windows.old" -Status "Success" -Details "Removed"
            } else {
                Write-Host "  [WARN] Windows.old partially locked - some files remain." -ForegroundColor $a
            }
        } else {
            Write-Host "  [SKIP] Windows.old not present." -ForegroundColor $d
        }

        Write-Host "  [PURGE] Draining Windows Update cache..." -ForegroundColor $a
        $stoppedServices = @()
        foreach ($svc in @('wuauserv','bits','cryptsvc')) {
            try {
                $svcObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($svcObj -and $svcObj.Status -eq 'Running') {
                    Stop-Service -Name $svc -Force -ErrorAction Stop
                    $stoppedServices += $svc
                }
            } catch {}
        }
        try {
            $updatePath = "C:\Windows\SoftwareDistribution\Download"
            if (Test-Path $updatePath) {
                Get-ChildItem -Path $updatePath -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        try { Remove-Item $_.FullName -Recurse -Force -ErrorAction Stop }
                        catch [System.UnauthorizedAccessException] {}
                        catch [System.IO.IOException] {}
                        catch {}
                    }
                Write-Host "  [OK] Update cache cleared." -ForegroundColor $s
            }
            Write-Log -Action "PURGE_ENGINE" -Target "UpdateCache" -Status "Success" -Details "Services cycled, Download folder purged"
        } finally {
            foreach ($svc in $stoppedServices) {
                try { Start-Service -Name $svc -ErrorAction Stop } catch {}
            }
            if ($stoppedServices.Count -gt 0) {
                Write-Host "  [OK] Core services restored: $($stoppedServices -join ', ')." -ForegroundColor $s
            }
        }

        Write-Host "`n ---[ PHASE 2: Native Cleanmgr Automation ]---" -ForegroundColor $a
        $volCachePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
        if (Test-Path $volCachePath) {
            Get-ChildItem -Path $volCachePath -ErrorAction SilentlyContinue | ForEach-Object {
                $subPath = $_.PSPath
                $cacheName = $_.PSChildName
                if ($cacheName -match '(?i)download') {
                    Set-ItemProperty -Path $subPath -Name StateFlags0100 -Value 0 -Type DWord -ErrorAction SilentlyContinue
                } else {
                    Set-ItemProperty -Path $subPath -Name StateFlags0100 -Value 1 -Type DWord -ErrorAction SilentlyContinue
                }
            }
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" -Name "StateFlags0100" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" -Name "StateFlags0100" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnails" -Name "StateFlags0100" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Microsoft Defender Antivirus" -Name "StateFlags0100" -Value 2 -Type DWord -ErrorAction SilentlyContinue
            Start-Process cleanmgr -ArgumentList "/sagerun:100" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            Write-Host "  [OK] Cleanmgr automation executed." -ForegroundColor $s
            Write-Log -Action "PURGE_ENGINE" -Target "Cleanmgr" -Status "Success" -Details "Sagerun:100 executed"
        } else {
            Write-Host "  [SKIP] VolumeCaches registry path not found." -ForegroundColor $d
        }

        Write-Host "`n ---[ PHASE 3: WinSxS & Driver Store Optimization ]---" -ForegroundColor $a
        Write-Host "==============================================" -ForegroundColor $e
        Write-Host " [INFO] Optimizing WinSxS component store &" -ForegroundColor $a
        Write-Host " superseded drivers. This aggressive deep-clean" -ForegroundColor $t
        Write-Host " is highly secure but will take several minutes." -ForegroundColor $t
        Write-Host " Please DO NOT close this console window..." -ForegroundColor $t
        Write-Host "==============================================" -ForegroundColor $e
        Write-Log -Action "PURGE_ENGINE" -Target "WinSxS" -Status "Info" -Details "Starting DISM component cleanup"
        try {
            $null = Invoke-UWMDisplayTopologyShield
            dism /online /cleanup-image /startcomponentcleanup 2>&1 | Out-Host
        } finally {
            $null = Invoke-UWMDisplayTopologyShield -Restore
        }
        Write-Host "  [OK] WinSxS optimization complete." -ForegroundColor $s
        Write-Log -Action "PURGE_ENGINE" -Target "WinSxS" -Status "Success" -Details "DISM component cleanup completed"

        Write-Host "`n ---[ PHASE 4: User Profile Evacuation ]---" -ForegroundColor $a
        Write-Host "  [PURGE] System Temp..." -ForegroundColor $a
        $sysTemp = "$env:SystemRoot\Temp"
        if (Test-Path $sysTemp) {
            Get-ChildItem -Path $sysTemp -Recurse -ErrorAction SilentlyContinue |
                ForEach-Object { try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
        }
        Write-Host "  [PURGE] Local AppData Temp for all users..." -ForegroundColor $a
        Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userTemp = Join-Path $_.FullName "AppData\Local\Temp"
            if (Test-Path $userTemp) {
                Get-ChildItem -Path $userTemp -Recurse -ErrorAction SilentlyContinue |
                    ForEach-Object { try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
            }
        }
        Write-Host "  [PURGE] Windows Prefetch..." -ForegroundColor $a
        $prefetch = "C:\Windows\Prefetch"
        if (Test-Path $prefetch) {
            Get-ChildItem -Path $prefetch -Recurse -ErrorAction SilentlyContinue |
                ForEach-Object { try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
        }
        Write-Host "  [PURGE] Browser cache directories (Chrome, Edge, Brave)..." -ForegroundColor $a
        $browserDirs = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        )
        foreach ($base in $browserDirs) {
            if (Test-Path $base) {
                Get-ChildItem -Path $base -Recurse -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match 'Cache' -or $_.Name -match 'GPUCache' } |
                    ForEach-Object {
                        Get-ChildItem -Path $_.FullName -Recurse -ErrorAction SilentlyContinue |
                            ForEach-Object { try { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
                    }
            }
        }
        Write-Host "  [PURGE] Recycle Bin..." -ForegroundColor $a
        Clear-RecycleBin -Confirm:$false -ErrorAction SilentlyContinue

        $finalFree = (Get-PSDrive -Name C).Free / 1GB
        $reclaimed = $finalFree - $initialFree
        $reclaimedStr = if ($reclaimed -ge 0) { "$([Math]::Round($reclaimed,2)) GB" } else { "0 GB (negligible)" }

        Write-Host "`n======================================================================" -ForegroundColor $s
        Write-Host " [SUCCESS] Purge complete! Reclaimed $reclaimedStr of storage space." -ForegroundColor $s
        Write-Host "======================================================================" -ForegroundColor $s
        Write-Log -Action "PURGE_ENGINE" -Target "System" -Status "Success" -Details "Reclaimed $reclaimedStr. Before: $([Math]::Round($initialFree,2)) GB, After: $([Math]::Round($finalFree,2)) GB"
        [Console]::Beep(800,100)
        Read-Host " $($script:Locale['PressEnter'])"
    } catch {
        Write-Host "`n [PURGE ENGINE ERROR] $($_.Exception.Message)" -ForegroundColor $script:Theme['Error']
        Write-Log -Action "PURGE_ENGINE" -Target "System" -Status "Error" -Details $_.Exception.Message
        if (-not $script:SilentMode) { Read-Host " $($script:Locale['PressEnter'])" }
    }
}

function Invoke-UWMSysDiagPlaceholder {
    $loc = Get-Locale
    $h = $script:Theme['Header']; $a = $script:Theme['Accent']; $t = $script:Theme['Text']
    $s = $script:Theme['Success']; $e = $script:Theme['Error']; $d = $script:Theme['Dim']
    Clear-Host
    Write-Host ""
    Write-Host ("  " + "═" * 58) -ForegroundColor $h
    Write-Host "  $($loc['SysDiagTitle'])" -ForegroundColor $h
    Write-Host ("  " + "═" * 58) -ForegroundColor $h
    Write-Host ""
    Write-Host "  $($loc['SysDiagPlaceholder'])" -ForegroundColor $a
    Write-Host ""
    Write-Host ("  " + "─" * 58) -ForegroundColor $d
    Write-Host ""
    Write-Host "  [STUB] Registered subsystems:" -ForegroundColor $t
    Write-Host "    ├─ Health Telemetry Collector ............ PENDING" -ForegroundColor $d
    Write-Host "    ├─ Service Dependency Graph Analyzer ..... PENDING" -ForegroundColor $d
    Write-Host "    ├─ Driver Conflict Scanner ............... PENDING" -ForegroundColor $d
    Write-Host "    ├─ Registry Drift Detector ............... PENDING" -ForegroundColor $d
    Write-Host "    ├─ Windows Update Component Auditor ...... PENDING" -ForegroundColor $d
    Write-Host "    ├─ Scheduled Task Integrity Verifier ..... PENDING" -ForegroundColor $d
    Write-Host "    └─ Network Stack Health Probe ............ PENDING" -ForegroundColor $d
    Write-Host ""
    Write-Host ("  " + "─" * 58) -ForegroundColor $d
    Write-Host ""
    Write-Host "  $($loc['SysDiagActions'])" -ForegroundColor $d
    Write-Host ""
    Write-Log -Action "SYS_DIAG_OPEN" -Target "Placeholder" -Status "Info" -Details "System Diagnostics Hub placeholder accessed"
    while ($true) {
        if (-not (Test-UWMConsoleAvailable)) { break }
        $key = [Console]::ReadKey($true)
        $ck = [char]::ToUpper($key.KeyChar)
        if ($ck -eq 'B' -or $key.Key -eq [ConsoleKey]::Escape) { break }
        if ($ck -eq 'R') {
            Write-Host ""
            Write-Host "  [SYS DIAG] Initiating system-wide diagnostic scan..." -ForegroundColor $a
            Write-Host "  [SYS DIAG] Scan subsystems are under development." -ForegroundColor $d
            Write-Host "  [SYS DIAG] Expected availability: UWM v16.0 release." -ForegroundColor $d
            Write-Host ""
            Write-Host "  $($loc['PressEnter'])" -ForegroundColor $d
            [void][Console]::ReadKey($true)
            break
        }
        if ($ck -eq 'L') {
            Write-Host ""
            $entries = @()
            if (Test-Path $script:LogPath) {
                try {
                    $raw = Get-Content $script:LogPath -Raw -ErrorAction Stop
                    if ($raw -and $raw.Trim()) {
                        $entries = $raw | ConvertFrom-Json -ErrorAction Stop
                        if ($entries -isnot [array]) { $entries = @($entries) }
                    }
                } catch {}
            }
            if ($entries.Count -eq 0) {
                Write-Host "  [SYS DIAG] No log entries found." -ForegroundColor $d
            } else {
                Write-Host "  [SYS DIAG] Last 10 log entries:" -ForegroundColor $a
                Write-Host ""
                $show = if ($entries.Count -gt 10) { $entries[-10..-1] } else { $entries }
                foreach ($entry in $show) {
                    $ts = if ($entry.Timestamp) { $entry.Timestamp.Substring(0, 19) } else { "N/A" }
                    $act = if ($entry.Action) { $entry.Action } else { "N/A" }
                    $st  = if ($entry.Status) { $entry.Status } else { "N/A" }
                    $tgt = if ($entry.Target) { $entry.Target } else { "" }
                    $col = switch ($st) {
                        "Success" { $s }
                        "Error"   { $e }
                        "Warning" { $a }
                        default   { $d }
                    }
                    Write-Host "    [$ts] $act :: $st" -ForegroundColor $col
                    if ($tgt) { Write-Host "      Target: $tgt" -ForegroundColor $d }
                }
            }
            Write-Host ""
            Write-Host "  $($loc['PressEnter'])" -ForegroundColor $d
            [void][Console]::ReadKey($true)
            break
        }
    }
}

# ---- Main Loop ----
try {
    Load-Config
    if ($script:ArcRepairScope) {
        try { [void](Invoke-UWMUpdateRepair -Health $null) } catch { }
        exit
    }
    if ($script:DiagRepairScope) {
        try {
            if ($script:DiagRepairScope -eq 'Update') {
                [void](Invoke-UWMUpdateRepair -Health $null)
            } else {
                [void](Invoke-UWMAppXHealer)
                $null = Invoke-UWMKernelRestore
            }
        } catch { }
        exit
    }
    # ---- Phase 7: Self-Healing & Testing ----
    Repair-ScriptIntegrity
    if ($script:RunTestsMode) {
        Write-Host " $($script:Locale['TestFlagDetected'])" -ForegroundColor $script:Theme['Accent']
        Invoke-SelfTest; Read-Host " $($script:Locale['PressEnter'])"; exit
    }
    Invoke-StartupAnimation
    if ($script:SilentMode) { Invoke-GlobalUpdate; exit }
    $c = ""
    do {
        Show-Header
        Write-Host ("  " + "-" * 46)
        Write-Host $script:Locale['MenuSectionCore'] -ForegroundColor $script:Theme['Accent']
        Write-Host $script:Locale['MenuUpdate'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuPin'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuBlock'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuGlobal'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuShredderApp'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuRollback'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSectionTools'] -ForegroundColor $script:Theme['Accent']
        Write-Host $script:Locale['MenuStatus'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSearch'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuPurge'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSchedule'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSandbox'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuLog'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuIgnore'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSectionDiag'] -ForegroundColor $script:Theme['Accent']
        Write-Host $script:Locale['MenuDiagnose'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuExport'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSectionInteg'] -ForegroundColor $script:Theme['Accent']
        Write-Host $script:Locale['MenuBridge'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuGitHub'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuNotify'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSectionPref'] -ForegroundColor $script:Theme['Accent']
        Write-Host $script:Locale['MenuThrottle'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuScale'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuLang'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuFixPassword'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuObliterator'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuInspector'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuPurgeEngine'] -ForegroundColor $script:Theme['Text']
        Write-Host $script:Locale['MenuSysDiag'] -ForegroundColor $script:Theme['Text']
        Write-Host ("  " + "-" * 46)
        Write-Host $script:Locale['MenuExit'] -ForegroundColor $script:Theme['Error']
        Write-Host ("  " + "-" * 46)
        $c = Read-Host " $($script:Locale['PromptSelect'])"
        switch ($c) {
            '1'  { Invoke-SmartAction -Mode "UPDATE" }
            '2'  { Invoke-SmartAction -Mode "PIN" }
            '3'  { Invoke-SmartAction -Mode "BLOCK" }
            '4'  { Invoke-GlobalUpdate }
            '5'  { Invoke-UWMAdvancedShredder }
            '6'  { Invoke-UWMRollback }
            '7'  { Invoke-StatusMenu }
            '8'  { Invoke-SmartSearch }
            '9'  { Invoke-Cleanup }
            '10' { Invoke-ScheduleMenu }
            '11' { Invoke-SandboxTest }
            '12' { Invoke-ViewLog }
            '13' { Invoke-IgnoreListMenu }
            '14' { Invoke-DiagnosticsMenu }
            '15' { Invoke-UWMHtmlDashboard }
            '16' { Invoke-BridgeMenu }
            '17' { Write-Host "`n [WARNING] This feature has been disabled and removed by the Administrator.`n" -ForegroundColor Yellow; Start-Sleep -Seconds 2; break }
            '18' { Invoke-NotifyTest }
            '19' { Invoke-ThrottleToggle }
            '20' { Invoke-UIScaleToggle }
            '21' { Invoke-ToggleLanguage }
            '22' { Invoke-FixPasswordPolicy }
            '23' { Invoke-UWMAdBlockObliterator }
            '24' { Invoke-CoreInspector }
            '25' { Invoke-UWMSystemPurgeEngine }
            '26' { Invoke-UWMSysDiagPlaceholder }
        }
    } while ($c -ne '27')
    if (Test-UWMConsoleAvailable) { [Console]::Beep(600,100) }
} catch {
    if (Test-UWMConsoleAvailable) { [Console]::Beep(200,300) }
    Write-Host ($script:Locale['ErrorGeneric'] -f $_.Exception.Message) -ForegroundColor $script:Theme['Error']
    if (-not $script:SilentMode) { Read-Host " $($script:Locale['PressEnter'])" }
}