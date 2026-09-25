param(
    [string]$SourceDir = $PSScriptRoot,
    [string]$OutputPath = (Join-Path $PSScriptRoot "Ultra_Winget_Manager.exe")
)

$ErrorActionPreference = 'Stop'

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     UWM EXECUTABLE BUILDER - Enterprise Deployment Pipeline" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

# ---- Verify source files ----
$required = @("update.ps1", "UWM_Launcher.bat", "fix Get-Appx.py")
foreach ($file in $required) {
    $path = Join-Path $SourceDir $file
    if (-not (Test-Path $path)) { Write-Host " [X] Missing: $file" -ForegroundColor Red; exit 1 }
    Write-Host " [OK] Found: $file" -ForegroundColor Green
}

# ---- Package source files into portable payload archive ----
$buildTemp = Join-Path $env:TEMP "UWM_Build_$(Get-Random)"
$null = New-Item -ItemType Directory -Path $buildTemp -Force
foreach ($file in $required) {
    Copy-Item (Join-Path $SourceDir $file) (Join-Path $buildTemp $file) -Force
}

$zipPath = Join-Path $env:TEMP "UWM_payload.zip"
if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
    Compress-Archive -Path "$buildTemp\*" -DestinationPath $zipPath -Force
} else {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($buildTemp, $zipPath)
}
Remove-Item -Path $buildTemp -Recurse -Force

$zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
Remove-Item -Path $zipPath -Force
Write-Host " [ARCHIVE] Payload: $($zipBytes.Length) bytes" -ForegroundColor Cyan

# ---- Generate C# launcher with embedded zip payload ----
Write-Host "`n [COMP] Generating C# launcher assembly..." -ForegroundColor Yellow

$hexLines = for ($i = 0; $i -lt $zipBytes.Length; $i += 16) {
    $remaining = [Math]::Min(16, $zipBytes.Length - $i)
    $chunk = New-Object byte[] $remaining
    [Array]::Copy($zipBytes, $i, $chunk, 0, $remaining)
    $hex = ($chunk | ForEach-Object { "0x{0:X2}" -f $_ }) -join ","
    "        " + $hex
}
$byteArrayLiteral = $hexLines -join ",`r`n"

$csCode = @"
using System;
using System.IO;
using System.IO.Compression;
using System.Diagnostics;
using System.Reflection;

[assembly: AssemblyTitle("Ultra Winget Manager")]
[assembly: AssemblyProduct("Ultra Winget Manager")]
[assembly: AssemblyCompany("Ultimate Edition Labs")]
[assembly: AssemblyVersion("15.0.0.0")]
[assembly: AssemblyFileVersion("15.0.0.0")]

class UWMStub {
    static byte[] Payload = new byte[] {
$byteArrayLiteral
    };

    static void Main() {
        string baseDir = Path.Combine(Path.GetTempPath(), "UWM_Runtime_Env");
        Directory.CreateDirectory(baseDir);

        try {
            using (var archive = new ZipArchive(new MemoryStream(Payload), ZipArchiveMode.Read)) {
                foreach (var entry in archive.Entries) {
                    if (string.IsNullOrEmpty(entry.Name)) continue;
                    string cleanName = entry.FullName.Replace('\\', '/');
                    string targetPath = Path.GetFullPath(Path.Combine(baseDir, cleanName));
                    if (!targetPath.StartsWith(baseDir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) continue;
                    string parentDir = Path.GetDirectoryName(targetPath);
                    if (string.IsNullOrEmpty(parentDir)) parentDir = baseDir;
                    Directory.CreateDirectory(parentDir);
                    using (var src = entry.Open())
                    using (var dst = File.Create(targetPath)) {
                        src.CopyTo(dst);
                    }
                }
            }
        } catch (Exception ex) {
            Console.Error.WriteLine("[FATAL] Extraction failed: " + ex.Message);
            Console.ReadLine();
            Environment.Exit(1);
        }

        string launcherPath = Path.Combine(baseDir, "UWM_Launcher.bat");
        if (!File.Exists(launcherPath)) {
            Console.Error.WriteLine("[FATAL] Bootstrapper not found after extraction.");
            Console.ReadLine();
            Environment.Exit(1);
        }

        if (!IsAdministrator()) {
            try {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "cmd.exe";
                psi.Arguments = "/c \"" + launcherPath + "\"";
                psi.WorkingDirectory = baseDir;
                psi.Verb = "runas";
                psi.UseShellExecute = true;
                psi.WindowStyle = ProcessWindowStyle.Normal;
                Process.Start(psi);
            } catch (Exception ex) {
                Console.Error.WriteLine("[FATAL] Elevation failed: " + ex.Message);
                Console.ReadLine();
                Environment.Exit(1);
            }
            return;
        }

        ProcessStartInfo runPsi = new ProcessStartInfo();
        runPsi.FileName = "cmd.exe";
        runPsi.Arguments = "/c \"" + launcherPath + "\"";
        runPsi.WorkingDirectory = baseDir;
        runPsi.UseShellExecute = false;
        Process runProc = Process.Start(runPsi);
        runProc.WaitForExit();
    }

    static bool IsAdministrator() {
        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }
}
"@

# ---- Compile ----
try {
    $IconPath = Join-Path $PSScriptRoot "uwm.ico"
    $IconOpt = ""
    if (Test-Path $IconPath) {
        $IconOpt = "/win32icon:`"$IconPath`""
    } else {
        Write-Host " [!] Warning: uwm.ico missing. Building without custom icon asset." -ForegroundColor Yellow
    }

    if ($PSVersionTable.PSEdition -eq 'Core') {
        $FwCsc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
        if (-not (Test-Path $FwCsc)) { $FwCsc = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" }
        if (-not (Test-Path $FwCsc)) { throw "csc.exe not found; install .NET Framework 4.x" }
        $srcFile = Join-Path $env:TEMP ("UWM_Src_{0}.cs" -f (Get-Random))
        [System.IO.File]::WriteAllText($srcFile, $csCode, (New-Object System.Text.UTF8Encoding($true)))
        $cscArgs = @('/nologo', '/target:exe', '/optimize+', ("/out:" + $OutputPath),
                     '/reference:System.dll', '/reference:System.IO.Compression.dll')
        if ($IconOpt) { $cscArgs += ("/win32icon:" + $IconPath) }
        $cscArgs += $srcFile
        try {
            & $FwCsc $cscArgs
            if ($LASTEXITCODE -ne 0) { throw "csc.exe exited with code $LASTEXITCODE" }
        } finally {
            Remove-Item -LiteralPath $srcFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        $CompilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
        $CompilerParameters.ReferencedAssemblies.Add("System.dll") | Out-Null
        $CompilerParameters.ReferencedAssemblies.Add("System.IO.Compression.dll") | Out-Null
        $CompilerParameters.OutputAssembly = $OutputPath
        $CompilerParameters.GenerateExecutable = $true
        $CompilerParameters.CompilerOptions = "/target:exe $IconOpt"
        Add-Type -TypeDefinition $csCode -Language CSharp -CompilerParameters $CompilerParameters -ErrorAction Stop
    }
    Write-Host "`n [SUCCESS] Compiled: $OutputPath" -ForegroundColor Green
    $fileInfo = Get-Item $OutputPath
    Write-Host " [INFO] Size: $([Math]::Round($fileInfo.Length/1KB,1)) KB" -ForegroundColor Cyan
    Write-Host " [INFO] Product: Ultra Winget Manager v15.0.0.0" -ForegroundColor Cyan
    Write-Host " [INFO] Company: Ultimate Edition Labs" -ForegroundColor Cyan
    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "     BUILD COMPLETE - Ultra_Winget_Manager.exe ready" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Cyan
} catch {
    Write-Host "`n [X] Compilation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
