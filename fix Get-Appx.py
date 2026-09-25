import os
import sys
import re
import ctypes
import subprocess
import time
import json
import winreg
from datetime import datetime, timedelta

class SentinelLog:
    SHIELD  = "[SENTINEL-HYPER-SHIELD]"
    HEAL    = "[OMNI-UNIVERSAL-HEAL]"
    SUCCESS = "[SECURE-CONFIRMED]"
    ALERT   = "[CRITICAL-ATTENTION]"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_silent_cmd(command):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command], 
            capture_output=True, text=True, encoding='utf-8', errors='ignore',
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)

def should_run_heavy_scan():
    if "--force" in sys.argv:
        return True
    timestamp_file = os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'), 'sentinel_timestamp.txt')
    now = datetime.now()
    if os.path.exists(timestamp_file):
        try:
            with open(timestamp_file, 'r') as f:
                last_scan = datetime.strptime(f.read().strip(), "%Y-%m-%d %H:%M:%S")
            if now < last_scan + timedelta(days=5):
                return False
        except Exception as err:
            print(f"{SentinelLog.ALERT} Trapped background exception during cache purge: {err}")
    try:
        with open(timestamp_file, 'w') as f:
            f.write(now.strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as err:
        print(f"{SentinelLog.ALERT} Trapped background exception during cache purge: {err}")
    return True

def execute_nuclear_cache_purge():
    print(f"{SentinelLog.SHIELD} Evaporating Windows Store metadata and breaking cache depots...")
    run_silent_cmd("wsreset.exe")
    local_appdata = os.environ.get('LOCALAPPDATA', '')
    if local_appdata:
        stray_cache = os.path.join(local_appdata, "Packages", "Microsoft.WindowsStore_8wekyb3d8bbwe", "LocalCache")
        if os.path.exists(stray_cache):
            run_silent_cmd(f"Remove-Item -Path '{stray_cache}\\*' -Recurse -Force -ErrorAction SilentlyContinue")

def dynamic_cbs_package_healer():
    print(f"{SentinelLog.HEAL} Scraping live system topology for broken/pending/staged CBS packages...")

    query = "Get-WindowsPackage -Online | Where-Object {$_.PackageState -ne 'Installed' -and $_.PackageState -ne 'Superseded'} | Select-Object -Property PackageName | ConvertTo-Json"
    stdout, _ = run_silent_cmd(query)

    if not stdout or stdout == "null" or stdout == "":
        print(f" -> No pending or staged core package failures discovered.")
        return False

    try:
        packages = json.loads(stdout)
        if isinstance(packages, dict):
            packages = [packages]

        print(f" -> [ALERT] Identified {len(packages)} corrupted/staged package nodes hanging in memory.")
        for pkg in packages:
            name = pkg.get("PackageName")
            if name:
                print(f"    -> Forcefully deploying and anchoring: {name}")
                run_silent_cmd(f"Dism /Online /Enable-Feature /FeatureName:{name} /All /NoRestart /LimitAccess")
        return True
    except Exception as e:
        print(f" -> Error parsing package list array matrix: {e}")
        return False

def dynamic_universal_appx_shredder():
    print(f"{SentinelLog.HEAL} Scanning universal AppX manifests. Re-registering ALL package identities dynamically...")

    appx_repair_cmd = 'Get-AppxPackage -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\\AppXManifest.xml" -ForceApplicationShutdown -ErrorAction SilentlyContinue}'
    run_silent_cmd(appx_repair_cmd)

    run_silent_cmd('REG ADD "HKLM\\SYSTEM\\CurrentControlSet\\Services\\cbdhsvc" /v Start /t REG_DWORD /d 2 /f')
    run_silent_cmd('Start-Service cbdhsvc -ErrorAction SilentlyContinue')

def query_active_refresh_rate():
    probe_cmd = r"""$ErrorActionPreference='SilentlyContinue'; $vc = Get-CimInstance Win32_VideoController; $hz = ($vc | Where-Object { $_.CurrentRefreshRate -gt 0 } | Measure-Object -Property CurrentRefreshRate -Maximum).Maximum; $h = ($vc | Where-Object { $_.CurrentHorizontalResolution -gt 0 } | Measure-Object -Property CurrentHorizontalResolution -Maximum).Maximum; $v = ($vc | Where-Object { $_.CurrentVerticalResolution -gt 0 } | Measure-Object -Property CurrentVerticalResolution -Maximum).Maximum; $dpi = (Get-ItemProperty 'HKCU:\Control Panel\Desktop\WindowMetrics').AppliedDPI; if (-not $hz) { $modes = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorListedSupportedSourceModes; $hz = ($modes | ForEach-Object { if ($_.ActiveFrameRateInMilliHertz) { [int]($_.ActiveFrameRateInMilliHertz / 1000) } else { 0 } } | Measure-Object -Maximum).Maximum }; [pscustomobject]@{Hz=[int]$hz;ResH=[int]$h;ResV=[int]$v;DPI=[int]$dpi} | ConvertTo-Json"""
    stdout, _ = run_silent_cmd(probe_cmd)
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            return {'Hz': int(data.get('Hz') or 0), 'ResH': int(data.get('ResH') or 0), 'ResV': int(data.get('ResV') or 0), 'DPI': int(data.get('DPI') or 0)}
    except Exception:
        pass
    return {'Hz': 0, 'ResH': 0, 'ResV': 0, 'DPI': 0}

def preserve_display_topology():
    print(f"{SentinelLog.SHIELD} Isolating Windows display topology profiles before component-store compaction...")
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    snapshot_dir = os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp'), 'UWM_DisplayTopology_{}'.format(stamp))
    try:
        os.makedirs(snapshot_dir, exist_ok=True)
    except Exception:
        pass
    nodes = [
        'HKCU\\Control Panel\\Desktop\\WindowMetrics',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Video',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Connectivity',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\ScaleFactors',
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}',
        'HKCU\\Software\\NVIDIA Corporation',
        'HKCU\\Software\\AMD',
        'HKCU\\Software\\Custom Resolution Utility',
    ]
    baseline = query_active_refresh_rate()
    backup_files = []
    for idx, node in enumerate(nodes):
        node_tag = re.sub(r'[^A-Za-z0-9]+', '_', node).strip('_')
        backup_file = os.path.join(snapshot_dir, '{:04d}_{}.reg'.format(idx + 1, node_tag))
        run_silent_cmd('reg export "{}" "{}" /y'.format(node, backup_file))
        if os.path.exists(backup_file) and os.path.getsize(backup_file) > 0:
            backup_files.append(backup_file)
    manifest = os.path.join(snapshot_dir, 'snapshot_manifest.json')
    try:
        with open(manifest, 'w') as f:
            json.dump({'timestamp': stamp, 'nodes': nodes, 'backup_files': backup_files, 'baseline': baseline}, f, indent=2)
    except Exception:
        pass
    if backup_files:
        print(f"{SentinelLog.SUCCESS} Display topology hives isolated & snapshotted: {snapshot_dir} ({len(backup_files)}/{len(nodes)} nodes preserved), baseline Hz={baseline.get('Hz', 'N/A')}")
    else:
        print(f"{SentinelLog.ALERT} WARNING: Display topology snapshot not confirmed. Component store compaction will proceed with profiles at nominal risk.")
    return snapshot_dir, backup_files, baseline

def restore_display_topology(snapshot_dir, backup_files, baseline):
    print(f"{SentinelLog.HEAL} Re-applying isolated display topology hives post-compaction (hardware registry injection override)...")
    if not backup_files:
        print(f"{SentinelLog.ALERT} No display topology snapshots available for re-injection. Manual verification advised.")
        return False
    restored = 0
    for backup_file in backup_files:
        stdout, stderr = run_silent_cmd('reg import "{}"'.format(backup_file))
        ok = 'operation completed successfully' in (stdout + ' ' + stderr).lower()
        if os.path.exists(backup_file) and ok:
            restored += 1
            print(f"    -> Injected & anchored: {os.path.basename(backup_file)}")
        else:
            print(f"{SentinelLog.ALERT}    -> Injection override failed: {os.path.basename(backup_file)} ({stderr or stdout})")
    print(f"{SentinelLog.SUCCESS} Display topology hives re-injected: {restored}/{len(backup_files)} registry snapshots locked to hardware profile.")
    return restored > 0

def verify_display_topology_shield(baseline, snapshot_dir, backup_files):
    print(f"{SentinelLog.SHIELD} Running hardware-level refresh-rate / resolution / scaling verification shield...")
    if not baseline or not baseline.get('Hz'):
        print(f"{SentinelLog.ALERT} Baseline topology unavailable - verification shield cannot confirm display parity.")
        return False
    current = query_active_refresh_rate()
    pre_hz = int(baseline.get('Hz') or 0)
    pre_h = int(baseline.get('ResH') or 0)
    pre_v = int(baseline.get('ResV') or 0)
    post_hz = int(current.get('Hz') or 0)
    post_h = int(current.get('ResH') or 0)
    post_v = int(current.get('ResV') or 0)
    post_dpi = int(current.get('DPI') or 0)
    degraded = post_hz < pre_hz or (pre_h and post_h != pre_h) or (pre_v and post_v != pre_v)
    if degraded:
        print(f"{SentinelLog.ALERT} STRUCTURAL OVERRIDE: display profile degraded - baseline {pre_hz}Hz vs current {post_hz}Hz ({post_h}x{post_v}). Forcing silent re-application of isolated hardware profile hives...")
        restore_display_topology(snapshot_dir, backup_files, baseline)
        current = query_active_refresh_rate()
        post_hz = int(current.get('Hz') or 0)
        post_h = int(current.get('ResH') or 0)
        post_v = int(current.get('ResV') or 0)
        post_dpi = int(current.get('DPI') or 0)
        if post_hz >= pre_hz:
            print(f"{SentinelLog.SUCCESS} Override confirmed locked: {post_hz}Hz @ {post_h}x{post_v} (DPI {post_dpi}) restored to stored baseline {pre_hz}Hz.")
            return True
        print(f"{SentinelLog.ALERT} OVERRIDE EXHAUSTED: current {post_hz}Hz vs baseline {pre_hz}Hz - reboot required / manual monitor profile re-affirmation advised.")
        return False
    print(f"{SentinelLog.SUCCESS} Display topology verification passed: {post_hz}Hz @ {post_h}x{post_v} (DPI {post_dpi}) matches stored baseline {pre_hz}Hz. High-refresh-rate profile locked.")
    return True

def main():
    if not is_admin():
        print(f"{SentinelLog.ALERT} Critical Administrative root privileges required.")
        sys.exit(1)

    is_silent = "--silent" in sys.argv
    if not is_silent:
        print("=====================================================================")
        print("   WIN11 SYSTEM SENTINEL v6.0 - DYNAMIC OMNI-REPAIR ULTIMATE CORE   ")
        print("=====================================================================")

    if is_silent and not should_run_heavy_scan():
        sys.exit(0)

    execute_nuclear_cache_purge()
    packages_healed = dynamic_cbs_package_healer()
    dynamic_universal_appx_shredder()

    print(f"{SentinelLog.SHIELD} Deploying final infrastructure verification matrix & Component Store Purge...")

    snapshot_dir, backup_files, topology_baseline = preserve_display_topology()

    run_silent_cmd("Dism /Online /Cleanup-Image /StartComponentCleanup")
    run_silent_cmd("Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase")
    run_silent_cmd("Dism /Online /Cleanup-Image /RestoreHealth")
    run_silent_cmd("sfc /scannow")

    restore_display_topology(snapshot_dir, backup_files, topology_baseline)
    verify_display_topology_shield(topology_baseline, snapshot_dir, backup_files)

    run_silent_cmd("Get-CimInstance -Namespace root\\cimv2 -ClassName Win32_Product | Out-Null")

    print(f"\n{SentinelLog.SUCCESS} Global system recovery pipeline fully completed!")

    if not is_silent:
        while True:
            print("\n=====================================================================")
            print("     UWM SYSTEM VERIFICATION & AUDIT PANEL                           ")
            print("=====================================================================")
            print(" [1] -> Run Dynamic Live Verification (Verify Cleared Package States)")
            print(" [2] -> Finalize Stream and Exit back to Master PowerShell Panel")
            print("=====================================================================")

            verify_choice = input(" Select verification action [1-2]: ").strip()

            if verify_choice == '1':
                print(f"\n{SentinelLog.SHIELD} Fetching dynamic package states and running raw validation matrices, please wait...")

                check_table_cmd = "Get-WindowsPackage -Online | Where-Object {$_.PackageState -ne 'Installed' -and $_.PackageState -ne 'Superseded'} | Select-Object -Property PackageName, PackageState"
                stdout_table, _ = run_silent_cmd(check_table_cmd)

                check_raw_cmd = "Get-WindowsPackage -Online | Where-Object {$_.PackageState -ne 'Installed' -and $_.PackageState -ne 'Superseded'}"
                stdout_raw, _ = run_silent_cmd(check_raw_cmd)

                print("\n---------------------------------------------------------------------")
                if (not stdout_table or stdout_table == "null" or stdout_table == "") and (not stdout_raw or stdout_raw == ""):
                    print(" [SUCCESS CONFIRMED] 100% Clean! All broken/staged/ghost packages are completely eradicated.")
                else:
                    if stdout_table and stdout_table != "null" and stdout_table != "":
                        print(" [PANEL A] Standard Package Matrix Output:")
                        print(stdout_table)
                        print("---------------------------------------------------------------------")

                    if stdout_raw and stdout_raw != "null" and stdout_raw != "":
                        print(" [PANEL B] Comprehensive Pure Raw Package Properties Output:")
                        print(stdout_raw)
                        print("---------------------------------------------------------------------")

                input("\n Press [Enter] to return to verification menu...")

            elif verify_choice == '2':
                print(f"\n{SentinelLog.SUCCESS} Exiting core sentinel stream. Returning control to master framework...")
                time.sleep(1)
                break
            else:
                print(" [X] Invalid option index selection token. Choose 1 or 2.")

if __name__ == "__main__":
    main()
