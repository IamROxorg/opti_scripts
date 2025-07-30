REM ⚠️ These tweaks are meant to improve performance, but no guarantees use at your own risk.

REM -- Disable useless file system features to reduce overhead
fsutil behavior set disable8dot3 1
fsutil behavior set DisableDeleteNotify 0
fsutil behavior set disablelastaccess 1

REM -- Disable VBS (Virtualization-Based Security) to lower latency and overhead
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HVCIMATRequired /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v RequirePlatformSecurityFeatures /t REG_DWORD /d 0 /f
bcdedit /set hypervisorlaunchtype Off

REM -- Disable VMP (Virtual Machine Platform) if not needed
dism /Online /Disable-Feature /FeatureName:VirtualMachinePlatform /NoRestart
dism /Online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart
REM -- Set higher GPU and CPU scheduling priorities for games
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f

REM -- Set CPU priority
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 10 /f

REM -- Lower input latency by reducing input buffer size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v KeyboardDataQueueSize /t REG_DWORD /d 0x13 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v MouseDataQueueSize /t REG_DWORD /d 0x13 /f

REM -- Disable Fault Tolerant Heap (FTH), which can slow down apps
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\FTH" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1

REM -- Enable Hardware Accelerated GPU Scheduling (HAGS)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f >nul 2>&1
pause
