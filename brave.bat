REM Optimizing Brave Browser

REM killing Brave 
taskkill /IM brave.exe /F >nul 2>&1

REM Delete Logs
del /f /q "%drive%:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\debug.log"
rmdir /s /q "%drive%:\Program Files (x86)\BraveSoftware\Brave-Browser\Update\CrashReports"
rmdir /s /q "%drive%:\Program Files (x86)\BraveSoftware\Brave-Browser\Update\Temp"

REM Delete Vpn
del /f /q "%drive%:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave_vpn_maner.exe"
rmdir /s /q "%drive%:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\BraveVpnWireguardService"

REM Remove Brave sch update tasks
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineCore" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineUA" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineCore{2320C90E-9617-4C25-88E0-CC10B8F3B6BB}" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineUA{FD1FD78D-BD51-4A16-9F47-EE6518C2D038}" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineCore{1B4ECC99-A065-4BA8-B4B5-6828D11834AC}" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineUA{C2741D3F-2DB1-4D3D-9679-8AF7E44826F3}" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineUA{63C18D06-59BC-4999-AF41-BEE3854F9BC6}" /F >nul 2>&1
schtasks /Delete /TN "BraveSoftwareUpdateTaskMachineCore{2566773E-9BC7-4330-BDE2-B34835158F82}" /F >nul 2>&1

REM Disable brave useless things you will never use
reg add "HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave" /v BraveRewardsDisabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave" /v BraveWalletDisabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave" /v BraveVPNDisabled /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave" /v BraveAIChatEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave" /v PasswordManagerEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\BraveSoftware\Brave" /v TorDisabled /t REG_DWORD /d 0 /f
pause
