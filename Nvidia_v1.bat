@echo off

REM Disable the legacy NVIDIA Telemetry service (if present)
sc stop "NvTelemetryContainer" >nul 2>&1
sc config "NvTelemetryContainer" start= disabled >nul 2>&1

REM Disable scheduled tasks related to NVIDIA telemetry and crash reports
for %%T in (
  "NvTmMon"
  "NvTmRep"
  "NvTmRepOnLogon"
  "NvTmRepCR1"
  "NvTmRepCR2"
  "NvTmRepCR3"
) do (
  schtasks /Change /TN %%T /Disable >nul 2>&1
)

REM Prevent the NVIDIA driver from sending telemetry data
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\Startup" /v "SendNonNvDisplayDetails" /t REG_DWORD /d 0 /f

REM Opt out of NVIDIA's Experience Improvement Program (per user)
reg add "HKCU\Software\NVIDIA Corporation\NVControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f

REM Make the NVIDIA telemetry module visible in Programs and Features (optional)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NvTelemetry" /v "SystemComponent" /t REG_DWORD /d 0 /f

REM Disable the NvTelemetryContainer service via registry (if present)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" /v "Start" /t REG_DWORD /d 4 /f
pause
