@echo off
cls
echo ================================
echo  Block drivers through WU
echo ================================
echo.

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 3 /f

reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState" /v ExcludeWUDrivers /t REG_DWORD /d 1 /f

echo.
echo Restart your computer
pause
