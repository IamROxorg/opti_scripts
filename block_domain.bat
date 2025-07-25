@echo off
setlocal enabledelayedexpansion

set HOSTS_FILE=%SystemRoot%\System32\drivers\etc\hosts

:: Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must be run as administrator.
    pause
    exit /b
)

echo.
echo Adding domains to the hosts file...
echo (Already existing entries will be ignored.)
echo.

:: Add each domain one by one
for %%D in (
    vortex.data.microsoft.com
    vortex-win.data.microsoft.com
    telecommand.telemetry.microsoft.com
    telecommand.telemetry.microsoft.com.nsatc.net
    oca.telemetry.microsoft.com
    oca.telemetry.microsoft.com.nsatc.net
    sqm.telemetry.microsoft.com
    sqm.telemetry.microsoft.com.nsatc.net
    watson.telemetry.microsoft.com
    watson.telemetry.microsoft.com.nsatc.net
    redir.metaservices.microsoft.com
    choice.microsoft.com
    choice.microsoft.com.nsatc.net
    df.telemetry.microsoft.com
    reports.wes.df.telemetry.microsoft.com
    wes.df.telemetry.microsoft.com
    services.wes.df.telemetry.microsoft.com
    sqm.df.telemetry.microsoft.com
    telemetry.microsoft.com
    watson.ppe.telemetry.microsoft.com
    telemetry.appex.bing.net
    telemetry.urs.microsoft.com
    settings-sandbox.data.microsoft.com
    vortex-sandbox.data.microsoft.com
    survey.watson.microsoft.com
    watson.live.com
    watson.microsoft.com
    statsfe2.ws.microsoft.com
    corpext.msitadfs.glbdns2.microsoft.com
    compatexchange.cloudapp.net
    cs1.wpc.v0cdn.net
    a-0001.a-msedge.net
    statsfe2.update.microsoft.com.akadns.net
    sls.update.microsoft.com.akadns.net
    fe2.update.microsoft.com.akadns.net
    diagnostics.support.microsoft.com
    corp.sts.microsoft.com
    statsfe1.ws.microsoft.com
    pre.footprintpredict.com
    i1.services.social.microsoft.com
    i1.services.social.microsoft.com.nsatc.net
    feedback.windows.com
    feedback.microsoft-hohm.com
    feedback.search.microsoft.com
    rad.msn.com
    preview.msn.com
    ad.doubleclick.net
    ads.msn.com
    ads1.msads.net
    ads1.msn.com
    a.ads1.msn.com
    a.ads2.msn.com
    adnexus.net
    adnxs.com
    az361816.vo.msecnd.net
    az512334.vo.msecnd.net
) do (
    findstr /C:"127.0.0.1 %%D" "%HOSTS_FILE%" >nul || (
        echo 127.0.0.1 %%D>>"%HOSTS_FILE%"
        echo Blocked: %%D
    )
)

echo.
echo Done blocking telemetry and ad domains.
pause
