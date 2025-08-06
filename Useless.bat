@echo off
REM ===============================================================================
REM Windows Privacy & Performance Optimization Script - Enhanced Version
REM ===============================================================================
REM This script disables telemetry, tracking, and unwanted Windows features
REM while optimizing system performance and removing bloatware
REM Auto-elevates to Administrator privileges if needed
REM ===============================================================================

REM Check for administrator privileges
net session   2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Attempting to restart with administrator rights...
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo Starting Windows Privacy and Performance Optimization - Enhanced...
echo Running with Administrator privileges...
echo.

REM ===============================================================================
REM TELEMETRY & DATA COLLECTION
REM ===============================================================================

echo [1/15] Disabling telemetry services and data collection...

REM Stop and disable telemetry services
sc stop DiagTrack   2>&1
sc config DiagTrack start=disabled   2>&1
sc stop dmwappushservice   2>&1
sc config dmwappushservice start=disabled   2>&1
sc stop WaaSMedicSvc   2>&1
sc config WaaSMedicSvc start=disabled   2>&1
sc stop DiagSvc   2>&1
sc config DiagSvc start=disabled   2>&1
sc stop diagnosticshub.standardcollector.service   2>&1
sc config diagnosticshub.standardcollector.service start=disabled   2>&1

REM Clear diagnostic tracking logs
echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl 2 

REM Disable telemetry via registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitDiagnosticLogCollection" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f  

REM Disable diagnostic tracking in registry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "Enabled" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f  

REM Disable Application Compatibility features
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f  

REM Disable advertising and personalization
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f  

echo Telemetry disabled.

REM ===============================================================================
REM WINDOWS SYNC & CLOUD FEATURES - ENHANCED
REM ===============================================================================
echo [2/15] Disabling Windows sync and cloud features - Enhanced...

REM Disable Settings Sync for current user
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f

REM Disable all sync categories - Enhanced with additional groups
for %%G in (Accessibility AppSync BrowserSettings Credentials DesktopTheme Language PackageState Personalization StartLayout Windows) do (
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\%%G" /v "Enabled" /t REG_DWORD /d 0 /f
)

REM --- Clés supplémentaires SettingSync ---
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d 0 /f

REM Disable SettingSync via Group Policy - Enhanced
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f

REM Disable individual sync categories via Group Policy - Enhanced
for %%P in (AppSync Application Credentials DesktopTheme Personalization StartLayout WebBrowser Windows) do (
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "Disable%%PSettingSync" /t REG_DWORD /d 2 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "Disable%%PSettingSyncUserOverride" /t REG_DWORD /d 2 /f
)

REM --- Clés supplémentaires SettingSync (suite) ---
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f

REM Additional detailed SettingSync policies from Script 1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 2 /f

REM Disable sync on paid networks
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 2 /f

echo Windows sync disabled - Enhanced.
REM ===============================================================================
REM CONSUMER FEATURES & CONTENT DELIVERY
REM ===============================================================================
echo [3/15] Disabling consumer features and content delivery...

REM Disable Windows consumer features and sponsored content
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f

REM Disable Content Delivery Manager features
for %%C in (ContentDeliveryAllowed FeatureManagementEnabled OemPreInstalledAppsEnabled PreInstalledAppsEnabled PreInstalledAppsEverEnabled SilentInstalledAppsEnabled SoftLandingEnabled SystemPaneSuggestionsEnabled SubscribedContentEnabled) do (
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "%%C" /t REG_DWORD /d 0 /f
)

REM --- Clés supplémentaires ContentDeliveryManager ---
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f

REM Disable specific subscribed content
for %%S in (338387 338388 338389 338393 310093 353694 353696 353698) do (
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-%%SEnabled" /t REG_DWORD /d 0 /f
)

REM --- Clés supplémentaires SubscribedContent ---
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f

REM Disable lock screen features
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f

REM Disable other unwanted features
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f

REM Additional interface optimizations
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f

REM Disable experimental features
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\FlightSettings" /v "UserPreferredRedirectStage" /t REG_DWORD /d 0 /f

echo Consumer features disabled.

REM ===============================================================================
REM SEARCH, CORTANA & COPILOT
REM ===============================================================================

echo [4/15] Disabling search suggestions, Cortana, and Copilot...

REM Disable Bing Search and Cortana
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f  

REM Disable Windows Search policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f  

REM Disable search suggestions (Enhanced - avoid duplication)
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d 0 /f  

REM Disable Windows Copilot
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f  

REM Disable News and Interests (Enhanced - avoid duplication)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f  

echo Search features disabled.

REM ===============================================================================
REM ACTIVITY TRACKING & ERROR REPORTING
REM ===============================================================================

echo [5/15] Disabling activity tracking and error reporting...

REM Disable Activity Feed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f  

REM Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DoReport" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f  
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f  

REM Disable feedback and CEIP
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Assist" /v "NoImplicitFeedback" /t REG_DWORD /d 1 /f  

echo Activity tracking disabled.

REM ===============================================================================
REM LOCATION & PRIVACY SERVICES
REM ===============================================================================

echo [6/15] Disabling location services and privacy invasive features...

REM Disable Location Services
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f  

REM Disable device metadata network fetch
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f  

REM Disable online speech recognition
reg add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f  

REM Disable personalization and typing data collection
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f  
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f  
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f  

REM Disable maps auto-updates
reg add "HKLM\SYSTEM\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d 0 /f  

echo Location services disabled.

REM ===============================================================================
REM GAMING & MULTIMEDIA FEATURES
REM ===============================================================================

echo [7/15] Disabling gaming overlay and multimedia features...

REM Disable Game DVR and Xbox features
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d 2 /f  
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f  
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d 1 /f  
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d 1 /f  
reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f  

REM Disable Your Phone app
reg add "HKCU\Software\Policies\Microsoft\Phone" /v "DisableYourPhone" /t REG_DWORD /d 1 /f  

echo Gaming features disabled.

REM ===============================================================================
REM WINDOWS UPDATE & REMOTE FEATURES
REM ===============================================================================

echo [8/15] Configuring Windows Update and disabling remote features...

REM Disable Delivery Optimization (P2P updates)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f  
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f  

REM Disable Remote Desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 1 /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "UserAuthentication" /t REG_DWORD /d 0 /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f  

REM Stop Remote Desktop services
sc stop TermService   2>&1
sc config TermService start=disabled   2>&1
sc stop UmRdpService   2>&1
sc config UmRdpService start=disabled   2>&1

echo Remote features disabled.

REM ===============================================================================
REM ADDITIONAL HARDWARE SERVICES - ENHANCED
REM ===============================================================================

echo [9/15] Disabling additional hardware services - Enhanced...

REM Disable Firewire
reg add "HKLM\SYSTEM\CurrentControlSet\Services\1394ohci" /v "Start" /t REG_DWORD /d 4 /f   2>&1

REM Disable UEV (User Experience Virtualization)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentDriver" /v "Start" /t REG_DWORD /d 4 /f   2>&1

REM Disable Windows Remote desktop bus
reg add "HKLM\SYSTEM\CurrentControlSet\Services\rdpbus" /v "Start" /t REG_DWORD /d 4 /f   2>&1

REM Disable other legacy hardware services
for %%S in (
    "beep" "fdc" "flpydisk" "sfloppy" 
) do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%S" /v "Start" /t REG_DWORD /d 4 /f   2>&1
)

echo Additional hardware services disabled.

REM ===============================================================================
REM EDGE BROWSER OPTIMIZATIONS
REM ===============================================================================

echo [10/15] Optimizing Microsoft Edge settings...

REM Disable Edge startup boost and background mode
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d 0 /f  

echo Edge optimized.

REM ===============================================================================
REM SYSTEM PERFORMANCE OPTIMIZATIONS
REM ===============================================================================

echo [11/15] Applying system performance optimizations...

REM Optimize system responsiveness
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f  
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f  
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f  
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f  
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f  

REM Disable hibernation and fast startup
powercfg -h off   2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f  

REM Stop and disable SysMain (Superfetch)
sc stop "SysMain"   2>&1
sc config "SysMain" start=disabled   2>&1

REM Disable password expiration
net accounts /maxpwage:unlimited   2>&1

echo Performance optimizations applied.

REM ===============================================================================
REM EXPLORER & INTERFACE CUSTOMIZATIONS
REM ===============================================================================

echo [12/15] Customizing Windows Explorer and interface...

REM Show file extensions and hidden files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f  

REM Set Explorer to open to This PC instead of Quick Access
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f  

REM Disable taskbar widgets and chat
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f  

REM Disable notifications
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 1 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f  

REM Disable transparency effects
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 0 /f  

REM Disable Windows Spotlight
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f  
reg add "HKCU\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f  

REM Disable accessibility features shortcuts
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f  
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f  
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f  
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f  

REM Remove Home and Gallery from Explorer
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /f   2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f   2>&1

REM Enable classic context menu (Windows 11)
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve   2>&1

echo Interface customizations applied.

REM ===============================================================================
REM SCHEDULED TASKS OPTIMIZATION - ENHANCED
REM ===============================================================================

echo [13/15] Disabling unnecessary scheduled tasks - Enhanced...

REM Disable telemetry and data collection tasks
for %%T in (
    "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "Microsoft\Windows\Application Experience\PcaPatchDbTask"
    "Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "Microsoft\Windows\Application Experience\StartupAppTask"
    "Microsoft\Windows\Application Experience\MareBackup"
    "Microsoft\Windows\Autochk\Proxy"
    "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "Microsoft\Windows\Feedback\Siuf\DmClient"
    "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    "Microsoft\Windows\Windows Error Reporting\QueueReporting"
    "Microsoft\Windows\Maps\MapsUpdateTask"
    "Microsoft\Windows\Maps\MapsToastTask"
    "Microsoft\Windows\Shell\FamilySafetyMonitor"
    "Microsoft\Windows\Shell\FamilySafetyRefreshTask"
) do (
    schtasks /Change /TN "%%T" /Disable   2>&1
)

REM Disable system maintenance and diagnostic tasks
for %%T in (
    "Microsoft\Windows\Defrag\ScheduledDefrag"
    "Microsoft\Windows\DiskCleanup\SilentCleanup"
    "Microsoft\Windows\DiskFootprint\Diagnostics"
    "Microsoft\Windows\DiskFootprint\StorageSense"
    "Microsoft\Windows\Maintenance\WinSAT"
    "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"
    "Microsoft\Windows\RetailDemo\CleanupOfflineContent"
    "Microsoft\Windows\Servicing\StartComponentCleanup"
    "Microsoft\Windows\Setup\SetupCleanupTask"
    "Microsoft\Windows\Setup\SnapshotCleanupTask"
) do (
    schtasks /Change /TN "%%T" /Disable   2>&1
)

REM Disable feature management and sync tasks
for %%T in (
    "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures"
    "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing"
    "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting"
    "Microsoft\Windows\Flighting\OneSettings\RefreshCache"
    "Microsoft\Windows\Input\LocalUserSyncDataAvailable"
    "Microsoft\Windows\Input\MouseSyncDataAvailable"
    "Microsoft\Windows\Input\PenSyncDataAvailable"
    "Microsoft\Windows\Input\TouchpadSyncDataAvailable"
    "Microsoft\Windows\International\Synchronize Language Settings"
    "Microsoft\Windows\LanguageComponentsInstaller\Installation"
    "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources"
    "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation"
) do (
    schtasks /Change /TN "%%T" /Disable   2>&1
)

REM Disable Update Orchestrator tasks
for %%T in (
    "Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
    "Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task"
    "Microsoft\Windows\UpdateOrchestrator\UpdateModelTask"
    "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker"
) do (
    schtasks /Change /TN "%%T" /Disable   2>&1
)

REM Additional scheduled tasks from Script 1 - Enhanced
for %%T in (
    "Microsoft\Windows\Device Information\Device"
    "Microsoft\Windows\Device Information\Device User"
    "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask"
    "Microsoft\Windows\License Manager\TempSignedLicenseExchange"
    "Microsoft\Windows\Management\Provisioning\Cellular"
    "Microsoft\Windows\Management\Provisioning\Logon"
    "Microsoft\Windows\NetTrace\GatherNetworkInfo"
    "Microsoft\Windows\UPnP\UPnPHostConfig"
    "Microsoft\Windows\WDI\ResolutionHost"
    "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"
    "Microsoft\Windows\TPM\Tpm-HASCertRetr"
    "Microsoft\Windows\TPM\Tpm-Maintenance"
    "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask"
    "Microsoft\Windows\User Profile Service\HiveUploadTask"
    "Microsoft\Windows\Workplace Join\Automatic-Device-Join"
    "Microsoft\Windows\Speech\SpeechModelDownloadTask"
    "Microsoft\Windows\PushToInstall\Registration"
    "Microsoft\Windows\Task Manager\Interactive"
    "Microsoft\Windows\SpacePort\SpaceAgentTask"
    "Microsoft\Windows\SpacePort\SpaceManagerTask"
    "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization"
    "Microsoft\Windows\Sysmain\ResPriStaticDbSync"
    "Microsoft\Windows\Sysmain\WsSwapAssessmentTask"
    "Microsoft\Windows\WwanSvc\NotificationTask"
    "Microsoft\Windows\WwanSvc\OobeDiscovery"
    "Microsoft\Windows\MUI\LPRemove"
    "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"
    "Microsoft\Windows\PI\Sqm-Tasks"
    "Microsoft\Windows\WOF\WIM-Hash-Management"
    "Microsoft\Windows\WOF\WIM-Hash-Validation"
    "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization"
    "Microsoft\Windows\Work Folders\Work Folders Maintenance Work"
) do (
    schtasks /Change /TN "%%T" /Disable   2>&1
)

echo Scheduled tasks optimized - Enhanced.

REM ===============================================================================
REM DISABLE AUTOLOGGERS & LOG COLLECTORS - ENHANCED
REM ===============================================================================

echo [14/15] Disabling Windows Autologgers - Enhanced...

REM Disable WMI Autologgers - Enhanced with additional loggers
for %%A in (
    "ReadyBoot" "SpoolerLogger" "UBPM" "WiFiSession" 
    "Circular Kernel Context Logger" "Diagtrack-Listener" "LwtNetLog"
    "Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace" "NetCore" "NtfsLog"
    "CloudExperienceHostOobe" "DefenderApiLogger" "DefenderAuditLogger"
    "RadioMgr" "RdrLog" "SQMLogger" "DiagLog" "WdiContextLog"
) do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\%%A" /v "Start" /t REG_DWORD /d 0 /f   2>&1
)

REM Stop active logman sessions
for %%L in (
    "NTFSLog" "WiFiDriverIHVSession" "WiFiDriverSession" "WiFiSession"
    "SleepStudyTraceSession" "1DSListener" "MpWppTracing" "Circular Kernel Context Logger"
    "DiagLog" "LwtNetLog" "Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace"
    "NetCore" "RadioMgr" "ReFSLog" "WdiContextLog" "ShadowPlay"
) do (
    logman stop %%L -ets   2>&1
)

echo Autologgers disabled - Enhanced.

REM ===============================================================================
REM SHELL ENHANCEMENTS - CREATE TEMPLATES
REM ===============================================================================

echo [15/15] Adding shell enhancements and creating templates...

REM Create shell new templates for .bat and .reg files
mkdir C:\Windows\ShellNew   2>&1
echo @echo off > C:\Windows\ShellNew\template.bat
echo Windows Registry Editor Version 5.00 > C:\Windows\ShellNew\template.reg

REM Add context menu entries for creating new .bat and .reg files
reg add "HKCR\.bat\ShellNew" /v "FileName" /t REG_SZ /d "template.bat" /f  
reg delete "HKCR\.bat\ShellNew" /v "NullFile" /f   2>&1
reg add "HKCR\.reg\ShellNew" /v "FileName" /t REG_SZ /d "template.reg" /f  
reg delete "HKCR\.reg\ShellNew" /v "NullFile" /f   2>&1

echo Shell enhancements added.

REM ===============================================================================
REM DISABLE SMB1 PROTOCOL (SECURITY)
REM ===============================================================================

echo Disabling SMB1 protocol for security...

powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart"   2>&1
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Client' -NoRestart"   2>&1
powershell -Command "Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol-Server' -NoRestart"   2>&1

REM Remove RDP capabilities
powershell -Command "Get-WindowsCapability -Online ^| Where-Object { $_.Name -like '*RemoteDesktop*' } ^| ForEach-Object { Remove-WindowsCapability -Online -Name $_.Name }"   2>&1

echo SMB1 protocol disabled.

REM ===============================================================================
REM DISABLE STORAGE SENSE & BACKGROUND DIAGNOSTICS
REM ===============================================================================

echo Disabling background diagnostics...

REM Disable Storage Sense
powershell -Command "Remove-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Recurse -ErrorAction SilentlyContinue"   2>&1

REM Disable app background task diagnostic log
powershell -NoProfile -ExecutionPolicy Bypass -Command "Disable-AppBackgroundTaskDiagnosticLog"   2>&1

echo Background diagnostics disabled.

:: Disable App Suggestions in Windows Ink Workspace
:: Turns off suggested apps in the Windows Ink Workspace
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v PenWorkspaceAppSuggestionsEnabled /t REG_DWORD /d 0 /f

:: Disable Bluetooth Advertising
:: Disables Bluetooth LE advertisements
reg add "HKLM\SYSTEM\CurrentControlSet\Services\BthAdvLEEnumerator" /v Start /t REG_DWORD /d 4 /f

:: Complete Disable Cloud Optimized Content
:: Turns off even more content delivery options
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v FeatureManagementEnabled /t REG_DWORD /d 0 /f

:: Disable My People App Suggestions
:: Completely disables the People bar and suggestions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\People" /v PeopleBand /t REG_DWORD /d 0 /f

:: Disable Suggestions in Timeline
:: Prevents Windows Timeline from suggesting content
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

echo Press any key to exit...
pause  


