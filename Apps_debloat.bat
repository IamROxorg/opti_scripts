REM Removing Microsoft 3D Viewer
powershell -Command "Get-AppxPackage -AllUsers Microsoft.3DViewer | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.3DViewer'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Bing News
powershell -Command "Get-AppxPackage -AllUsers Microsoft.BingNews | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingNews'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Bing Weather
powershell -Command "Get-AppxPackage -AllUsers Microsoft.BingWeather | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Get Help
powershell -Command "Get-AppxPackage -AllUsers Microsoft.GetHelp | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Get Started
powershell -Command "Get-AppxPackage -AllUsers Microsoft.Getstarted | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Office Hub
powershell -Command "Get-AppxPackage -AllUsers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Solitaire Collection
powershell -Command "Get-AppxPackage -AllUsers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Sticky Notes
powershell -Command "Get-AppxPackage -AllUsers Microsoft.MicrosoftStickyNotes | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Mixed Reality Portal
powershell -Command "Get-AppxPackage -AllUsers Microsoft.MixedReality.Portal | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MixedReality.Portal'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft OneConnect
powershell -Command "Get-AppxPackage -AllUsers Microsoft.OneConnect | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.OneConnect'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft People
powershell -Command "Get-AppxPackage -AllUsers Microsoft.People | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.People'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Skype App
powershell -Command "Get-AppxPackage -AllUsers Microsoft.SkypeApp | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Todos
powershell -Command "Get-AppxPackage -AllUsers Microsoft.Todos | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Todos'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Windows Alarms
powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsAlarms | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Windows Camera
powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsCamera | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsCamera'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Windows Communications Apps
powershell -Command "Get-AppxPackage -AllUsers Microsoft.windowscommunicationsapps | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Windows Feedback Hub
powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsFeedbackHub | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Windows Maps
powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsMaps | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Windows Sound Recorder
powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsSoundRecorder | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsSoundRecorder'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Xbox Gaming Overlay
powershell -Command "Get-AppxPackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Your Phone
powershell -Command "Get-AppxPackage -AllUsers Microsoft.YourPhone | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Zune Music
powershell -Command "Get-AppxPackage -AllUsers Microsoft.ZuneMusic | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Zune Video
powershell -Command "Get-AppxPackage -AllUsers Microsoft.ZuneVideo | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Teams
powershell -Command "Get-AppxPackage -AllUsers MicrosoftTeams | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'MicrosoftTeams'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Power Automate Desktop
powershell -Command "Get-AppxPackage -AllUsers Microsoft.PowerAutomateDesktop | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.PowerAutomateDesktop'} | Remove-AppxProvisionedPackage -Online"

REM Removing Microsoft Whiteboard
powershell -Command "Get-AppxPackage -AllUsers Microsoft.Whiteboard | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Whiteboard'} | Remove-AppxProvisionedPackage -Online"

REM Removing Clipchamp
powershell -Command "Get-AppxPackage -AllUsers Microsoft.Clipchamp | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Clipchamp'} | Remove-AppxProvisionedPackage -Online"

REM Removing Web Experience Pack
powershell -Command "Get-AppxPackage -AllUsers MicrosoftWindows.Client.WebExperience | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'MicrosoftWindows.Client.WebExperience'} | Remove-AppxProvisionedPackage -Online"

REM Removing Media Player
powershell -Command "Get-AppxPackage -AllUsers Microsoft.MediaPlayer | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MediaPlayer'} | Remove-AppxProvisionedPackage -Online"

REM Removing Cortana
powershell -Command "Get-AppxPackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.549981C3F5F10'} | Remove-AppxProvisionedPackage -Online"
