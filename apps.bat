powershell -Command "Get-AppxPackage -AllUsers Microsoft.3DViewer | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.3DViewer'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.BingNews | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingNews'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.BingWeather | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.BingWeather'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.GetHelp | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.GetHelp'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.Getstarted | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Getstarted'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftOfficeHub'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftSolitaireCollection'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.MicrosoftStickyNotes | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MicrosoftStickyNotes'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.MixedReality.Portal | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.MixedReality.Portal'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.OneConnect | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.OneConnect'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.People | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.People'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.SkypeApp | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.SkypeApp'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.Todos | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Todos'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsAlarms | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsAlarms'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsCamera | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsCamera'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.windowscommunicationsapps | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.windowscommunicationsapps'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsFeedbackHub | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsFeedbackHub'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsMaps | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsMaps'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.WindowsSoundRecorder | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.WindowsSoundRecorder'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.XboxGamingOverlay'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.YourPhone | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.YourPhone'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.ZuneMusic | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneMusic'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.ZuneVideo | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.ZuneVideo'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers MicrosoftTeams | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'MicrosoftTeams'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.PowerAutomateDesktop | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.PowerAutomateDesktop'} | Remove-AppxProvisionedPackage -Online"

powershell -Command "Get-AppxPackage -AllUsers Microsoft.Whiteboard | Remove-AppxPackage -AllUsers"
powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -eq 'Microsoft.Whiteboard'} | Remove-AppxProvisionedPackage -Online"
