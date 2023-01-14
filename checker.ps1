
  $ProgressPreference = 'SilentlyContinue'
  $ErrorActionPreference='SilentlyContinue'
  $VerbosePreference='SilentlyContinue'
  $OS = Get-CimInstance -ClassName Win32_OperatingSystem
  $Network = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Get-NetIPConfiguration
  $explorerprocesses = @(Get-WmiObject -Query "Select * FROM Win32_Process WHERE Name='explorer.exe'" -ErrorAction SilentlyContinue)
  $netsh = @(netsh lan show interface | sls State)
  $ezd = Get-WmiObject win32_product | where {$_.name -like 'ezd.AddIn*'} | select version | Select-Object Version -ExpandProperty Version
  $abc = @(netsh lan show interface | sls State)
  $netsh = "$abc"
  $TightService = Get-WmiObject -Class win32_service | Where-Object {$_.Name -eq 'tvnserver'}
  $UltraService = Get-WmiObject -Class win32_service | Where-Object {$_.Name -eq 'uvnc_service'}
  $LSA = Get-WmiObject -Class win32_service | Where-Object {$_.Name -eq 'LSAService'}
  $Event = @(Get-WinEvent -LogName 'Microsoft-Windows-Wired-AutoConfig/Operational' -MaxEvents 4 | select-object TimeCreated, Message | Format-Table -Property * -HideTableHeaders)
  ForEach ($i in $explorerprocesses){
          $user = $i.GetOwner().User
          $domena = $i.GetOwner().Domain}
  CD HKCU:
  $InternetSettings = Get-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
  $BrowserSettings = Get-ItemProperty $InternetSettings
  $ProxyAutoConfigURL = $BrowserSettings.AutoConfigURL
  $abcd = $Network.DNSServer | Where-Object {$_.AddressFamily -eq '2'} | Select-Object ServerADdresses -ExpandProperty ServerAddresses
  Write-Host "   - - - - - - - - - - - - - - - - - - - -"
  Write-Host "              [ Test hosta ]" -ForegroundColor yellow
  Write-Host "   - - - - - - - - - - - - - - - - - - - -" -nonewline
  $props = [pscustomobject]@{
      '  System' = $OS.Caption
      '  Wersja' = $OS.Version
      '  Hostname' = $env:computername
      '  Zalogowany User' = "$domena / $user"
      '  MAC' = $Network.NetAdapter.LinkLayerAddress 
      '  IPv4' = $Network.IPv4Address.IPAddress
      '  GW' = $Network.IPv4DefaultGateway.nexthop	
      '  DNSy' = $Network.DNSServer | Where-Object {$_.AddressFamily -eq '2'} | Select-Object ServerADdresses -ExpandProperty ServerAddresses
      '  LinkSpeed' = $Network.NetAdapter.LinkSpeed 
      '  Proxy' = $ProxyAutoConfigURL = $BrowserSettings.AutoConfigURL
      '  Tight' = $TightService | select-object State -ExpandProperty State
      '  Ultra' = $UltraService | select-object State -ExpandProperty State
      '  LSA' = $LSA | select-object State -ExpandProperty State
      '  EZD Addin' = $ezd}
  $pingajGW = Test-NetConnection -ComputerName $props.GW -InformationLevel Quiet
  $pingajDNSy = Test-NetConnection -ComputerName $abcd[0] -InformationLevel Quiet
  $pingajIntranet = Test-NetConnection -ComputerName '10.40.7.12' -InformationLevel Quiet -WarningAction SilentlyContinue
  $pingajEZD = Test-NetConnection -ComputerName '10.40.1.190' -InformationLevel Quiet -WarningAction SilentlyContinue
  $pingajInternet = Test-NetConnection -ComputerName '8.8.8.8' -InformationLevel Quiet -WarningAction SilentlyContinue
  $pingajExch = Test-NetConnection -ComputerName '10.40.1.154' -InformationLevel Quiet -WarningAction SilentlyContinue
  $dot1x = $netsh | Select-Object State -ExpandProperty State
  $VNC5900 = Test-NetConnection 127.0.0.1 -Port 5900 -InformationLevel Quiet -WarningAction SilentlyContinue
  $VNC5901 = Test-NetConnection 127.0.0.1 -Port 5901 -InformationLevel Quiet -WarningAction SilentlyContinue
  $props | Add-Member -MemberType NoteProperty -Value $VNC5900 -Name '  VNC Port 5900' -WarningAction SilentlyContinue
  $props | Add-Member -MemberType NoteProperty -Value $VNC5901 -Name '  VNC Port 5901' -WarningAction SilentlyContinue
  $props | Add-Member -MemberType NoteProperty -Value $pingajGW -Name '  Pinga GW'
  $props | Add-Member -MemberType NoteProperty -Value $pingajDNSy -Name '  Pinga DNS'
  $props | Add-Member -MemberType NoteProperty -Value $pingajEZD -Name '  Pinga EZD'
  $props | Add-Member -MemberType NoteProperty -Value $pingajExch -Name '  Pinga Exchange'
  $props | Add-Member -MemberType NoteProperty -Value $pingajIntranet -Name '  Pinga Intranet'
  $props | Add-Member -MemberType NoteProperty -Value $pingajInternet -Name '  Pinga Googla'
  $props
  Write-Host "  NAC dot1x       :" -nonewline; Write-Host ($netsh.Substring($netsh.Lenght+22)) -f green -nonewline;
  Write-Host " "
  Write-Host " "
  Write-Host "   - - - - - - - - - - - - - - - - - - - -" 
  Write-Host "       [ Cztery ostatnie logi dot1x ]" -ForegroundColor yellow
  Write-Host "   - - - - - - - - - - - - - - - - - - - -"
  $evencik = Get-WinEvent -LogName 'Microsoft-Windows-Wired-AutoConfig/Operational' -MaxEvents 4 | select-object TimeCreated, Message | Format-Table -Property * -HideTableHeaders | Out-String | ForEach-Object { $_.Trim() };
  Write-Host $evencik -f gray
  Write-Host " "
  Write-Host "   - - - - - - - - - - - - - - - - - - - -" 
  Write-Host "          [ Pozapinane drukarki ]" -ForegroundColor yellow
  Write-Host "   - - - - - - - - - - - - - - - - - - - -"
  $printerek = Get-Printer | where Shared -eq $true | Select Name, DriverName, PortName, PrinterStatus | Format-Table -Property * -HideTableHeaders | Out-String | ForEach-Object { $_.Trim() };
  Write-Host $printerek -f gray
  Write-Host "  "

 
