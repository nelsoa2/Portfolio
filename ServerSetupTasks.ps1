	#READ ME: Windows remote management is required for the tasks to work.
	# Start-Service "winrm"; Set-Service "winrm" -StartupType Automatic; Enable-PSRemoting –force; 
	#ToUndo
	# Disable-PSRemoting –force;
	# winrm delete winrm/config/listener?address=*+transport=HTTP
	# Stop-Service winrm
	# Set-Service -Name winrm -StartupType Disabled
	# Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccoun -Value 0
	# #Disable FireWall Exception
	#
	#Pick the necessary tasks for setting up a fresh server via TeamCity.
	
task ESTTimeZone -requiredVariables server {		
	invoke-command -computername $server -scriptblock {	
		$tz = [System.TimeZone]::CurrentTimeZone.StandardName
		write-host "Current Time Zone: $tz"
		C:\windows\system32\tzutil /s "Eastern Standard Time" 
	}
}

task UTCTimeZone -requiredVariables server {		
	invoke-command -computername $server -scriptblock {	
		$tz = [System.TimeZone]::CurrentTimeZone.StandardName
		write-host "Current Time Zone: $tz"
		C:\windows\system32\tzutil /s "UTC"
	}
}

task CreateDBfolders -requiredVariables server, tempDB_log, tempDB_data, DB_log, DB_data {		
	#Create basic log folders
	invoke-command -computername $server -scriptblock {	param($tempDB_log,$tempDB_data,$DB_log,$DB_data)
	if ($tempDB_log) {new-item $tempDB_log -itemType directory -Force }
	if ($tempDB_data) {new-item $tempDB_data -itemType directory -Force }
	if ($DB_log) {new-item $DB_log -itemType directory -Force }
	if ($DB_data) {new-item $DB_data -itemType directory -Force }
	} -ArgumentList $tempDB_log,$tempDB_data,$DB_log,$DB_data
}

task TurnOnEssentialServices -requiredVariables server {	
	#Turning on some essential services
	invoke-command -computername $server -scriptblock {	Set-Service "RemoteAccess" -StartupType Automatic -ErrorAction SilentlyContinue
	Start-Service "RemoteAccess" -ErrorAction SilentlyContinue
	Set-Service "RpcSs" -StartupType Automatic -ErrorAction SilentlyContinue
	Start-Service "RpcSs" -ErrorAction SilentlyContinue
	Set-Service "RpcLocator" -StartupType Automatic -ErrorAction SilentlyContinue
	Start-Service "RpcLocator" -ErrorAction SilentlyContinue
	Set-Service "SepMasterService" -StartupType Automatic -ErrorAction SilentlyContinue
	Start-Service "SepMasterService" -ErrorAction SilentlyContinue
	Set-Service "NSClientpp" -StartupType Automatic -ErrorAction SilentlyContinue
	Start-Service "NSClientpp" -ErrorAction SilentlyContinue
	}
}

task RenameComputer -requiredVariables NewComputerName, server {	
	invoke-command -computername $server -scriptblock {	$comp = get-content env:computername
	IF ($NewComputerName -eq $comp)
	{
		Rename-Computer -NewName $NewComputerName -LocalCredential admin
	} }
}

task RenameDomain -requiredVariables NewDomain, AGTacct ,SqlAgentPassword, server {	
	invoke-command -computername $server -scriptblock {	$domain = (gwmi WIN32_ComputerSystem).Domain
	IF ($NewDomain -eq $domain)
	{
		Add-Computer -DomainName $NewDomain -Credential $AGTacct -Password $SqlAgentPassword
	} }
}

task InstallSQL2012 -requiredVariables SqlAgentPassword, SqlServicePassword, tempDB_log, tempDB_data, DB_log, DB_data, SVCacct, AGTacct, SysAdmins, server, SQLedition, InstallAnalysisServices, InstallReportingServices {	
	#Supress network file warnings (SEE_MASK_NOZONECHECKS)
	#Add SVCacct as administrator on the box
	invoke-command -computername $server -scriptblock {	param($SQLedition,$server,$tempDB_log,$tempDB_data,$DB_log,$DB_data,$SVCacct,$AGTacct,$InstanceName,$SqlServicePassword,$SqlAgentPassword,$SysAdmins,$InstallAnalysisServices,$InstallReportingServices)
	$env:SEE_MASK_NOZONECHECKS = 1
	$domain = (gwmi WIN32_ComputerSystem).Domain
	$user1 = $SVCacct -replace "$domain\\", ""
	$user2 = $AGTacct -replace "$domain\\", ""
	$user1_chk = $SVCacct -replace "\\", "/"
	$user2_chk = $AGTacct -replace "\\", "/"
	write-host "user1_chk:"$user1_chk "user2_chk:"$user2_chk "user1:"$user1 "user2:"$user2 "SVCacct:"$SVCacct "AGTacct:"$AGTacct
	if (!([ADSI]"WinNT://$server/Administrators,group").isMember("WinNT://$user1_chk"))
	{([ADSI]"WinNT://$server/Administrators,group").add("WinNT://$user1")}
	if (!([ADSI]"WinNT://$server/Administrators,group").isMember("WinNT://$user2_chk"))
	{([ADSI]"WinNT://$server/Administrators,group").add("WinNT://$user2")}
	#Install SQL 2012
	$NullName = [string]::IsNullOrEmpty($InstanceName)
	IF ($SQLedition -eq "enterprise")
	{copy-item "\\fileServer\sql_2012_enterprise_sp1_x64_1227976\" "C:\Temp\SQLserver2012" -Recurse}
	IF ($SQLedition -eq "development")
	{copy-item "\\fileServer\SQL Server 2012 SP1 Dev ed\" "C:\Temp\SQLserver2012" -Recurse}
	$Features = "SQL,Tools,IS"
	IF ($InstallAnalysisServices -eq 1)
	{$Features = $Features + ",AS"}
	IF ($InstallReportingServices -eq 1)
	{$Features = $Features + ",RS"}
	if ($NullName)
	{Start-Process "C:\Temp\SQLserver2012\setup.exe" -ArgumentList "/Q", "/IACCEPTSQLSERVERLICENSETERMS", "/FEATURES=$Features", "/ACTION=Install", "/ENU", "/INSTANCENAME=MSSQLSERVER", "/AGTSVCACCOUNT=$AGTacct", "/AGTSVCPASSWORD=$SqlAgentPassword", "/AGTSVCSTARTUPTYPE=Automatic", "/ASSVCACCOUNT=$SVCacct", "/ASSVCPASSWORD=$SqlServicePassword", "/SQLSVCACCOUNT=$SVCacct", "/SQLSVCPASSWORD=$SqlServicePassword", "/SQLSVCSTARTUPTYPE=Automatic", "/SQLTEMPDBDIR=$tempDB_data", "/SQLTEMPDBLOGDIR=$tempDB_log", "/SQLUSERDBDIR=$DB_data", "/SQLUSERDBLOGDIR=$DB_log", "/ISSVCACCOUNT=$SVCacct", "/ISSVCPASSWORD=$SqlServicePassword", "/RSSVCACCOUNT=$SVCacct", "/RSSVCPASSWORD=$SqlServicePassword", "/SQLSYSADMINACCOUNTS=$SysAdmins", "/UpdateEnabled=FALSE" -Wait}
	else
	{Start-Process "C:\Temp\SQLserver2012\setup.exe" -ArgumentList "/Q", "/IACCEPTSQLSERVERLICENSETERMS", "/FEATURES=$Features", "/ACTION=Install", "/ENU", "/INSTANCENAME=$InstanceName", "/AGTSVCACCOUNT=$AGTacct", "/AGTSVCPASSWORD=$SqlAgentPassword", "/AGTSVCSTARTUPTYPE=Automatic", "/ASSVCACCOUNT=$SVCacct", "/ASSVCPASSWORD=$SqlServicePassword", "/SQLSVCACCOUNT=$SVCacct", "/SQLSVCPASSWORD=$SqlServicePassword", "/SQLSVCSTARTUPTYPE=Automatic", "/SQLTEMPDBDIR=$tempDB_data", "/SQLTEMPDBLOGDIR=$tempDB_log", "/SQLUSERDBDIR=$DB_data", "/SQLUSERDBLOGDIR=$DB_log", "/ISSVCACCOUNT=$SVCacct", "/ISSVCPASSWORD=$SqlServicePassword", "/RSSVCACCOUNT=$SVCacct", "/RSSVCPASSWORD=$SqlServicePassword", "/SQLSYSADMINACCOUNTS=$SysAdmins", "/UpdateEnabled=FALSE" -Wait}
	Remove-Item env:\SEE_MASK_NOZONECHECKS } -ArgumentList $SQLedition,$server,$tempDB_log,$tempDB_data,$DB_log,$DB_data,$SVCacct,$AGTacct,$InstanceName,$SqlServicePassword,$SqlAgentPassword,$SysAdmins,$InstallAnalysisServices,$InstallReportingServices
}

task InstallDotNet3 -requiredVariables server {		
	invoke-command -computername $server -scriptblock {	
		$env:SEE_MASK_NOZONECHECKS = 1
		Start-Process "\\fileServer\dotNetFx35setup.exe" -ArgumentList "/S", "/q", "/norestart" -Wait
		Remove-Item env:\SEE_MASK_NOZONECHECKS 
	}
}

task InstallDotNet45 -requiredVariables server {	
	#Supress network file warnings
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
		#Add .net 4.5
	Start-Process "\\fileServer\dotNetFx45_Full_setup.exe" -ArgumentList "/S", "/q", "/norestart" -Wait
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task InstallMVC3 -requiredVariables server {	
	#Supress network file warnings
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
	Start-Process "\\fileServer\AspNetMVC3Setup.exe" -ArgumentList "/S", "/q", "/norestart" -Wait
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task InstallMVC4 -requiredVariables server {	
	#Supress network file warnings
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
	Start-Process "\\fileServer\AspNetMVC4Setup.exe" -ArgumentList "/S", "/q", "/norestart" -Wait
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task InstallAntiVirus -requiredVariables server {	
	#Supress network file warnings
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
		#Add anti-virus
	Start-Process "\\fileServer\AntiVirus\setup.exe" -ArgumentList "/S" -Wait
	Start-Process "\\fileServer\AntiVirus.exe"
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task CustomizeRegistry -requiredVariables server {	
	#Supress network file warnings
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
	#DNS lookup list to be complete
	if((Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\TCPIP\Parameters\" -Name SearchList -ea 0).SearchList -eq "Dev.local,Test.local,Prod.com") {write-host '   DNS SearchList already set' -foreground "magenta"} ELSE { IF ((Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\TCPIP\Parameters\" -Name SearchList -ea 0).SearchList) {Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\TCPIP\Parameters\" -Name "SearchList" 	-Value "Dev.local,Test.local,Prod.com"}}
	
	#Set max power consumption to 100
	if((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\" -Name ValueMax -ea 0).ValueMax -eq 100) {write-host '   Max power already set to 100' -foreground "magenta"} ELSE { IF ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\" -Name ValueMax -ea 0).ValueMax) {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\" -Name "ValueMax" -Value "100"}}

	if((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec\" -Name ValueMax -ea 0).ValueMax -eq 100) {write-host '   Max power already set to 100' -foreground "magenta"} ELSE { IF ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec\" -Name ValueMax -ea 0).ValueMax) {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec\" -Name "ValueMax" -Value "100"}}
	}
}

task TraceFlags -requiredVariables server {	
	invoke-command -computername $server -scriptblock {	param($InstanceName)
	$comp = get-content env:computername
	$NullName = [string]::IsNullOrEmpty($InstanceName)
	if ($NullName)
	{$DB_inst = $comp
	$RegName = "MSSQLSERVER"}
	else
	{$DB_inst = $comp + "\"+ $InstanceName
	$RegName = $InstanceName}
	write-host $DB_inst
		#ADD trace flag 1118
	$query = "DBCC TRACEON(1118,-1)"
	sqlcmd -S ($DB_inst) -W -h -1 -v comp=$DB_inst -q $query
	exit
		#HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$InstanceName\MSSQLServer\Parameters -> Add SQLArg3 REG_SZ -T1118
	if((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name SQLArg3 -ea 0).SQLArg3) {'Propertyalready exists'} ELSE { IF ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name SQLArg0 -ea 0).SQLArg0) {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name "SQLArg3" -Value "-T1118"}}
		#ADD trace flag 3226
	$query = "DBCC TRACEON(3226,-1)"
	sqlcmd -S ($DB_inst) -W -h -1 -v comp=$DB_inst -q $query
	exit
	if((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name SQLArg4 -ea 0).SQLArg4) {'Propertyalready exists'} ELSE { IF ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name SQLArg0 -ea 0).SQLArg0) {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name "SQLArg4" -Value "-T3226"}}
		#ADD trace flag 2453 for @table stats
	$query = "DBCC TRACEON(2453,-1)"
	sqlcmd -S ($DB_inst) -W -h -1 -v comp=$DB_inst -q $query
	exit
	if((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name SQLArg5 -ea 0).SQLArg5) {'Propertyalready exists'} ELSE { IF ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name SQLArg0 -ea 0).SQLArg0) {Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.$RegName\MSSQLServer\Parameters\" -Name "SQLArg5" -Value "-T2453"}}	} -ArgumentList $InstanceName
}

task DatabaseTweeks -requiredVariables server {	
	invoke-command -computername $server -scriptblock {	param($InstanceName)
	$comp = get-content env:computername
	$NullName = [string]::IsNullOrEmpty($InstanceName)
	if ($NullName)
	{$DB_inst = $comp}
	else
	{$DB_inst = $comp + "\"+ $InstanceName}
	
		#alter model to be simple, file growth of 1000MB and log growth of 8000MB
	$query = "use master
		GO
		alter database model
		set recovery simple
		go

		use model
		go

		alter database model
		modify file 
		(
			name = modeldev,
			filegrowth = 1000 MB
		)
		GO

		alter database model
		modify file
		(
			name = modellog,
			filegrowth = 8000 MB
		)
		GO"
	sqlcmd -S ($DB_inst) -W -h -1 -v comp=$DB_inst -q $query
	exit
	} -ArgumentList $InstanceName
}

task RestartServer -requiredVariables server {	
	invoke-command -computername $server -scriptblock {	Restart-Computer -Force}
	Start-Sleep -s 600
}

task CreateReplicationAlerts -requiredVariables server, scriptPath {	
	$query1 = [Io.File]::ReadAllText($scriptPath + "\ReplicationAlertCreation.sql")
	invoke-command -computername $server -scriptblock {	param($InstanceName, $server, $query1)
	$NullName = [string]::IsNullOrEmpty($InstanceName)
	if ($NullName)
	{$DB_inst = $server}
	else
	{$DB_inst = $server + "\"+ $InstanceName}
	sqlcmd -S ($DB_inst) -W -h -1 -v comp=$DB_inst -q $query1} -ArgumentList $InstanceName, $server, $query1
}

task InstallInternetExplorer -requiredVariables server {	
	#Supress network file warnings
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
	START-PROCESS "\\FileServer\IE11-Windows6.1.exe" -ArgumentList "/quiet", "/passive", "/norestart" -Wait
	#restartRequiredHere
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task InstallVisualStudio -requiredVariables server {	
	#Supress network file warnings
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
	#Add VS 2013
	START-PROCESS "\\FileServer\Visual_Studio_2013_Pro_Installer\vs_professional.exe" -ArgumentList "/quiet", "/passive", "/norestart" -Wait
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task SQL2012_SP2 -requiredVariables server {	
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
		#Add VS 2013
	START-PROCESS "\\FileServer\SP2\SQLServer2012SP2-KB2958429-x64-ENU.exe" -ArgumentList "/quiet", "/passive", "/norestart" -Wait
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task UnInstallVisualStudio -requiredVariables server {	
	invoke-command -computername $server -scriptblock {	$env:SEE_MASK_NOZONECHECKS = 1
		#Add VS 2013
	START-PROCESS "\\FileServer\Visual_Studio_2013_Pro_Installer\vs_professional.exe" -ArgumentList "/quiet", "/passive", "/norestart", "/Uninstall" -Wait
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}

task RestoreEssentialDatabase -requiredVariables server, scriptPath {	
	$query1 = [Io.File]::ReadAllText($scriptPath + "\EssentialDBRestore.sql")
	invoke-command -computername $server -scriptblock {	param($InstanceName, $server, $query1)
	$NullName = [string]::IsNullOrEmpty($InstanceName)
	if ($NullName)
	{$DB_inst = $server}
	else
	{$DB_inst = $server + "\"+ $InstanceName}
	sqlcmd -S ($DB_inst) -W -h -1 -v comp=$DB_inst -q $query1} -ArgumentList $InstanceName, $server, $query1
}

task SetupIIS -requiredVariables server {	
	invoke-command -computername $server -scriptblock {
	Import-Module ServerManager
	Add-WindowsFeature Web-Mgmt-Service
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1
	Set-Service -name WMSVC -StartupType Automatic
	Start-service WMSVC
	$env:SEE_MASK_NOZONECHECKS = 1
		#Run HotFix for Windows Server 2008 R2 SP1
	START-PROCESS "\\FileServer\IIS\Windows6.1-KB2545850-x64.msu" -ArgumentList "/quiet", "/passive", "/norestart" -Wait
	Remove-Item env:\SEE_MASK_NOZONECHECKS }
}
