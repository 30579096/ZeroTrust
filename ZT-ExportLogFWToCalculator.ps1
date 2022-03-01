###############################################################################
# @brief This script was designed by 1mm0rt41PC.
#        It harden automaticaly Server against many attacks
#        It enable the local firewall to avoid latteral movement.
# @author https://github.com/1mm0rt41PC
###############################################################################
# TEST ONLY
$REMOTE_database="$(pwd)\logs"
# In prod, store logs into a central log like:
#$REMOTE_database="\\log-storage.domain.lo)\logs$"



###############################################################################
###############################################################################
###############################################################################



$date_raw = Get-Date
$date = $date_raw.ToString('yyyy-MM-dd-HH-mm-ss')
mkdir -Force C:\Windows\Logs\ZeroTrust | Out-Null
if( $PSVersionTable.PSVersion.Major -ge 5 ){
	Start-Transcript -Force -IncludeInvocationHeader -Append ("C:\Windows\Logs\ZeroTrust\ZT-ExportLogFWToCalculator_"+(Get-Date -Format "yyyy-MM-dd")+".log")
}else{
	Start-Transcript -Force -Append ("C:\Windows\Logs\ZeroTrust\ZT-ExportLogFWToCalculator_"+(Get-Date -Format "yyyy-MM-dd")+".log")
}


###############################################################################
# Show pretty status
function head( $title )
{
	Write-Host -BackgroundColor Blue -ForegroundColor White "[*] $title"
}


###############################################################################
# Remove invalid or old rule
function FWRemoveBadRules
{
	head "Remove invalid or old rule"
	@(
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System',
		'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules'
	) | foreach {
		Write-Host ">    [*] Working on $_"
		$hive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($_ -Replace 'HKLM\:\\', ''), $true)
		if( $hive -eq $null ){
			continue
		}
		$hive.GetValueNames() | where {-not $hive.GetValue($_).Contains("[AutoHarden-$date]") -and -not $hive.GetValue($_).Contains("[AutoHarden]") } | foreach {
			$v = $hive.GetValue($_)
			Write-Host ">    [*] Delete $_ => $v"
			$hive.DeleteValue($_) | Out-Null
		}
	}
}


###############################################################################
# Get file content even with file lock
function getFile( [string] $pFilename )
{
	$tmp1 = cat -ErrorAction SilentlyContinue $pFilename
	if( [String]::IsNullOrWhiteSpace($tmp1) ){
		Write-Host ">    [!] log is empty !? Trying to copy the file to temp"
		$tmpMerge = ("{0}\system32\logfiles\firewall\ZeroTrust_{1}.merge" -f $env:windir, (-join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})))
		cp -Force $pFilename $tmpMerge | Out-Null
		$tmp1 = cat -ErrorAction SilentlyContinue $tmpMerge
		rm -Force $tmpMerge | Out-Null
		if( [String]::IsNullOrWhiteSpace($tmp1) ){
			throw "Empty"
		}
	}
	return $tmp1
}


###############################################################################
head "Forward firewall log"
###############################################################################
# Move logs
$rotateFile = "${REMOTE_database}\${env:COMPUTERNAME}_${date}_pfirewall.log"
$tmpMerge = ("{0}\system32\logfiles\firewall\ZeroTrust_{1}.merge" -f $env:windir, (-join ((65..90) + (97..122) | Get-Random -Count 12 | % {[char]$_})))
$wfLog = '';
$isFile = 0
@("pfirewall.log","pfirewall.log.old","ZeroTrust.staging") | foreach {
	$log = "${env:windir}\system32\logfiles\firewall\$_"
	Write-Host "[*] Reading $log"
	if( [System.IO.File]::Exists($log) ){
		$isFile += 1
		try {
			$wfLog += getFile $log
			Write-Host ">    [*] Data grabbed"
		}catch{
			Write-Host ">    [!] log is empty !? Trying to temporary disable the firewall"
			# Stop firewall
			netsh advfirewall set allprofiles state off | Out-Null
			try {
				$wfLog += getFile $log
			}catch{}
			Write-Host ">    [*] Data grabbed"
		}
		$wfLog += "`r`n"
		Write-Host ">    [*] Remove / Clear old log"
		try{
			echo '' | Out-File -ErrorAction SilentlyContinue -FilePath $log -Encoding ascii
		}catch{}
	}else{
		Write-Host ">    [!] File not found !"
	}
}
if( $isFile -gt 0 ){
	try{
		$wfLog | Out-File -FilePath $rotateFile -Encoding ASCII
	}catch{
		$wfLog | Out-File -Append -FilePath $env:windir\system32\logfiles\firewall\ZeroTrust.staging -Encoding ASCII
	}
}else{
	echo "Log are not enabled !!! logs doesn't exist" | Out-File -FilePath "${rotateFile}.LOG-NOT-ENABLED" -Encoding ASCII
}


###############################################################################
head "Set firewall"
try{
	$myPS1 = ("{0}\{1}.ps1"-f $REMOTE_database,$env:COMPUTERNAME)
	###############################################################################
	Write-Host -BackgroundColor DarkGreen "Checking if rules in $myPS1"
	if( [String]::IsNullOrWhiteSpace( (cat -ErrorAction SilentlyContinue $myPS1) ) ){
		throw "NO PS1"
	}
	
	Write-Host -BackgroundColor DarkGreen "[*] Running $myPS1"
	powershell -exec bypass -nop -File $myPS1
	
	Write-Host -BackgroundColor DarkGreen "[*] PS1 ended"
}catch{
	###############################################################################
	Write-Host -BackgroundColor DarkRed "[!] Unable to read/find FW rules"
	Write-Host -BackgroundColor DarkRed "[*] Wide open the firewall remote"
	# Restart firewall
	netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
	netsh advfirewall set allprofiles settings localfirewallrules enable | Out-Null
	netsh advfirewall set allprofiles settings localconsecrules enable | Out-Null
	netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
	netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
	mkdir -Force C:\Windows\system32\LogFiles\Firewall | Out-Null
	netsh advfirewall set allprofiles logging filename "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" | Out-Null
	netsh advfirewall set allprofiles logging maxfilesize 32767 | Out-Null
	netsh advfirewall set allprofiles state on | Out-Null

	FWRemoveBadRules
}
