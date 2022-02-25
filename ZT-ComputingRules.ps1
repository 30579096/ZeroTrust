###############################################################################
# @brief This script was designed by 1mm0rt41PC.
#        It harden automaticaly Server against many attacks
#        It enable the local firewall to avoid latteral movement.
# @author https://github.com/1mm0rt41PC
###############################################################################
$DB_database      = "$(pwd)\data"
$DB_debugLogs     = "$(pwd)\logs"
$LEARNING_days    = 30
$AUTOCLOSE_PORT   = 30 # Auto close ports after no usage of xxx days
$RPC_MAPPER       = @(135,593)
$RPC_PORTS        = @(49152,65535)
$LOG_MAX_SIZE     = 500 # Log size for this script activity (value in MB)

$IP_ROLE = @{
	# List of admin IP allowed to administrate DC
	IP_ADMIN=@(
		'10.1.30.0/24',
		'10.250.250.1',
		'192.168.1.0-192.168.1.20'
	);
	IP_USERS=@(
		'10.1.2.0/24', # Ethernet
		'10.1.1.0/24', # Ethernet
		'10.1.4.0/24'  # Wifi
	);
	# IP in this block will be ignored, no rules will be created for them.
	# So if these IP make connection on a server, the remote server will not make a rule for them.
	LOOPBACK=@(
		'6.6.6.6'
	);

	# You can make group here like:
	MY_GROUP=@(
		'1.2.3.4',
		'1.2.3.5'
	);
	MY_DATABASE=@(
		'4.5.6.7',
		'4.5.6.8'
	);
}


###############################################################################
###############################################################################
###############################################################################


$date_raw = Get-Date
$raw_LEARNING_days = $date_raw.AddDays($LEARNING_days)
$date = $date_raw.ToString('yyyy-MM-dd-HH-mm-ss')


###############################################################################
# Show pretty status
function head( $title )
{
	Write-Host -BackgroundColor Blue -ForegroundColor White "[*] $title"
}


###############################################################################
# Coverter list of ip notation to IP list
# @example Cidr2List @('10.0.0.0/24','10.1.1.1-10.1.1.50')
# will return
# 10.0.0.0
# 10.0.0.1
# 10.0.0.2
# ...
# 10.0.0.255
# 10.1.1.1
# 10.1.1.2
# 10.1.1.3
# ...
# 10.1.1.50
#
Function Cidr2List
{
	Param ( $IP )
	$IP | foreach {
		$_ = $_ -replace ' ', ''
		if( $_.contains('/') ){
			$tmp=$_.split('/')
			Get-SubnetAddresses $tmp[0] $tmp[1] | foreach { Get-IPRange $_.Lower $_.Upper }
		}elseif( $_.contains('-') ){
			$tmp=$_.split('-')
			Get-IPRange $tmp[0] $tmp[1]
		}else{
			[IPAddress] $_
		}
	} | foreach {
		$_.IPAddressToString
	}
}
###############################################################################
# Converter ip notation cidr to list
# @example
# Get-SubnetAddresses 10.0.0.0 24
# will return
# 10.0.0.0
# 10.0.0.1
# 10.0.0.2
# ...
# 10.0.0.255
#
Function Get-SubnetAddresses
{
Param ([IPAddress]$IP,[ValidateRange(0, 32)][int]$maskbits)

	# Convert the mask to type [IPAddress]:
	$mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
	$maskbytes = [BitConverter]::GetBytes([UInt32] $mask)
	$DottedMask = [IPAddress]((3..0 | ForEach-Object { [String] $maskbytes[$_] }) -join '.')

	# bitwise AND them together, and you've got the subnet ID
	$lower = [IPAddress] ( $ip.Address -band $DottedMask.Address )

	# We can do a similar operation for the broadcast address
	# subnet mask bytes need to be inverted and reversed before adding
	$LowerBytes = [BitConverter]::GetBytes([UInt32] $lower.Address)
	[IPAddress]$upper = (0..3 | %{$LowerBytes[$_] + ($maskbytes[(3-$_)] -bxor 255)}) -join '.'

	# Make an object for use elsewhere
	if( $PSVersionTable.PSVersion.Major -ge 5 ){
		Return [pscustomobject][ordered]@{
			Lower=$lower
			Upper=$upper
		}
	}
	Return [pscustomobject]@{
		Lower=$lower
		Upper=$upper
	}
}
###############################################################################
# Converter ip notation to list
# @example
# Get-IPRange 10.1.1.1 10.1.1.50
# will return
# 10.1.1.1
# 10.1.1.2
# 10.1.1.3
# ...
# 10.1.1.50
#
Function Get-IPRange
{
Param (
	[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][IPAddress]$lower,
	[Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)][IPAddress]$upper
)
	# use lists for speed
	$IPList = @($lower)
	$i=$lower
	# increment ip until reaching $upper in range
	while ( $i -ne $upper ) {
		# IP octet values are built back-to-front, so reverse the octet order
		$iBytes = [BitConverter]::GetBytes([UInt32] $i.Address)
		[Array]::Reverse($iBytes)
		# Then we can +1 the int value and reverse again
		$nextBytes = [BitConverter]::GetBytes([UInt32]([bitconverter]::ToUInt32($iBytes,0) +1))
		[Array]::Reverse($nextBytes)
		# Convert to IP and add to list
		$i = [IPAddress]$nextBytes
		$IPList += @($i)
	}
	return $IPList
}
###############################################################################
# Replace $IP_cidr by $name into $replaceIn
# @example
# $data = @'
# TCP,10.0.0.1,3389
# TCP,10.0.0.1,445
# TCP,10.0.0.2,3389
# TCP,10.0.0.2,445
# TCP,10.0.1.1,3389
# TCP,10.0.1.1,445
# '@
# $ip = '10.0.0.0/24'
# replaceIP ([ref]$data) ([ref]$ip) 'USERS'
# Write-Host $data
#    TCP,USERS,3389
#    TCP,USERS,445
#    TCP,USERS,3389
#    TCP,USERS,445
#    TCP,10.0.1.1,3389
#    TCP,10.0.1.1,445
function replaceIP
{
Param(
	[ref] $replaceIn,
	[ref] $IP_cidr,
	[string] $name
)
	$tpl_rx = [System.Text.StringBuilder]',('
	$IP_cidr.value | & { process
		{
			if( $_.contains('.0/24') ){
				$null=$tpl_rx.Append(($_ -replace '0/24', '[0-9]+')+'|')
			}elseif( $_.contains('.0.0/16') ){
				$null=$tpl_rx.Append(($_ -replace '0.0/16', '[0-9]+.[0-9]+')+'|')
			}elseif( $_.contains('-') -or $_.contains('/') ){
				Cidr2List $_ | foreach {
					$null=$tpl_rx.Append("$_|")
				}
			}else{
				$null=$tpl_rx.Append("$_|")
			}
		}
	}
	$tpl_rx = ($tpl_rx.ToString() -replace '\.', '\.').trim('|')+'),'
	$replaceIn.value = [System.Text.RegularExpressions.Regex]::Replace($replaceIn.value, $tpl_rx, ",$name,", [System.Text.RegularExpressions.RegexOptions]::Compiled)
	[System.GC]::Collect()
}


###############################################################################
# FW creation / update
function FWRule( $param, [ref] $buff )
{
	$param['DisplayName'] = "[AutoHarden-$date] "+$param['Name'];
	$param.remove('Name') | Out-Null
	if( $param['RemoteAddress'] -eq '0.0.0.0' ){
		$param.remove('RemoteAddress') | Out-Null
	}

	$buff.value.AppendLine('$rule=@{') | Out-Null
	$param.Keys | foreach {
		$k = $_
		$v = $param[$k].Replace('"','');
		if( $v -is [array] ){
			$buff.value.AppendLine("    $k = @(");
			$buff.value.AppendLine(($v | ConvertTo-Json).Replace('[', '').Replace(']',''));
			$buff.value.AppendLine("    );");
		}else{
			$buff.value.AppendLine("    $k = `"$v`";");
		}
	} | Out-Null
	$buff.value.AppendLine('}') | Out-Null
	$buff.value.AppendLine("New-NetFirewallRule -Enabled True -Profile Any @rule -ErrorAction Continue | Out-Null`r`n") | Out-Null
}


###############################################################################
# Convert raw firewall logs into
# TCP,42.42.42.42,3389
# UDP,42.42.42.42,123
# TCP,42.42.42.42,445
# TCP,42.42.42.42,135
#
# and fill $lo with loopback addr
# and fill $LEARNING_cache
# and fill $lastLog
function ConvertFlatLog( [string]$data, [System.Collections.Generic.HashSet[String]]$lo, [System.Collections.Hashtable]$LEARNING_cache, [ref]$lastLog )
{
	Write-Debug '>    [d] Catch only required data to make a stringlist <PROTO,IP,PORT>\n'
	$m = [System.Text.RegularExpressions.Regex]::Matches($data, '([0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9+]+) ALLOW (TCP|UDP) ([0-9\.]+) ([0-9\.]+) [0-9]+ ([0-9]+) [^\r\n]+RECEIVE[\r\n]*', [System.Text.RegularExpressions.RegexOptions]::Compiled)
	# https://powershell.one/tricks/performance/strings
	$text = [System.Text.StringBuilder]""

	$m | & { process
		{
			$null = $lo.Add($_.Groups.Value[4])
			$logTimestamp = [int64]($_.Groups.Value[1].Replace('-','').replace(':','').replace(' ',''))
			if( $logTimestamp -ge $LEARNING_cache['Last log'] ){
				$null = $text.AppendLine($_.Groups.Value[2]+','+$_.Groups.Value[3]+','+$_.Groups.Value[5])
				if( $logTimestamp -gt $lastLog.value ){
					$lastLog.value = $logTimestamp
				}
			}
		}
	}
	return $text.ToString()
}


###############################################################################
# Replace all IP with named range
function ReplaceIPWithNamedRange( [ref]$data, $lo=$null )
{
	Write-Host '>    [d] Replace all IP with range name'
	$IP_ROLE.Keys | foreach {
		replaceIP $data ([ref]$IP_ROLE[$_]) $_
	}
	if( $lo -ne $null ){
		replaceIP $data ([ref]$lo) 'LOOPBACK'
	}
}


###############################################################################
# Remove all duplicate lines
function RemoveDuplicate( [ref]$data )
{
	Write-Host '>    [d] Remove duplicate entry'
	$d = $data.Value.split("`r`n", [System.StringSplitOptions]::RemoveEmptyEntries)
	$uniq = @{}
	$d | & { process
		{
			# TCP,10.1.1.140,49678
			$row = $_.split(',')
			$port = [int]$row[2]
			if( -not $_.contains('IP_ADMIN') -and -not $_.contains('LOOPBACK') -and -not ($RPC_PORTS[0] -le $port -and $port -le $RPC_PORTS[1]) ){
				$uniq[$_]=$true
			}
		}
	}
	$data.Value=$uniq.Keys -Join "`r`n"
}


###############################################################################
# Remove individual ports if used by USER range
function OpenPortIfUsersUseIt( [ref]$data )
{
	Write-Host '>    [d] If a port is open for users => open this ports for everybody'
	$m = [System.Text.RegularExpressions.Regex]::Matches($data.Value, '(TCP|UDP),IP_USERS,([0-9]+)', [System.Text.RegularExpressions.RegexOptions]::Compiled)
	$m | foreach {
		$proto=$_.Groups.Value[1]
		$port=$_.Groups.Value[2]
		$data.Value=[Regex]::new("$proto,([^,]+),$port[\r\n]+", [System.Text.RegularExpressions.RegexOptions]::Compiled).Replace($data.Value,'')
	}
	$data.Value += "`r`n"
	$data.Value += ($m | foreach { $_.Value }) -join "`r`n"
}



###############################################################################
###############################################################################
###############################################################################
# MAIN
###############################################################################
###############################################################################
###############################################################################

head "Reading logs in $DB_database"

# Get list of hosts
$hosts = Get-ChildItem $DB_database -Recurse -Force -include @("*_pfirewall.log","*.xml") | foreach { (($_.name -Split '_20')[0]).Replace('.xml','') } | Sort -u
$hosts | foreach {
	$myHost = $_
	Start-Transcript -Force -IncludeInvocationHeader -Append ("${DB_debugLogs}\ZT-ComputingRules-${myHost}_${date}.log")
	head "Reading logs for $myHost"
	$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

	$LEARNING_file = "${DB_database}\${myHost}.xml"
	$SCRIPT_file = "${DB_database}\${myHost}.ps1"
	$LEARNING_cache = @{}
	if( [System.IO.File]::Exists($LEARNING_file) ){
		Write-Host ">    [d] Reading ZeroTrust DB !"
		$LEARNING_cache = Import-CliXML $LEARNING_file
		if( $LEARNING_cache -eq $null ){
			$LEARNING_cache = @{}
		}
	}
	if( $LEARNING_cache['Apply ZT'] -eq $null ){
		$LEARNING_cache['Apply ZT'] = $raw_LEARNING_days;
	}
	if( $LEARNING_cache['Last log'] -eq $null ){
		$LEARNING_cache['Last log'] = [int64] 0;
	}


	Get-ChildItem ${DB_database}\${myHost}*_pfirewall.log | foreach {
		$name = $_.Name
		Write-Host -BackgroundColor Blue -ForegroundColor White ">    [*] Parsing $name"
		$d = [IO.File]::ReadAllText($_.FullName)
		[int64] $lastLog = $LEARNING_cache['Last log']
		[System.Collections.Generic.HashSet[String]] $lo = @()

		$d = ConvertFlatLog -data $d -lo $lo -LEARNING_cache $LEARNING_cache -lastLog ([ref]$lastLog)
		# Update the last log to avoid to reuse old data
		$LEARNING_cache['Last log'] = $lastLog;
		if( [String]::IsNullOrWhiteSpace($d) ){
			Write-Host '>    [d] No new data'
			rm -Force $_.FullName | Out-Null
			return ;
		}

		###############################################################################
		ReplaceIPWithNamedRange -data ([ref]$d) -lo $lo -LEARNING_cache $LEARNING_cache

		###############################################################################
		RemoveDuplicate -data ([ref]$d)

		###############################################################################
		OpenPortIfUsersUseIt -data ([ref]$d)

		###############################################################################
		Write-Host '>    [d] Split data by lines and keep only uniq lines'
		$d = $d.replace("`r",'').split(([string[]]@("`n")), [System.StringSplitOptions]::RemoveEmptyEntries) | sort -uniq

		###############################################################################
		Write-Host '>    [d] Update $LEARNING_cache with fresh data'
		$expire = $date_raw.AddDays($AUTOCLOSE_PORT)# Wait $LEARNING_days before closing a port
		if( -not [string]::IsNullOrEmpty($d) ){
			$d | foreach {
				$_ = $_.Trim()
				if( $_ -ne '' ){
					$LEARNING_cache[$_] = $expire
				}
			}
		}
		$d=$null
		rm -Force $_.FullName | Out-Null
	}# END Get-ChildItem


	###############################################################################
	Write-Host '>    [d] Cleaning LEARNING_cache'
	$d = $LEARNING_cache.Keys -Join "`r`n"
	ReplaceIPWithNamedRange -data ([ref]$d)


	###############################################################################
	Write-Host '>    [d] Remove duplicate entry in LEARNING_cache'
	RemoveDuplicate -data ([ref]$d)
	$expire = $date_raw.AddDays($AUTOCLOSE_PORT)# Wait $LEARNING_days before closing a port
	$LEARNING_cache_new=@{}
	$d.split("`r`n", [System.StringSplitOptions]::RemoveEmptyEntries) | foreach {
		if( $LEARNING_cache.Contains($_) ){
			$LEARNING_cache_new[$_] = $LEARNING_cache[$_]
		}else{
			$LEARNING_cache_new[$_] = $expire
		}
	}
	$LEARNING_cache = $LEARNING_cache_new


	###############################################################################
	Write-Host '>    [d] Remove old entry from $LEARNING_cache'
	($LEARNING_cache.Keys + @()) | foreach {
		if( $_ -ne 'Apply ZT' -and $_ -ne 'Last log' -and $LEARNING_cache[$_] -lt $date_raw ){
			Write-Host -BackgroundColor DarkRed ">    [-] $_ hasn't been used since $AUTOCLOSE_PORT days => closing port"
			$LEARNING_cache.Remove($_) | Out-Null
		}
	}

	###############################################################################
	Write-Host '>    [d] Save the learning cache'
	if( [System.IO.File]::Exists($LEARNING_file) ){
		mv -Force $LEARNING_file "${LEARNING_file}.old" | Out-Null
	}
	$LEARNING_cache | Export-CliXML -Path $LEARNING_file -NoClobber -Encoding 'ASCII' -Force

	[System.GC]::Collect()
	Write-Host ('>    [d] ZT cache updated in {0:n1} seconds' -f $stopwatch.Elapsed.TotalSeconds)
	$stopwatch = $null


	###############################################################################
	Write-Host ('>    [d] ZT will be applyed after '+$LEARNING_cache['Apply ZT'])
	if( $LEARNING_cache['Apply ZT'] -lt $date_raw ){
		Write-Host -BackgroundColor DarkGreen '>    [d] ZT is enabled ! Create rules'

		$buff = [System.Text.StringBuilder]""
		$buff.AppendLine(@"
###############################################################################
# @brief This script was designed by 1mm0rt41PC.
#        It harden automaticaly Server against many attacks
#        It enable the local firewall to avoid latteral movement.
# @author https://github.com/1mm0rt41PC
###############################################################################
# @warning THIS SCRIPT IS AUTOGENERATED ! ALL CHANGE WILL BE REMOVED
# @date $date
###############################################################################
# Computed rules:
"@) | Out-Null
		$buff.AppendLine('# '+(($LEARNING_cache.Keys | where {$_ -ne 'Apply ZT' -and $_ -ne 'Last log'})-join "`r`n# ").replace(',135',',RPC & RPC-MAPPER')) | Out-Null
		$buff.AppendLine('') | Out-Null

		###############################################################################
		Write-Host '>    [d] Create basic firewall rules'
		FWRule @{
			Action='Allow'; Direction='Inbound'; Name='ADMIN-ACCESS';
			Group='ADMIN-ACCESS';
			RemoteAddress=$IP_ROLE['IP_ADMIN'];
		} ([ref]$buff)

		# Ajout des nouvelles rules
		$LEARNING_cache.Keys | where { $_ -ne 'Apply ZT' -and $_ -ne 'Last log' } | foreach {
			$proto,$ip,$port = $_.split(',')
			if( $ip.StartsWith('IP_') ){
				$ip = switch($ip){
					'IP_USERS' {'0.0.0.0'; break;}
					default {$IP_ROLE[$ip]; break;}
				}
			}

			Write-Host ">        [r] Create rule for $_"
			if( $port -eq 135 ){
				FWRule @{
					Name=("[ZT] Allow "+$_.replace(',135',',RPC'));
					Action='Allow';
					Direction='Inbound';
					Protocol=$proto;
					Group='AutoHarden-ZeroTrust';
					LocalPort='RPC';
					RemoteAddress=$ip;
				} ([ref]$buff)
				$port = 'RPCEPMAP'
				$_=$_.replace(',135',',RPCEPMAP')
			}
			FWRule @{
				Name="[ZT] Allow $_";
				Action='Allow';
				Direction='Inbound';
				Protocol=$proto;
				Group='AutoHarden-ZeroTrust';
				LocalPort=$port;
				RemoteAddress=$ip;
			} ([ref]$buff)
		}
	$buff.AppendLine((@'
mkdir $env:windir\system32\logfiles\firewall -Force | Out-Null
Write-Host -BackgroundColor DarkGreen "[*] Enable WF with strict mode"
Set-NetFirewallProfile -All -Enabled True -NotifyOnListen False -DefaultOutboundAction Allow -DefaultInboundAction Block -AllowInboundRules True -AllowLocalFirewallRules True -AllowLocalIPsecRules True -AllowUnicastResponseToMulticast True -LogAllowed True -LogBlocked True -LogIgnored True -LogFileName "%windir%\system32\logfiles\firewall\pfirewall.log" -LogMaxSizeKilobytes 32767
Write-Host -BackgroundColor Blue -ForegroundColor White "[*] Remove invalid or old rule"
@(
	'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules',
	'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System',
	'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules'
) | foreach {
	Write-Host ('>    [d] Working on {0}' -f $_) ;
	$hive = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($_ -Replace 'HKLM\:\\', ''), $true);
	if( $hive -eq $null ){
		continue;
	} ;
	$hive.GetValueNames() | where {
		-not $hive.GetValue($_).Contains('[AutoHarden]') -and
		-not $hive.GetValue($_).Contains('[AutoHarden-%date%]')
	} | foreach {
		$v = $hive.GetValue($_) ;
		Write-Host ('>    [d] Delete {0} => {1}' -f $_,$v)
		$hive.DeleteValue($_) | Out-Null
	} ;
}
'@).replace('%date%',$date)) | Out-Null
		$buff.ToString() | Out-File -Encoding ASCII -Force -File $SCRIPT_file
		# https://blog.netwrix.com/2018/04/18/how-to-manage-file-system-acls-with-powershell-scripts/
		$acl = Get-Acl $SCRIPT_file
		$fsar = New-Object System.Security.AccessControl.FileSystemAccessRule(('{0}\{1}$' -f $env:USERDOMAIN,$myHost), 'ReadAndExecute', 'Allow')
		$acl.SetAccessRule($fsar)
		$acl | Set-Acl $SCRIPT_file
	}else{
		Write-Host -BackgroundColor DarkCyan '>    [d] ZT is in learning mode'
	}
	Stop-Transcript
}


echo "####################################################################################################"
head "Logs: Remove old logs if missing space"
echo "####################################################################################################"
if( $env:AUTOHARDEN_LOG_MAX_SIZE -ne $null -and [int]::TryParse($env:AUTOHARDEN_LOG_MAX_SIZE,[ref]$null) ){
	$LOG_MAX_SIZE = $env:AUTOHARDEN_LOG_MAX_SIZE
}
while( ((Get-ChildItem $DB_debugLogs | Measure-Object -Property Length -Sum -ErrorAction Stop).Sum / 1MB) -gt $LOG_MAX_SIZE )
{
	$log = Get-ChildItem $DB_debugLogs | Sort CreationTime
	if( $log.Count ){
		$log = $log[0]
	}
	Write-Host "[*] Too many logs, removing old log $log"
	$log | Remove-Item -Force | Out-Null
}