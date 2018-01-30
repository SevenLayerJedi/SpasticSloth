
function Show-ObligatoryBanner
{
	$footerText = "Get Ready to Parse Some XML!"

# Don't move this as it will break if you tab it
$Head = @"

  __   __     __    __     ______     ______                                             
 /\ "-.\ \   /\ "-./  \   /\  __ \   /\  == \                                            
 \ \ \-.  \  \ \ \-./\ \  \ \  __ \  \ \  _-/                                            
  \ \_\\"\_\  \ \_\ \ \_\  \ \_\ \_\  \ \_\                                              
   \/_/ \/_/   \/_/  \/_/   \/_/\/_/   \/_/                                              
                                                                                         
  __  __     __    __     __         ______   ______     ______     ______     __        
 /\_\_\_\   /\ "-./  \   /\ \       /\__  _\ /\  __ \   /\  ___\   /\  __ \   /\ \       
 \/_/\_\/_  \ \ \-./\ \  \ \ \____  \/_/\ \/ \ \ \/\ \  \ \___  \  \ \ \/\_\  \ \ \____  
   /\_\/\_\  \ \_\ \ \_\  \ \_____\    \ \_\  \ \_____\  \/\_____\  \ \___\_\  \ \_____\ 
   \/_/\/_/   \/_/  \/_/   \/_____/     \/_/   \/_____/   \/_____/   \/___/_/   \/_____/  

"@

	# Print each line to the screen in random intervals
	$Head -split "`n" | %{Write-host "$_" -foregroundcolor green;sleep -milliseconds (Get-Random -min 50 -max 200)}

	# Print blank space
	Write-host " "

	# Create an array to print to the bottom 1 character at a time
	[ARRAY]$Array = "      $($footerText)"
	
	# Print each character to the screen at a random interval
	[regex]::split($Array,””) | %{Write-host "$_" -nonewline -foregroundcolor cyan;sleep -milliseconds $(Get-random -min 50 -max 200)}

	# Print blank space just because
	Write-host " "
	Write-host " "
}


function Get-SHA1Hash([String] $String) 
{
	$HashName = "SHA1"
	$StringBuilder = New-Object System.Text.StringBuilder 
	[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
	[Void]$StringBuilder.Append($_.ToString("x2")) 
	} 
	$StringBuilder.ToString() 
}


function Send-SQLQuery($SqlQuery)
{
	$SQLServer = "XXXXXXXXXXXXX"
	$SQLDBName = "Port_Scan"
	$SQLUName = "svc_xxxxx"
	$SQLPWord = "xxxxxxxxxxx"

	$SqlConnection = New-Object System.Data.SqlClient.SqlConnection
	$SqlConnection.ConnectionString = "Server=$SQLServer; Database=$SQLDBName; User ID=$SQLUName; Password=$SQLPWord;"
	#$SqlConnection.ConnectionString = "Server=$SQLServer;Database=$SQLDBName;Integrated Security=false"

	# Open SQL Socket
	$SqlConnection.Open()

	# Create NULL command object
	$SqlCmd = New-Object System.Data.SqlClient.SqlCommand

	# Add the Connection Settings
	$SqlCmd.Connection = $SqlConnection

	# Command to Send
	$SqlCmd.CommandText = $SqlQuery

	# Execute the SQL Command
	$SqlCmd.ExecuteNonQuery()

	# Clear out SqlCmd
	$SqlCmd.CommandText = $NULL

	# Close the SQL Connection
	$SqlConnection.Close()
}


function NMAP-XmlToSQL($DirectoryToWorkWith)
{
	# Show Obligatory Banner
	Show-ObligatoryBanner

	# Get the Date for all the INSERT's
	$dayScanned = Get-Date
	
	# Get list of all files in the dir
	$fileList = Get-ChildItem "$($DirectoryToWorkWith)"


	# Foreach loop to go through each file one by one
	foreach ($file in $fileList)
	{
		# Only select files with an extension that contains *.xml
		if ($($file.fullname) -like "*.xml")
		{
			# Parse xml file into an object
			$nmapXML = c:\nmap\scripts\nmap-parse.ps1 -Path "$($file.fullname)"
			
			# Foreach host in the nmap object do something
			foreach ($nmapHOST in $nmapXML)
			{
				# Initially each time we loop through each
				# host we will need to calculate an index number for each port
				# set it to 0 because we like 0 based arrays
				#$i = 0
			
				# Convert the ports into an arrays
				# Originally it's a one big ugly string 
				# let's split it on the carriage returns (horrible way to do this)
				# I forgot how to do it with getenumerator method which is still 
				# the wrong way to do it
				# Also... if there are no ports you have to add logic so it doesn't add
				# Weird info into the INSERT command. That is why the below IF is used
				if ($($nmapHOST.ports) -eq '<no-ports>')
				{
					# No ports found
					# Null out the variables each time to make sure they are all cleansed
					$nmapPortSingle = $NULL
					$nmapPortOpenClose = $NULL
					$nmapPortTcpUdp = $NULL
					$nmapPortNum = $NULL
					$nmapPortDesc = $NULL
					
					# Split up the string into indexed parts based off the colon (":")
					$nmapOS = $($($nmapHOST.OS) -split "`n")[0]
					
					if ($($nmapOS.Length) -lt 3)
					{
						$nmapOS = "$($nmapHOST.OS)"
					}
						
# Don't move this. It will break if you tab it!				
$SqlQuery = @"
INSERT INTO TBL_SCAN_HOSTS (HOSTNAME, FQDN, STATUS, IPV4, IPV6, MAC, PORTOPENCLOSE, PORTTCPUDP, PORTNUM, PORTDESCR, SERVICES, OS, DAYSCANNED, DATEADDED, SHA1HASH)
VALUES ('{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}', '{13}', '{14}', '{15}');
"@

					$SqlQuery = $SqlQuery.replace("{1}","$($nmapHOST.HostName)")
					$SqlQuery = $SqlQuery.replace("{2}","$($nmapHOST.FQDN)")
					$SqlQuery = $SqlQuery.replace("{3}","$($nmapHOST.Status)")
					$SqlQuery = $SqlQuery.replace("{4}","$($nmapHOST.IPv4)")
					$SqlQuery = $SqlQuery.replace("{5}","$($nmapHOST.IPv6)")
					$SqlQuery = $SqlQuery.replace("{6}","$($nmapHOST.MAC)")
					$SqlQuery = $SqlQuery.replace("{7}","<no-ports>")
					$SqlQuery = $SqlQuery.replace("{8}","<no-ports>")
					$SqlQuery = $SqlQuery.replace("{9}","<no-ports>")
					$SqlQuery = $SqlQuery.replace("{10}","<no-ports>")
					$SqlQuery = $SqlQuery.replace("{11}","$($nmapHOST.Services)")
					$SqlQuery = $SqlQuery.replace("{12}","$($nmapOS)")
					
					# Convert date to ticks
					$SqlQuery = $SqlQuery.replace("{13}","$($dayScanned)")
					
					# Convert date to ticks
					$SqlQuery = $SqlQuery.replace("{14}","$($(get-date).ticks)")
					
					# Big Fuckin String
					$bfs = $($nmapHOST.HostName) + $($nmapHOST.FQDN) + $($nmapHOST.Status) + $($nmapHOST.IPv4) + $($nmapHOST.IPv6) + $($nmapHOST.MAC) + $($nmapPortOpenClose) + $($nmapPortTcpUdp) + $($nmapPortNum) + $($nmapPortDesc) + $($nmapHOST.Services) + $($nmapOS)
					
					# Get the SHA1 Hash of the BFS
					$sha1Hash = Get-SHA1Hash $bfs
					$SqlQuery = $SqlQuery.replace("{15}","$($sha1Hash)")
					
					# Send the command to the SQL Server
					# The function will take care of the magic
					write-host " [" -nonewline -foregroundcolor white;write-host "+" -nonewline -foregroundcolor green;write-host "] " -nonewline -foregroundcolor white;Write-host "INSERTING into SQL DB: $($nmapHOST.IPv4)" -foregroundcolor green
					Send-SQLQuery $SqlQuery
				}
				ELSE
				{
					# Convert the ports into an arrays
					# Originally it's a one big ugly string 
					# let's split it on the carriage returns (horrible way to do this)
					# I forgot how to do it with getenumerator method which is still 
					# the wrong way to do it
					$portsArray = $($nmapHOST.ports) -split ("`n")
					
					# Foreach port in our host
					# We do it this way because every port gets a new line inserted into DB table
					# if 10.10.10.10 has 3 ports open it is inserted into the DB 3 seperate times
					foreach ($nmapPort in $portsArray)
					{
						# Null out the variables each time to make sure they are all cleansed
						$nmapPortSingle = $NULL
						$nmapPortOpenClose = $NULL
						$nmapPortTcpUdp = $NULL
						$nmapPortNum = $NULL
						$nmapPortDesc = $NULL		

						# This is where the index counter comes in
						# First time it will be 0
						#$nmapPortSingle = $($nmapHOST.Ports[$i])
						
						# Split up the string into indexed parts based off the colon (":")
						$nmapPortOpenClose = $($nmapPort -split ":")[0]
						$nmapPortTcpUdp = $($nmapPort -split ":")[1]
						$nmapPortNum = $($nmapPort -split ":")[2]
						$nmapPortDesc = $($nmapPort -split ":")[3]
						$nmapOS = $($($nmapHOST.OS) -split "`n")[0]
						
						if ($($nmapOS.Length) -lt 3)
						{
							$nmapOS = "$($nmapHOST.OS)"
						}
						
						# increment counter for next port index
						#$i++
						
						#"$($nmapHOST.HostName)"
						#"`t$($nmapHOST.FQDN)"
						#"`t$($nmapHOST.Status)"
						#"`t$($nmapHOST.IPv4)"
						#"`t$($nmapHOST.IPv6)"
						#"`t$($nmapHOST.MAC)"
						#"`t$($nmapPortOpenClose)"
						#"`t$($nmapPortTcpUdp)"
						#"`t$($nmapPortNum)"
						#"`t$($nmapPortDesc)"
						#"`t$($nmapHOST.Services)"
						#"`t$($nmapOS)"
						#"`t#################"

# Don't move this. It will break if you tab it!				
$SqlQuery = @"
INSERT INTO TBL_SCAN_HOSTS (HOSTNAME, FQDN, STATUS, IPV4, IPV6, MAC, PORTOPENCLOSE, PORTTCPUDP, PORTNUM, PORTDESCR, SERVICES, OS, DAYSCANNED, DATEADDED, SHA1HASH)
VALUES ('{1}', '{2}', '{3}', '{4}', '{5}', '{6}', '{7}', '{8}', '{9}', '{10}', '{11}', '{12}', '{13}', '{14}', '{15}');
"@

						$SqlQuery = $SqlQuery.replace("{1}","$($nmapHOST.HostName)")
						$SqlQuery = $SqlQuery.replace("{2}","$($nmapHOST.FQDN)")
						$SqlQuery = $SqlQuery.replace("{3}","$($nmapHOST.Status)")
						$SqlQuery = $SqlQuery.replace("{4}","$($nmapHOST.IPv4)")
						$SqlQuery = $SqlQuery.replace("{5}","$($nmapHOST.IPv6)")
						$SqlQuery = $SqlQuery.replace("{6}","$($nmapHOST.MAC)")
						$SqlQuery = $SqlQuery.replace("{7}","$($nmapPortOpenClose)")
						$SqlQuery = $SqlQuery.replace("{8}","$($nmapPortTcpUdp)")
						$SqlQuery = $SqlQuery.replace("{9}","$($nmapPortNum)")
						$SqlQuery = $SqlQuery.replace("{10}","$($nmapPortDesc)")
						$SqlQuery = $SqlQuery.replace("{11}","$($nmapHOST.Services)")
						$SqlQuery = $SqlQuery.replace("{12}","$($nmapOS)")

						# Convert date to ticks
						$SqlQuery = $SqlQuery.replace("{13}","$($dayScanned)")
						
						# Convert date to ticks
						$SqlQuery = $SqlQuery.replace("{14}","$($(get-date).ticks)")
						
						# Big Fuckin String
						$bfs = $($nmapHOST.HostName) + $($nmapHOST.FQDN) + $($nmapHOST.Status) + $($nmapHOST.IPv4) + $($nmapHOST.IPv6) + $($nmapHOST.MAC) + $($nmapPortOpenClose) + $($nmapPortTcpUdp) + $($nmapPortNum) + $($nmapPortDesc) + $($nmapHOST.Services) + $($nmapOS)
						
						# Get the SHA1 Hash of the BFS
						$sha1Hash = Get-SHA1Hash $bfs
						$SqlQuery = $SqlQuery.replace("{15}","$($sha1Hash)")
						
						# Send the command to the SQL Server
						# The function will take care of the magic
						write-host " [" -nonewline -foregroundcolor white;write-host "+" -nonewline -foregroundcolor green;write-host "] " -nonewline -foregroundcolor white;Write-host "INSERTING into SQL DB: $($nmapHOST.IPv4)" -foregroundcolor green
						Send-SQLQuery $SqlQuery
					}
				}
			}
		}
	}
}



# NMAP-XmlToSQL "C:\nmap\scans\20180119"





