####################################################################################
#.Synopsis 
#    Scans subnets with NMAP and outputs XML files 
#
#.Description 
#    Runs multiple NMAP instances at the same time. This expedites scan times  
#    by 10x by default. No scientitfic testing has been completed to verify that
#    statistic. Changing the maxthread variable will change how fast the scans
#    run. Don't make maxthread larger than 64.
#
#.Example 
#    .\Prepare-ToBeScanned.ps1
#
#Requires -Version 2 
#
#.Notes 
#  Author: Keith Smith (https://www.keithsmithonline.com)  
# Version: 1.0
# Updated: 25.Jan.2018
#   LEGAL: PUBLIC DOMAIN.  SCRIPT PROVIDED "AS IS" WITH NO WARRANTIES OR GUARANTEES OF 
#          ANY KIND, INCLUDING BUT NOT LIMITED TO MERCHANTABILITY AND/OR FITNESS FOR
#          A PARTICULAR PURPOSE.  ALL RISKS OF DAMAGE REMAINS WITH THE USER, EVEN IF
#          THE AUTHOR, SUPPLIER OR DISTRIBUTOR HAS BEEN ADVISED OF THE POSSIBILITY OF
#          ANY SUCH DAMAGE.  IF YOUR STATE DOES NOT PERMIT THE COMPLETE LIMITATION OF
#          LIABILITY, THEN DELETE THIS FILE SINCE YOU ARE NOW PROHIBITED TO HAVE IT.
####################################################################################


#######################################
# .variables                          #
#######################################

# Remember to put a trailing "\" in the paths
# I haven't added logic (regex) for that yet
$scanPath = "C:\nmap\scans\"
$LogPath = "C:\nmap\logs\"
$subnetConfig = "C:\nmap\config\subnets.config"
$bannerPath = "c:\nmap\banner\PrepareToBeScanned\"

# Multiplexing Option set to 10
# When set to 10 it bumps CPU up to 60%
# on quadcore
$maxThreads = 24
$subnetResults = @()
$jobs = @()

# Start stopwatch
# This is to keep track of how long things are running
$sw = [system.diagnostics.stopwatch]::startNew()


#######################################
# .functions                          #
#######################################


function Show-ObligatoryBanner($param)
{
	$footerText = "Prepare To Be Scanned!"
	$minHeaderSleep = "50"
	$maxHeaderSleep = "200"
	$minFooterSleep = "50"
	$maxFooterSleep = "200"	
	
	# Path to banners
	# All banners need to have .txt extension
	$bannerPath = $($param)

	# Get list of all files in the dir
	$bannerList = Get-ChildItem "$($bannerPath)"

	# Randomly select one of the banners
	$objBanner = $bannerList | ?{$_.Name -like "*.txt"} | get-random

	# Get the contents and put it into an object
	$objBannerContents = Get-Content "$($objBanner.fullname)"
	
	# Print each line to the screen in random intervals
	$objBannerContents | %{Write-host "$_" -foregroundcolor green;sleep -milliseconds (Get-Random -min $($minHeaderSleep) -max $($maxHeaderSleep))}

	# Print blank space
	Write-host " "

	# Create an array to print to the bottom 1 character at a time
	[ARRAY]$Array = "      $($footerText)"
	
	# Print each character to the screen at a random interval
	[regex]::split($Array,””) | %{Write-host "$_" -nonewline -foregroundcolor cyan;sleep -milliseconds $(Get-random -min $($minFooterSleep) -max $($maxFooterSleep))}

	# Print blank space just because
	Write-host " "
	Write-host " "
}


function Create-LogFile($logPath)
{
	$TheDate = get-date -f yyyyMMdd
	"[START] $($Expression)" | out-file "$($logPath)$($TheDate).log" -append
}

function Split-array 
{
<#  
  .SYNOPSIS   
    Split an array
  .NOTES
    Version : July 2, 2017 - implemented suggestions from ShadowSHarmon for performance   
  .PARAMETER inArray
   A one dimensional array you want to split
  .EXAMPLE  
   Split-array -inArray @(1,2,3,4,5,6,7,8,9,10) -parts 3
  .EXAMPLE  
   Split-array -inArray @(1,2,3,4,5,6,7,8,9,10) -size 3
#> 

	param($inArray,[int]$parts,[int]$size)

	# Split Array Function taken from
	# https://gallery.technet.microsoft.com/scriptcenter/Split-an-array-into-parts-4357dcc1
	
	if ($parts) {
	$PartSize = [Math]::Ceiling($inArray.count / $parts)
	} 
	if ($size) {
	$PartSize = $size
	$parts = [Math]::Ceiling($inArray.count / $size)
	}

	$outArray = New-Object 'System.Collections.Generic.List[psobject]'

	for ($i=1; $i -le $parts; $i++) {
	$start = (($i-1)*$PartSize)
	$end = (($i)*$PartSize) - 1
	if ($end -ge $inArray.count) {$end = $inArray.count -1}
	$outArray.Add(@($inArray[$start..$end]))
	}
	return ,$outArray

}

### START OF SCRIPTBLOCK ###
# ScriptBlock to execute asynchronously
# This is what we are "multiplexing"
$ProcessTarget = {
        param(
		$subnet,
		$scanPath,
		$logPath
		)
        
		function Get-DateForFiles($scanPath)
		{
			#######################################
			# .variables                          #
			#######################################

			# See if the date folder exists
			# If not create it
			If(!(test-path $scanPath))
			{
				write-host " [" -nonewline -foregroundcolor white;write-host "-" -nonewline -foregroundcolor yellow;write-host "] " -nonewline -foregroundcolor white;Write-host "Creating Directory: $($scanPath)" -foregroundcolor green

				New-Item -ItemType Directory -Force -Path $scanPath | out-null
				sleep -seconds 2
			}
			Return [string]$TheDate.ToString()
		}

		
        function scanSubnet($subnet, $scanPath, $logPath)
        {
			#######################################
			# .variables                          #
			#######################################
			
            # Set result to false
			$result = $false
			
			# Get the simple date and use it over and over
			# This is so we can go back and see the amount of 
			# a certain port opened for a specific day
			$TheDate = get-date -f yyyyMMdd
						
			# Add the DATE as a folder to the scanpath 
			$scanPath = $scanPath + [string]$TheDate.ToString()
						
			# Format the IP and Subnet into CIDR notation for nmap
			$IPSubnet = $($subnet.IP) + "/" + $($subnet.SUBNET)
			
			# Format the name of the XML file
			# E.X "10.10.10.0_24.xml"
			$xmlFile = $($subnet.IP) + "_" + $($subnet.SUBNET) + ".xml"
			
			# Set the Expression that we want to run
			# E.X. "nmap -O -T4 -oX c:\nmap\scans\20180125\10.10.10.0_24.xml 10.10.10.0/24"
			$Expression = "nmap -O -T4 -oX c:\nmap\scans\$(Get-DateForFiles $scanPath)\$($xmlFile) $($IPSubnet)"

			
			#######################################
			# .main                               #
			#######################################
						
			# Check to see if the folder for the xml file exists
			# If not, create the folder
			If(!(test-path $ScanPath))
			{
				# Print "Creating Directory" message
				write-host " [" -nonewline -foregroundcolor white;write-host "-" -nonewline -foregroundcolor yellow;write-host "] " -nonewline -foregroundcolor white;Write-host "Creating Directory: $($ScanPath)" -foregroundcolor green
				
				# Create new folder
				New-Item -ItemType Directory -Force -Path $ScanPath | out-null
				
				# Dont need this, but just in case...
				sleep -seconds 2
			}
			
            try {
                # Attempt running NMAP
                invoke-expression $Expression | Out-Null
				"[TRY] $($Expression)" | out-file "$($logPath)$($TheDate).log" -append
				$result = $true
            }
            
            catch {
                # If Some kind of error occurs
				"[CATCH] $($Expression)" | out-file "c:\nmap\logs\$($TheDate).log" -append
                $result = $false
            }

            finally {
                # Cleanup
                #"CLEANUP $($Expression)" | out-file "c:\nmap\scans\scanSubnet.log" -append
            }
        }
		# Execute the Function
        scanSubnet $subnet $scanPath
}
### END OF SCRIPTBLOCK ###

# Put an "START" entry
Create-LogFile $logPath

# Show Obligatory Banner
Show-ObligatoryBanner "$($bannerPath)"

# Import all the subnets into an object called objCSV
$objCSV = Import-Csv $SubnetConfig

# Randomize the Subnet list so we aren't pounding the same plant
# over and over again
$ShuffledSubnetList = $objCSV | Sort-Object {Get-Random}

# Split list up into equal parts of 100 subnets
$objSubnets = Split-array -inArray $ShuffledSubnetList -size 100

# Var for total subnet count
[int]$TotalSubnetCount = $objCSV.count

# create a pool of maxThread runspaces   
$pool = [runspacefactory]::CreateRunspacePool(1, $maxThreads)   
$pool.Open()

# Create blank arrays
$jobs = @()   
$ps = @()   
$wait = @()

# Create Counter for job index
$i = 0

# Create Counter to send out an update every so often
$t = 0

# ObjSubnets is indexed because it is randomized and broken into sections
# Its a cool idea, but not sure if it brings any benefit at all
# I was going to originally break up the sections and input them into
# config files that I would then scan 1 by 1 so its not an all or nothing thing
foreach ($section in $objSubnets)
{
	# Fancy way to get current index
	# This should be used for the jobs too, but am too lazy to do it right now
	$CurrentIndex = [array]::IndexOf($objSubnets, $section)
	
	# Have to do it this way because of indexing
	foreach ($objIP in $objSubnets[$CurrentIndex])
	{
		# While loop to check for available Runspaces
		while ($($pool.GetAvailableRunspaces()) -le 0) {
        Start-Sleep -milliseconds 500
		}
		
		# Creates a "powershell pipeline runner"
		# https://blogs.technet.microsoft.com/heyscriptingguy/2015/11/26/beginning-use-of-powershell-runspaces-part-1/
		$ps += [powershell]::create()

		# Assign our pool of runspaces to use   
		$ps[$i].runspacepool = $pool

		# Commands to run
		[void]$ps[$i].AddScript($processTarget)
		[void]$ps[$i].AddParameter("subnet", $objIP)
		[void]$ps[$i].AddParameter("scanPath", $scanPath)
		[void]$ps[$i].AddParameter("logPath", $logPath)
		
		# Start job
		$jobs += $ps[$i].BeginInvoke();
		 
		# Store wait handles for WaitForAll call   
		$wait += $jobs[$i].AsyncWaitHandle
		
		# Increment counter for the jobs
		$i++

		# Print "[+] Scanning: x.x.x.x/x"
		write-host " [" -nonewline -foregroundcolor white;write-host "+" -nonewline -foregroundcolor green;write-host "] " -nonewline -foregroundcolor white;Write-host "Scanning: $($objIP.IP)/$($objIP.Subnet)" -foregroundcolor cyan

		# Increment t by 1
		$t++
		
		if ($t -gt 25)
		{
			# Print "Percent Complete:"
			write-host " [" -nonewline -foregroundcolor white;write-host "-" -nonewline -foregroundcolor yellow;write-host "] " -nonewline -foregroundcolor white;Write-host "Percent Complete: $($TotalPercentComplete)" -foregroundcolor green
			
			# Print "Total Time Spent Scanning:"
			write-host " [" -nonewline -foregroundcolor white;write-host "-" -nonewline -foregroundcolor yellow;write-host "] " -nonewline -foregroundcolor white;Write-host "Total Time Spent Scanning: $($swFullTime.Elapsed.Hours):$($swFullTime.Elapsed.Minutes):$($swFullTime.Elapsed.Seconds)" -foregroundcolor green
			
			$t = 0

		}
	}
}

# Print "Waiting for NMAP scanning threads to finish..."
write-host " [" -nonewline -foregroundcolor white;write-host "+" -nonewline -foregroundcolor yellow;write-host "] " -nonewline -foregroundcolor white;Write-host "Waiting for scanning threads to finish..." -foregroundcolor green

# Get Date for While loop calculation
$waitTimeout = get-date

# While loop to wait for all jobs to complete
while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) 
{
	Start-Sleep -milliseconds 500
} 
  
# End async call and dispose of everything
# Why? because it's the nice thing to do
for ($y = 0; $y -lt $i; $y++) {     
  
    try {   
        # Complete async job   
        $subnetResults += $ps[$y].EndInvoke($jobs[$y])   
  
    } catch {   
       
        # ERROR
        write-warning " [x] ERROR: $_" 
    }
    
    finally {
		# Dispose of the object
        $ps[$y].Dispose()
    }    
}
# Be a good person and dispose of the pool object
$pool.Dispose()
    
#######################################
# .statistics                         #
#######################################

# Stop the Stopwatch
$sw.stop()

$totalTime = $($sw.elapsed.Hours).ToString() + ":" + $($sw.elapsed.Minutes).ToString() + ":" + $($sw.elapsed.Seconds).ToString()

# Output to logs that the script stopped
"[STOP] Completed Prepare-ToBeScanned script" | out-file "$($logPath)$($TheDate).log" -append

# Print "Total Time Spent Scanning: xx:xx:xx"
write-host " [" -nonewline -foregroundcolor white;write-host "+" -nonewline -foregroundcolor yellow;write-host "] " -nonewline -foregroundcolor white;Write-host "totalTime" -foregroundcolor green

$subnetResults | Export-CSV $outputFile

$swFullTime.stop()

# Print "Total Time Spent Scanning: xx:xx:xx"
write-host " [" -nonewline -foregroundcolor white;write-host "-" -nonewline -foregroundcolor yellow;write-host "] " -nonewline -foregroundcolor white;Write-host "Total Time Spent Scanning: $($swFullTime.Elapsed.Hours):$($swFullTime.Elapsed.Minutes):$($swFullTime.Elapsed.Seconds)" -foregroundcolor green



