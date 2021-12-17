<#
    LOG4J Hunter 1.3.0, By Will Coulter @ AlchemySec.com.au 
    1. searches all disks for *.jar files 
    2. examines each file for the presence of the vulnerable 'JndiLookup.Class'
    3. examines the identified library for the presence of the patched code in the 'JmsAppender$Builder.class'.
    4. Outputs the result to disk (Default is C:\) for review and clearly marks the jar files that are vulnerable to Log4Shell/Log4Jam.

    This script was based off of the script created by SP4IR: https://github.com/sp4ir/incidentresponse/blob/35a2faae8512884bcd753f0de3fa1adc6ec326ed/Get-Log4shellVuln.ps1
    Note: While this script will identify log4j instances within .jar files, in its current version it will not recursively extract and examine nested .JAR files.
#>

#Add compression assemblies to access archive files (zips/jars)
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

#Define log folder variable, default is C:\.
$logFolder = "C:\"
$targetManifestFile = "$logFolder\log4j-manifest.txt"
$targetClassFile = "$logFolder\log4j-class.txt"
$manifestCsv = "$logFolder\log4j-manifest.csv"

#Define result array
$resultsArray = @()
#Define file name filter, default is 'log4j*.jar', however this approach will not find the LOG4J library if it is present in a none log4j named file. Recommendation is to leave this as '*.jar'.
$log4Filter = "*.jar"

#Create list of JAR files on all disks.
write-host "# Identifying Local Disks"
get-wmiobject win32_volume | ? { $_.DriveType -eq 3 -and $_.DriveLetter -ne $null } | % { get-psdrive $_.DriveLetter[0] }
write-host
write-host "# Hunting for .jar files (This may take awhile..)"

#Create Job to identify all .JAR files.
$jobName = Start-Job -ScriptBlock { $jarFiles = get-wmiobject win32_volume | ? { $_.DriveType -eq 3 -and $_.DriveLetter -ne $null } | % { get-psdrive $_.DriveLetter[0] } | Where-Object { $_.Name.length -eq 1 } | Select-Object -ExpandProperty Root | Get-ChildItem -File -Recurse -Filter $log4Filter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName }

#Create loading animation while Job is still running.
while($jobName.JobStateInfo.State -eq "Running") {
	Write-Host '.' -NoNewline
	Start-Sleep -Seconds 1
}
write-host

$jarFiles = Get-PSDrive | Where-Object { $_.Name.length -eq 1 } | Select-Object -ExpandProperty Root | Get-ChildItem -File -Recurse -Filter $log4Filter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
write-host "# Examaning found .jar files."
#Loop through all jar files looking for the JndiLookup class.
foreach ($jarFile in $jarFiles) {
    write-host "# Examining: $jarFile"
    $zip = [System.IO.Compression.ZipFile]::OpenRead($jarFile)
    $zip.Entries | 
    Where-Object { $_.Name -like 'JndiLookup.class' } | ForEach-Object {  
        write-host "# Found JndiLookup.class: $($_.FullName)"
        $jndiclasspath = "$($_.FullName)"            
    }

    $zip.Entries |
    Where-Object { $_.Name -like 'JmsAppender$Builder.class' -and $_.FullName -like '*log4j*' } | ForEach-Object {
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $targetClassFile, $true)
        $patchedlog4jdetection = Get-Content $targetClassFile
        if ($patchedlog4jdetection -like '*allowedLdapHosts*') {
            $log4jvuln = "FALSE"
        } else{
            $log4jvuln = "TRUE"
        }
        Remove-Item $targetClassFile -ErrorAction SilentlyContinue
    }       

    $zip.Entries | 
    Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | ForEach-Object {        
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $targetManifestFile, $true)
        $implementationVersion = Get-Content $targetManifestFile | Where-Object { $_ -like 'Implementation-Version: *' }
        if ($implementationVersion -like '*Implementation-Version: *') { 
            $implementationVersion = $implementationVersion.ToString()
            $implementationVersion = $implementationVersion.Replace('Implementation-Version: ', '')
        } else {
            $implementationVersion = "N/A"
        }
        Remove-Item $targetManifestFile -ErrorAction SilentlyContinue
    }

    if ($jndiclasspath -eq $null) {
        #Do nothing.
    }else {
        #Append to array
        $row = "" | SELECT JARFILE,JARVERSION,VULNERABLE,JNDICLASSPATH
        $row.JARFILE = "$($jarFile.ToString())"
        $row.JARVERSION = "$($implementationVersion.ToString())"
        $row.VULNERABLE = "$log4jvuln"
        $row.JNDICLASSPATH = "$jndiclasspath"
        $resultsArray += $row
        write-host "# $($jarFile.ToString()) Results: "
        write-host "Filename: $($jarFile.ToString())"
        write-host ".JAR Version: $($implementationVersion.ToString())"
        write-host "Vulnerable: $log4jvuln"
        write-host "JNDI Class Path: $jndiclasspath"
        write-host
    }
    #clear variables
    if ($implementationVersion -ne $null) { Clear-Variable -Name "implementationVersion" }
    if ($log4jvuln -ne $null) { Clear-Variable -Name "log4jvuln" }
    if ($jndiclasspath -ne $null) { Clear-Variable -Name "jndiclasspath" }
}
write-output "# Hunting Complete. Overall Results: "
$resultsArray

#Write array to disk.
$datetime = Get-Date -Format "dd.MM.yyyy_HH-mm-ss";
$file_name = "Log4JHunting_Result_" + $datetime + ".csv";
$file_path = $logFolder + $file_name;

$resultsArray | Export-Csv -Path "$file_path" -NoTypeInformation
