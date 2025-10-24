# "----------------------------------------- CTF-FlagFinder ---------------------------------------------" #
# " Version:  1.0                                                                                        " # 
# " Made by   NoAuthZone                                                                                 " # 
# " Source:   https://github.com/NoAuthZone/CTF-FlagFinder                                               " # 
# "------------------------------------------------------------------------------------------------------" #

param(
    [string]$Path = "C:\",
    [string]$Pattern,
    [string[]]$FileExtensions = @('txt','log','cfg','db','ini','ps1','bat','bak','md','html','xml','json','csv','yml','js','py','c','cpp','java','rb','go','psd1','reg','pcap','sqlite','', 'zip' ),
    [switch]$IncludeHidden,
    [string]$OutFile,
    [string]$FlagFormat,
    [switch]$DeepReg,
    [string]$AllFileTypes='*',
    [switch]$AllFiles
)

######################################## HELP INFOS

Write-Host "" -ForegroundColor DarkCyan
Write-Host "--------------------------------------- CTF-FlagFinder -----------------------------------------------------" -ForegroundColor White -BackgroundColor Black
Write-Host " Version:  1.0                                                                                              " -ForegroundColor White -BackgroundColor Black
Write-Host " Made by   NoAuthZone                                                                                       " -ForegroundColor White -BackgroundColor Black
Write-Host " Source:   https://github.com/NoAuthZone/CTF-FlagFinder                                                     " -ForegroundColor White -BackgroundColor Black
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host " -Path 'C:\Users'        - Search path ( example: `-Path 'C:\Users'` ).                                     " -ForegroundColor White -BackgroundColor Black
Write-Host "                           The command searches recursively under the specified path.                       " -ForegroundColor White -BackgroundColor Black
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host " -IncludeHidden          - Includes hidden files and protected directories (e.g., AppData, Recycle Bin).    " -ForegroundColor White -BackgroundColor Black
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host " -AllFiles               - Searches all file types.                                                         " -ForegroundColor White -BackgroundColor Black
Write-Host "                           Default: Only the predefined file types listed above are searched.               " -ForegroundColor White -BackgroundColor Black      
Write-Host "                              bak, bat, c, cfg, cpp, csv, db, go, html, ini, java, js, json, log, md,       " -ForegroundColor White -BackgroundColor Black 
Write-Host "                              pcap, ps1, psd1, py, rb, reg, sqlite, txt, Without_file_type_extension,       " -ForegroundColor White -BackgroundColor Black 
Write-Host "                              xml, yml, zip                                                                 " -ForegroundColor White -BackgroundColor Black      
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host " -FlagFomat 'FLAG'       - Overwrites the default settings for the search (flag / ctf / htb / thm )         " -ForegroundColor White -BackgroundColor Black
Write-Host "                           Upper and lower case letters are not distinguished!                              " -ForegroundColor White -BackgroundColor Black
Write-Host "                           DEFAULT Pattern: (?i)(?:flag|ctf|HTB|THM)\{([^}]{1,500})\}                       " -ForegroundColor White -BackgroundColor Black
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host " -DeepReg                - Searches all registry paths (may take a very long time).                         " -ForegroundColor White -BackgroundColor Black 
Write-Host "                           ⚠️ Use with caution — this option significantly increases runtime.               " -ForegroundColor White -BackgroundColor Black
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host " -OutFile 'C:\file.csv'  - Writes the search results to the specified output .csv file                      " -ForegroundColor White -BackgroundColor Black   
Write-Host "                                                                                                            " -ForegroundColor White -BackgroundColor Black
Write-Host "                                                                                                            " -ForegroundColor DarkCyan
Write-Host "------------------------------------------ SEARCH ----------------------------------------------------------" -ForegroundColor DarkCyan
Write-Host "                                                                                                            " -ForegroundColor DarkCyan
Write-Host "                                                                                                            " -ForegroundColor DarkCyan

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

function New-Result 
{
    param($SourceType,$SourcePath,$Location,$Match,$Context)
    [PSCustomObject]@{
        Time = (Get-Date).ToString('s')
        SourceType = $SourceType
        SourcePath = $SourcePath
        Location = $Location
        Match = $Match
        Context = $Context
    }
}

$results = [System.Collections.Generic.List[object]]::new()

# --- Check folder names ---
function Search-Directories {
    param($root,$pattern,$includeHidden)
    $regex = [regex]$pattern

    $gciParams = @{
        Path = $root
        Recurse = $true
        Directory = $true
        ErrorAction = 'SilentlyContinue'
    }
    if ($includeHidden) 
    { 
        $gciParams['Force'] = $true 
    }

    Get-ChildItem @gciParams | ForEach-Object {
        try 
        {
            $dir = $_
            $matches = $regex.Matches($dir.Name)
            if ($matches.Count -gt 0) 
            {
                foreach ($m in $matches) 
                {
                    $results.Add( (New-Result -SourceType 'DirectoryName' -SourcePath $dir.FullName -Location 'Name' -Match $m.Value -Context $dir.FullName) )
                }
            }
        } catch { }
    }
}

# --- Check file contents + file names ---
function Search-Files {
    param($root,$extFilter,$pattern,$includeHidden)

    $gciParams = @{
        Path = $root
        Recurse = $true
        File = $true
        ErrorAction = 'SilentlyContinue'
    }
    if ($includeHidden) { $gciParams['Force'] = $true }

    if ($extFilter -and $extFilter.Count -gt 0)
    {
        $filters = $extFilter | ForEach-Object { "*.$_" }
        foreach ($f in $filters) 
        {
            Get-ChildItem @gciParams -Filter $f | ForEach-Object {
                Process-File $_ $pattern
            }
        }
    } else 
    {
        Get-ChildItem @gciParams | ForEach-Object {
            Process-File $_ $pattern
        }
    }
}

function Process-File {
    param($fileObj,$pattern)

    $nameRegex = [regex]$pattern
    $nameMatches = $nameRegex.Matches($fileObj.Name)
    if ($nameMatches.Count -gt 0) 
    {
        foreach ($nm in $nameMatches) 
        {
            $results.Add( (New-Result -SourceType 'FileName' -SourcePath $fileObj.FullName -Location 'Name' -Match $nm.Value -Context $fileObj.Name) )
        }
    }

    try 
    {
        if ($fileObj.Length -gt 20MB) 
        {
            return 
         }
        $content = Get-Content -Path $fileObj.FullName -Raw -ErrorAction Stop -Encoding UTF8
    } catch 
    {
        $content = $null
    }

    if ($null -ne $content) 
    {
        $regex = [regex]$pattern
        $matches = $regex.Matches($content)
        if ($matches.Count -gt 0) 
        {
            foreach ($m in $matches)
            {
                $idx = [Math]::Max(0,$m.Index - 40)
                $len = [Math]::Min(160, [Math]::Min($content.Length - $idx, ($m.Length + 80)))
                $ctx = $content.Substring($idx, $len) -replace "`r`n", ' '
                $results.Add( (New-Result -SourceType 'File' -SourcePath $fileObj.FullName -Location "offset:$($m.Index)" -Match $m.Value -Context $ctx) )
            }
        }
    }

    $ext = $fileObj.Extension.ToLowerInvariant()
    if ($ext -in ".docx",".pptx",".xlsx",".zip") 
    {
        Search-ZipLike -ZipPath $fileObj.FullName -pattern $pattern
    }
}

# --- ZIP / Office files ---
function Search-ZipLike {
    param (
        [string]$ZipPath,
        [string]$pattern
    )

    try 
    {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    } catch 
    {
        Write-Host "ERROR when opening as ZIP: $ZipPath" -ForegroundColor Yellow
        return
    }

    $regex = [regex]$pattern

    try 
    {
        foreach ($entry in $zip.Entries) 
        {

            if ($entry.Length -gt 0 -and ($entry.FullName -match '\.(xml|txt|json|md|csv)$' -or $entry.FullName -match 'document' -or $entry.FullName -match '^word/')) 
            {
                try 
                {
                    $sr = $entry.Open()
                    $reader = New-Object System.IO.StreamReader($sr, [System.Text.Encoding]::UTF8)
                    $text = $reader.ReadToEnd()
                    $reader.Close()
                    $sr.Close()
                } catch 
                {
                    continue # ERROR when opening as ZIP:
                }

                $matches = $regex.Matches($text)
                if ($matches.Count -gt 0) 
                {
                    foreach ($m in $matches)
                    {
                        $idx = [Math]::Max(0,$m.Index - 40)
                        $len = [Math]::Min(160, $text.Length - $idx)
                        $ctx = $text.Substring($idx, $len) -replace "`r`n", ' '
                        $global:results.Add( (New-Result -SourceType 'Zip/OOXML' -SourcePath $ZipPath -Location $entry.FullName -Match $m.Value -Context $ctx) )
                    }
                }
            }
        }
    } finally
    {
        $zip.Dispose()
    }
}


# --- Search processes ---
function Search-Processes {
    param($pattern)
    $regex = [regex]$pattern
    
    try 
    {
        $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    } catch 
    { 
        return 
    }

    foreach ($p in $procs) 
    {
        foreach ($field in @('CommandLine','ExecutablePath','Name')) 
        {
            $val = $p.$field
            if ($null -ne $val -and $val -ne '') 
            {
                $matches = $regex.Matches($val.ToString())
                if ($matches.Count -gt 0) 
                {
                    foreach ($m in $matches)
                    {
                        $ctx = ($val.ToString() -replace "`r`n",' ')
                        $results.Add( (New-Result -SourceType 'Process' -SourcePath "PID:$($p.ProcessId)" -Location $field -Match $m.Value -Context $ctx) )
                    }
                }
            }
        }
    }
}

# --- DNS cache (ipconfig /displaydns) ---
function Search-DNSCache {
    param (
        [Parameter(Mandatory = $true)]
        [string]$pattern,
        [string]$outFileBase
    )
        
    $regex = [regex]$pattern
    Write-Host "       DNS output is being collected..." -ForegroundColor Yellow
    
    try 
    {
        $dnsOutput = ipconfig /displaydns 2>&1 | Out-String
    } catch 
    {
        $dnsOutput = "Error while executing ipconfig /displaydns: $($_)"
    }

    $sourcePath = if ($dnsLogPath) { $dnsLogPath } else { 'DNS-Cache' }

    # Context line for overview
    $rawContext = $dnsOutput.Substring(0, [Math]::Min(1000, $dnsOutput.Length)) -replace "`r?`n", ' '

    # Regex-Matching
    $matches = $regex.Matches($dnsOutput)
    if ($matches.Count -gt 0) 
    {
        foreach ($m in $matches) 
        {
            $start = [Math]::Max(0, $m.Index - 40)
            $length = [Math]::Min(160, $dnsOutput.Length - $start)
            $ctx = $dnsOutput.Substring($start, $length) -replace "`r?`n", ' '
            $global:results.Add( (New-Result -SourceType 'DNSCache' -SourcePath $sourcePath -Location "ipconfig /displaydns offset:$($m.Index)" -Match $m.Value -Context $ctx) )
        }
        Write-Host "       [+] $($matches.Count) Hit found in DNS cache!" -ForegroundColor Green
    } 
    return $dnsLogPath
}


function Is-DomainController 
{
    try 
    {
        $role = (Get-WmiObject Win32_ComputerSystem).DomainRole
        return ($role -ge 4)  # 4=Backup DC, 5=Primary DC
    } catch 
    {
        return $false
    }
}

function Search-LogFiles 
{
    param($pattern)

    $regex = [regex]$pattern
    $logPaths = @()

    # Standard log directories
    $logPaths += "C:\Windows\Logs"
    $logPaths += "C:\Windows\System32\LogFiles"
    $logPaths += "C:\Windows\debug"
    $logPaths += "C:\inetpub\logs\LogFiles"

    # If DC, add special logs
    if (Is-DomainController) 
    {
        Write-Host "Domain controller detected – additional DC logs are being analyzed." -ForegroundColor Yellow
        $logPaths += "C:\Windows\debug\Netlogon.log"
        $logPaths += "C:\Windows\debug\Netlogon.bak"
        $logPaths += "C:\Windows\NTDS\NTDS.diagnostic.log"
      # $logPaths += "C:\Windows\NTDS\ntds.dit"   # Note: This is the Active Directory database, not typically for log parsing
        $logPaths += "C:\Windows\NTDS\ntds.jfm"
        $logPaths += "C:\Windows\System32\winevt\Logs"
        $logPaths += "C:\Windows\System32\LogFiles\Netlogon\Netlogon.log"
    }

    foreach ($path in $logPaths) 
    {
        if (Test-Path $path)
        {
            Get-ChildItem -Path $path -Recurse -Filter *.log -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $content = Get-Content $_.FullName -Raw -ErrorAction Stop -Encoding UTF8
                    $matches = $regex.Matches($content)
                    if ($matches.Count -gt 0) 
                    {
                        foreach ($m in $matches) 
                        {
                            $idx = [Math]::Max(0,$m.Index - 40)
                            $len = [Math]::Min(160, [Math]::Min($content.Length - $idx, ($m.Length + 80)))
                            $ctx = $content.Substring($idx, $len) -replace "`r`n", ' '
                            $results.Add( (New-Result -SourceType 'LogFile' -SourcePath $_.FullName -Location "offset:$($m.Index)" -Match $m.Value -Context $ctx) )
                        }
                    }
                } catch 
                {
                    # Optional: Ignore errors in binary files
                }
            }
        }
    }
}

function Search-EventLogs {
    param($pattern)
    $regex = [regex]$pattern

    # List of logs to be scanned
    if(Is-DomainController)
    {
        $logsToSearch = @("Application","System","Security","Directory Service","DNS Server","DFS Replication","File Replication Service")
        
    }else
    {           
        $logsToSearch = @("Application", "System", "Security")
    }

    foreach ($logName in $logsToSearch) 
    {
        try 
        {
            Write-Host "	Search event log: $logName ..." -ForegroundColor DarkGray


            $events = Get-WinEvent -LogName $logName -ErrorAction SilentlyContinue
            foreach ($evt in $events)
            {
                try 
                {
                    $msg = $evt.Message
                    if ($null -ne $msg -and $msg -ne '') 
                    {
                        $matches = $regex.Matches($msg)
                        if ($matches.Count -gt 0) {
                            foreach ($m in $matches) 
                            {
                                $ctx = $msg.Substring([Math]::Max(0,$m.Index - 40), [Math]::Min(160, $msg.Length - $m.Index)) -replace "`r`n",' '
                                $results.Add( (New-Result -SourceType 'EventLog' -SourcePath $logName -Location "EventID:$($evt.Id)" -Match $m.Value -Context $ctx) )
                            }
                        }
                    }
                } catch { continue }
            }
        } catch 
        {
           # Write-Host “Error reading $logName: $_” -ForegroundColor Red
        }
    }
}


# --- Check local user descriptions (only on non-DCs) ---
function Search-LocalUserDescriptions {
    param($pattern)
    $regex = [regex]$pattern

    try 
    {
        if (Get-Command -Name Get-LocalUser -ErrorAction SilentlyContinue) 
        {
            try 
            {
                $users = Get-LocalUser -ErrorAction SilentlyContinue
            } catch 
            {
                $users = @()
            }

            foreach ($u in $users) 
            {
                $desc = $u.Description
                if ($null -ne $desc -and $desc -ne '') 
                {
                    $matches = $regex.Matches($desc.ToString())
                    if ($matches.Count -gt 0) 
                    {
                        foreach ($m in $matches) 
                        {
                            $results.Add( (New-Result -SourceType 'LocalUserDescription' -SourcePath $env:COMPUTERNAME -Location $u.Name -Match $m.Value -Context ($desc -replace "`r`n",' ')) )
                        }
                    }
                }
            }
        } else 
        {
            # Fallback: ADSI WinNT provider (older systems)
            try 
            {
                $comp = [ADSI]"WinNT://$env:COMPUTERNAME"
                $adsiUsers = @()
                foreach ($child in $comp.Children) 
                {
                    if ($child.SchemaClassName -eq 'User') 
                    {
                        $name = $child.Name
                        $desc = $child.Properties['Description'].Value
                        if ($null -ne $desc -and $desc -ne '') 
                        {
                            $matches = $regex.Matches($desc.ToString())
                            if ($matches.Count -gt 0) 
                            {
                                foreach ($m in $matches) 
                                {
                                    $results.Add( (New-Result -SourceType 'LocalUserDescription' -SourcePath $env:COMPUTERNAME -Location $name -Match $m.Value -Context ($desc -replace "`r`n",' ')) )
                                }
                            }
                        }
                    }
                }
            } catch 
            {
               # ADSI fallback failed -> do nothing
            }
        }
    } catch 
    {
       # General error: ignore so that script continues to run
    }
}

# --- Search registry ---
function Search-Registry {
    param (
        [string]$pattern 
    )

    $regex = [regex]$pattern
    if ($null -ne $FlagFormat -and $FlagFormat.Trim() -ne '') 
    {
        $terms = @()                     # now empty list
        $terms += $FlagFormat.Trim()     # Add first (and only) value 
    }else
    {
      # New strategy: simple terms, then check regex
        $terms = @('flag', 'ctf', 'htb', 'thm')
    }
    
    if ($DeepReg) 
    {            
            $hives = @(
                @{ Name = "HKCR"; Desc = "HKEY_CLASSES_ROOT" },
                @{ Name = "HKCU"; Desc = "HKEY_CURRENT_USER" },
                @{ Name = "HKLM"; Desc = "HKEY_LOCAL_MACHINE" },
                @{ Name = "HKU";  Desc = "HKEY_USERS" },
                @{ Name = "HKCC"; Desc = "HKEY_CURRENT_CONFIG" }
            )

            foreach ($hive in $hives) 
            {
                foreach ($term in $terms) 
                {
                    Write-Host "        reg query $($hive.Name) for term '$term' ..." -ForegroundColor Yellow
                    try 
                    {
                        $cmd = "reg query $($hive.Name) /f `"$term`" /s"
                        $regOutput = cmd /c $cmd 2>&1
                        $lines = $regOutput -split "`r?`n"

                        foreach ($line in $lines) 
                        {
                            # Check with your complete regex pattern
                            if ($regex.IsMatch($line)) 
                            {
                                $match = $regex.Match($line)
                                $ctx = $line.Trim()
                                $results.Add((New-Result -SourceType 'RegistryQuery' -SourcePath $hive.Name -Location "reg query (term=$term)" -Match $match.Value -Context $ctx))
                            }
                        }
                    } catch 
                    {
                        Write-Host "        Error querying $($hive.Name) for '$term': $_" -ForegroundColor Red
                    }
                }
            }
    }
}


function Process-RegistryKey
{
    param (
        [string]$keyPath,
        [regex]$regex
    )

    try 
    {
        $props = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
        foreach ($name in $props.PSObject.Properties.Name) 
        {
            $val = $props.$name
            if ($null -ne $val) 
            {
                $s = $val.ToString()
                $matches = $regex.Matches($s)
                if ($matches.Count -gt 0) 
                {
                    foreach ($m in $matches) 
                    {
                        $ctx = $s -replace "`r`n", ' '
                        $results.Add( (New-Result -SourceType 'Registry' -SourcePath $keyPath -Location $name -Match $m.Value -Context $ctx) )
                    }
                }
            }
        }
    } catch {}
}

function Get-PartitionInfo {
    # Get all partitions with drive letters
    $partitions = Get-Volume | Where-Object { $_.DriveLetter -ne $null }

    # Determine number
    $partitionCount = $partitions.Count
     
    # Compile a list of names
    $partitionNames = $partitions | ForEach-Object {
        "$($_.DriveLetter): ($($_.FileSystemLabel))"
    }

    # Output as a user-defined object
    return [PSCustomObject]@{
        Anzahl     = $partitionCount
        Partitionen = $partitionNames
    }
    write-host "partitionCount"
}

#################################################################################  Flag Settings
# Standard-Pattern
$DefaultPattern = '(?i)(?:flag|ctf|FLAG|HTB|THM)\{([^}]{1,500})\}'

# Load default or set input
if ($null -ne $FlagFormat -and $FlagFormat.Trim() -ne '') {

        $maxLength = 100
        # Generate the pattern dynamically from $FlagFormat
        $Pattern = "(?i)(?:$FlagFormat)\{([^}]{1,$maxLength})\}"
} else
{
    # The default values are loaded.
    $Pattern = '(?i)(?:flag|ctf|FLAG|HTB|THM)\{([^}]{1,500})\}'
}

################################################################################# Partion Infos
# Get the partitions
$partitionInfo = Get-PartitionInfo

# If more than 1 partition exists → Display message
if ($partitionInfo.Anzahl -ne 1) 
{ 
    Write-Host "Notice: Multiple drives detected                  " -ForegroundColor Yellow
    Write-Host "        — only the path '$Path' will be scanned.  " -ForegroundColor Yellow
    Write-Host "                                                  " -ForegroundColor Yellow
    Write-Host "                                                  " -ForegroundColor Yellow
}

################################################################################## Search all FileTypes
if ($AllFiles) 
{
    $FileExtensions = @()                      
    $FileExtensions += $AllFileTypes.Trim()   
    Write-Host "                                                  " -ForegroundColor Yellow
    Write-Host "  All File Types will be searched!!!              " -ForegroundColor Yellow
    Write-Host "  It'll take a while, grab a coffee.              " -ForegroundColor Yellow
    Write-Host "                                                  " -ForegroundColor Yellow
} 

##################################################################################  Main sequence ===
Write-Host "Start search in $Path ..." -ForegroundColor Cyan
Write-Host "Pattern: $Pattern" -ForegroundColor DarkCyan

################################################################################## Folder Names
Write-Host "Search folder names..." -ForegroundColor Cyan
Search-Directories -root $Path -pattern $Pattern -includeHidden:$IncludeHidden

##################################################################################  Files (content + name)
Write-Host "Search files and file names ..." -ForegroundColor Cyan
Search-Files -root $Path -extFilter $FileExtensions -pattern $Pattern -includeHidden:$IncludeHidden


################################################################################## Registry
Write-Host "Search for flags in the registry ..." -ForegroundColor Cyan
Search-Registry -pattern $Pattern

################################################################################## Process
Write-Host "Search running processes ..." -ForegroundColor Cyan
Search-Processes -pattern $Pattern

################################################################################## Windows LOGS
# Search in Windows Logs
Write-Host "Search Windows log files..." -ForegroundColor Cyan
Search-LogFiles -pattern $Pattern

################################################################################## Event Logs
Write-Host "Search event logs (application, system, security, setup, etc.) ..." -ForegroundColor Cyan
Search-EventLogs -pattern $Pattern


################################################################################## DNS Cache
# DNS Cache (ipconfig /displaydns)
Write-Host "Determine DNS cache via 'ipconfig /displaydns' ..." -ForegroundColor Cyan
$dnsLog = Search-DNSCache -pattern $Pattern # -outFileBase $OutFile

################################################################################## Local User Discription search
if (-not (Is-DomainController)) 
{
    Write-Host "Search local user descriptions for flags ..." -ForegroundColor Cyan
    Search-LocalUserDescriptions -pattern $Pattern
} else 
{
    Write-Host "System is domain controller — local user descriptions are skipped." -ForegroundColor Yellow
}

################################################################################## Output
if ($OutFile) 
{
    try 
    {
        $results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
        Write-Host "Results saved in ${OutFile}" -ForegroundColor Green
    } catch {
        Write-Host "Error writing ${OutFile}: $($_)" -ForegroundColor Red
    }
} else
{
    Write-Host "                                                                                                      " -ForegroundColor DarkCyan
    Write-Host "------------------------------------------ OUTPUT ----------------------------------------------------" -ForegroundColor DarkCyan
    $results | Format-Table -Property Time, SourceType, SourcePath, Match
}
