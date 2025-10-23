Version: **1.0**  
Author: **NoAuthZone**  
Source: [https://github.com/NoAuthZone/FlagFinder](https://github.com/NoAuthZone/FlagFinder)

---

## Short description

**FlagFinder** is a PowerShell-based search tool for finding CTF/flag strings and similar secrets on Windows systems. It searches files (content & names), the registry, DNS cache, recycle bin, log files, ZIP and OOXML archives, and much more—including hidden areas, if desired.

---

## Features (selection)

- Content and name search in files (many formats, including file-less entries such as `hosts`)
- Search in hidden/protected areas (e.g., `AppData`, `C:\$Recycle.Bin`)    
- Recursive scanning of ZIP and OOXML files (`.docx`, `.xlsx`)
- Searching the registry (HKLM & HKCU) for possible flag strings (optional deep)    
- Evaluation of Windows event logs (Application, Security, System)
- Reading of the DNS cache (`ipconfig /displaydns`)
- Detection of multiple partitions (only one is searched by default; notification in case of multiple volumes)
- Optional inclusion of all file types or restriction to typical text/configuration files
    
 
---

## Standard search file types

By default, the following file types are searched (if **-AllFiles** is not set):  
`bak, bat, c, cfg, cpp, csv, db, go, html, ini, java, js, json, log, md, pcap, ps1, psd1, py, rb, reg, sqlite, txt, Without_file_type_extension, xml, yml, zip`

---

## Options / Parameters

- `-Path "Path"`  
	Search path ( example: `-Path "C:\Users"` ). Searches recursively under the specified path.
    
- `-IncludeHidden`  
    Includes hidden files and protected areas (e.g., `AppData`, Recycle Bin).
    
- `-AllFiles`  
    Searches **all** file types. Default: only the types listed above.
    
- `-FlagFormat "PATTERN"`  
    Custom flag/CTF pattern (e.g., `"HTB"`, `"FLAG"`, or a complete regex). Overrides the default pattern. Case-insensitive.
    
- `-DeepReg`  
    Searches **all** registry paths (very long runtime!). Caution: can be very time-consuming.
    
- `-OutFile '<Dateipfad>'`  
    Write the results to the specified output file (e.g., `-OutFile "C:\file.txt"`).

## Example Commands

### Disable PowerShell Logging and Search on Partion E inlusive hidden Files as Appdata or Recycle Bin.
```
powershell -ep Bypass -File "C:\Users\Administrator\Documents\FlagFinderv2.ps1" ` -Path "E:\"  -IncludeHidden 
```

