
```
   ____ __             ____ _          __         
  / __// /___ _ ___ _ / __/(_)___  ___/ /___  ____
 / _/ / // _ `// _ `// _/ / // _ \/ _  // -_)/ __/
/_/  /_/ \_,_/ \_, //_/  /_//_//_/\_,_/ \__//_/   
              /___/                                                         
```

Version: **1.0**  
Author: **NoAuthZone**  


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

`-Path "Path"`  
	Search path ( example: `-Path "C:\Users"` ). The command searches recursively under the specified path.
    
`-IncludeHidden  
    Includes hidden files and protected directories (e.g., AppData, Recycle Bin).
    
`-AllFiles  
    Searches **all** file types. Default: Only the predefined file types listed above are searched.
    
`-FlagFormat "PATTERN"  
    Defines a custom flag or CTF pattern (e.g., "HTB", "FLAG", or a full regex).
    Overrides the default pattern. Matching is case-insensitive.

`-DeepReg 
    Searches all registry paths (may take a very long time).
    ⚠️ Use with caution — this option significantly increases runtime.
    
`-OutFile "<FilePath>"
    Writes the search results to the specified output file
    (example: -OutFile "C:\results.txt").
	
## Example Commands

```
# This command searches all files, including hidden ones, on the C: partition for the flag "RASTA", regardless of file type.
powershell -ep Bypass -File "C:\Users\Administrator\Documents\FlagFinder.ps1"  -Path "C:\"  -IncludeHidden  -FlagFormat "RASTA" -AllFiles
```

```PowerShell
# This command disables PowerShell logging and searches the E: partition — including hidden directories such as AppData and the Recycle Bin
powershell -ep Bypass -File "C:\Users\Administrator\Documents\FlagFinder.ps1" ` -Path "E:\"  -IncludeHidden 
```


