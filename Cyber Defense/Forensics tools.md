# Forensics tools 

### Disk analysis
- Autopsy
- FTK Imager

### Memory analysis / Forensic investigation
- Redline (can be used to extract a memory)
- Volatility

### Zero dependency viewer
- EZViewer (Eriz Zimmerman's tools), Windows

### File system analysis
- MFTECmd (Eriz Zimmerman's tools), Windows

### Evidence of Execution 
#### Windows Prefetch files
Prefetch files contain the last run times of the application, the number of times the application was run, and any files and device handles used by the file
- PECmd (Eriz Zimmerman's tools), Windows

#### Windows 10 Timeline
Windows 10 stores recently used applications and files in an SQLite database called the Windows 10 Timeline. This data can be a source of information about the last executed programs. It contains the application that was executed and the focus time of the application
- WxTCmd (Eriz Zimmerman's tools), Windows

#### Windows Jump Lists
Windows introduced jump lists to help users go directly to their recently used files from the taskbar. We can view jumplists by right-clicking an application's icon in the taskbar, and it will show us the recently opened files in that application.
- JLECmd (Eriz Zimmerman's tools), Windows

#### Shortcut Files
The shortcut files contain information about the first and last opened times of the file and the path of the opened file, along with some other data
- LECmd (Eriz Zimmerman's tools), Windows

