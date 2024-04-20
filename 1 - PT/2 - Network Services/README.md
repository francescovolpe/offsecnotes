<details>
<summary>FTP</summary>

- Connect to ftp server
  - `ftp <ip>` and then login
- Check anonymous login (with nmap script ftp-anon or anonymous user)
- If you have a username try using the it as the password
- Brute force login
- Search exploit for vulnerable version

</details>

<details>
<summary>SSH</summary>

- Connect to SSH
  - `ssh <username>@<ip>` and then login
- If you have a username try using the it as the password
- Brute force login
- Search exploit for vulnerable version

</details>

<details>
<summary>SMB</summary>

- If you have a username try using the it as the password
- Brute force login
- If v1 is enabled - EternalBlue exploit (check with nmap --> smb-protocols)
- List shared folders
  - `smbclient --no-pass -L //<IP>` Null user
  - `smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP>` If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
    - Example: `smbclient -U 'admin%admin' -L //<IP>`
- Obtain Information
  - `enum4linux -a [-u "<username>" -p "<passwd>"] <IP>`
- Command execution
  - to do

    
</details>
