<details>
<summary>$\huge{\text{FTP}}$</summary>

- Connect to ftp server
  - `ftp <ip>` and then login
- Check anonymous login (with nmap script ftp-anon or anonymous user)
- If you have a username try using it as password
- Brute force login
- Search exploit for vulnerable version

</details>

<details>
<summary>$\huge{\text{SSH}}$</summary>

- Connect to SSH
  - `ssh <username>@<ip>` and then login
- If you have a username try using it as password
- Brute force login
- Search exploit for vulnerable version

</details>

<details>
<summary>$\huge{\text{SMB & Samba}}$</summary>

- If you have a username try using it as password
- Brute force login
- Search exploit for vulnerable version
- If v1 is enabled - EternalBlue exploit (check with nmap --> smb-protocols)
- List shared folders
  - `smbclient --no-pass -L //<IP>` Null user
  - `smbclient -U 'username[%passwd]' -L [--pw-nt-hash] //<IP>` If you omit the pwd, it will be prompted. With --pw-nt-hash, the pwd provided is the NT hash
    - Example: `smbclient -U 'admin%admin' -L //<IP>`
- Obtain Information
  - `enum4linux -a [-u "<username>" -p "<passwd>"] <IP>`
- Command execution (authenticated)
  - `smbmap -H <ip> -u <user> -p <pass> -x 'ipconfig'`
  - psexec (impacket or metasploit)
    - can be used to pass NTLM hashes as password
    - `python3 psexec.py Administrator@ip`

</details>

<details>
<summary>$\huge{\text{MYSQL}}$</summary>

- Connect: `mysql -h <Hostname> -u root`
- If you have a username try using it as password
- Brute force login
  - Try with `root` default user

</details>

<details>
<summary>$\huge{\text{PHP}}$</summary>

- Famous exploit: php_cgi_arg_injection (up to version 5.3.12 and 5.4.2 )

</details>

#### Other ports
Most of the services identified by the Nmap scan are easily recognizable, however, it's possibile that there are a few open ports on a target system that do not have a service banner. To learn more about these port and the service running, we can perform banner grabbing with Netcat
- `netcat <ip> <port>`

