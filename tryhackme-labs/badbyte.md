# TryHackMe: Badbyte - A Detailed Pentest Walkthrough

**Author:** Achref
**Date:** 2026-01-21

---

## Task 2: Reconnaissance

### Objective
The first step in any engagement is to map the target's attack surface. The goal is to conduct thorough network scanning to discover all open ports and running services, which will inform our initial entry strategy.

### Process
A two-stage Nmap scan was performed to build a complete and accurate picture.

1.  **Initial Full Port Scan:** To ensure no service was missed, a quick scan covering all 65,535 TCP ports was conducted.
    *   **Command:** `nmap -p- -vv 10.49.159.189`
2.  **Detailed Service Scan:** With the open ports identified, a more focused and aggressive scan was run to determine the exact versions of the running services, which is crucial for finding public exploits.
    *   **Command:** `nmap -A -p 22,30024 10.49.159.189`

### Findings
*   **Port 22 (TCP):** OpenSSH 8.2p1 (Ubuntu)
*   **Port 30024 (TCP):** vsftpd 3.0.5

---
### Questions & Answers

*   **How many ports are open?** 2
*   **What service is running on the lowest open port?** SSH
*   **What non-standard port is open?** 30024
*   **What service is running on the non-standard port?** FTP

---

## Task 3: Foothold

### Objective
With an anonymous FTP server identified, the primary goal is to exploit this weakness to find credentials or keys that will grant us an initial shell on the machine.

### Process
The FTP service on the non-standard port was the most promising entry point.

1.  **Anonymous FTP Login:** The FTP service on port 30024 was tested and found to allow anonymous login, a significant misconfiguration.
    *   **Command:** `ftp 10.49.159.189 30024` (Username: `anonymous`, blank password)
2.  **File Discovery & Exfiltration:** Upon logging in, two critical files were discovered and downloaded.
    *   **Commands:**
        ```bash
        ls -la
        get id_rsa
        get note.txt
        bye
        ```
3.  **Username Discovery:** The downloaded `note.txt` file contained the text "errorcauser", a likely username.
4.  **SSH Key Cracking:** The `id_rsa` key was encrypted. The passphrase was cracked in a two-stage process:
    *   First, `ssh2john.py` converted the key into a hash format: `python /usr/share/john/ssh2john.py id_rsa > privatekey.hash`
    *   Second, `John the Ripper` cracked the hash using a common wordlist: `john privatekey.hash -w /usr/share/wordlists/rockyou.txt`
5.  **Initial Access:** With the username (`errorcauser`), private key (`id_rsa`), and cracked passphrase (`cupcake`), a successful SSH connection was made.
    *   **Command:** `ssh -i id_rsa errorcauser@10.48.150.185`

---
### Questions & Answers

*   **What username do we find during the enumeration process?** `errorcauser`
*   **What is the passphrase for the RSA private key?** `cupcake`

---

## Task 4: Port Forwarding

### Objective
An external scan doesn't show the full picture. Having gained a shell, our new objective is to perform internal reconnaissance to discover services running on the machine's localhost interface, which are invisible from the outside.

### Process
The initial shell as `errorcauser` was extremely restricted. To work around this and perform a proper internal scan, we set up an SSH tunnel.

1.  **SSH Dynamic Port Forwarding (SOCKS Proxy):** A dynamic tunnel was created to proxy our tools through the compromised `errorcauser` shell, effectively allowing us to scan the target's internal network from our attack machine.
    *   **Command:** `ssh -i id_rsa -D 1337 -N errorcauser@10.48.150.185`
2.  **ProxyChains Configuration:** The `proxychains.conf` file was updated to route traffic through our new SOCKS proxy.
    *   **File:** `/etc/proxychains4.conf`
    *   **Action:** The default line was commented out and our proxy on port 1337 was added. `socks5 127.0.0.1 1337`
3.  **Creative Internal Scan:** Since the `errorcauser` shell was so limited, a simple port scanning loop was executed using built-in bash functionality to get a definitive list of open internal ports.
    *   **Command:** `for i in {1..65535}; do (echo > /dev/tcp/127.0.0.1/$i) >/dev/null 2>&1 && echo $i is open; done`
4.  **Internal Services Found:** The scan revealed two new services listening on `127.0.0.1`.

---
### Questions & Answers

*   **What main TCP ports are listening on localhost?** 80, 3306
*   **What protocols are used for these ports?** HTTP, MySQL

---

## Task 5: Web Exploitation

### Objective
The internal web server is our next target. The goal is to identify the web application, find a critical vulnerability, and leverage it to gain a more privileged shell on the system, leading to the user flag.

### Process
1.  **Local Port Forwarding:** To interact with the internal web server from our browser and tools, a local port forwarding tunnel was created.
    *   **Command:** `ssh -i id_rsa -L 5000:127.0.0.1:80 -N errorcauser@10.48.150.185`
2.  **CMS Enumeration:** With the web service now accessible on `localhost:5000`, the specialized scanner `wpscan` was used to analyze it.
    *   **Command:** `wpscan --url http://localhost:5000/ -e u,vp --no-update`
    *   **Findings:** The scan identified **WordPress 5.3.2** (an insecure version) and the username **`cth`**.
3.  **Vulnerability Research:** With a specific version identified, research pointed to a critical Remote Code Execution (RCE) vulnerability in the `wp-file-manager` plugin: **CVE-2020-25213**.
4.  **Metasploit Exploit:** The Metasploit Framework provided a pre-built module for this RCE.
    *   **Module:** `exploit/unix/webapp/wp_file_manager_rce`
    *   **Configuration:** `RHOSTS` was set to `localhost`, `RPORT` to `5000`, and `LHOST` to our VPN IP for the reverse shell.
5.  **User Shell & Flag:** The exploit granted a reverse shell as the `cth` user, which was used to read the user flag at `/home/cth/user.txt`.

---
### Questions & Answers

*   **What CMS is running on the machine?** WordPress 5.3.2
*   **Can you find any vulnerable plugins?** Yes, `wp-file-manager` (related to `CVE-2020-25213`).
*   **What is the CVE number for directory traversal vulnerability?** `CVE-2020-11738`
*   **What is the CVE number for remote code execution vulnerability?** `CVE-2020-25213`
*   **What is the user that was running CMS?** `cth`
*   **What is the user flag?** `THM{227906201d17d9c45aa93d0122ea1af7}`

---

## Task 6: Privilege Escalation

### Objective
The final phase: escalate from the user `cth` to `root` by exploiting misconfigurations and capturing the final flag.

### Process
The hint about "logged SSH sessions" was the key to this phase.

1.  **Log File Discovery:** Enumerating as `cth`, a non-standard, world-readable log file was discovered at `/var/log/bash.log`.
2.  **Password Discovery:** This log file contained a cleartext password: `G00dP@$sw0rd2020`.
3.  **Pattern Recognition:** Following the room's hint to guess a "new" password from an "old" one, the found password was incremented to guess the current working password: `G00dP@$sw0rd2021`.
4.  **Shell Stabilization:** The initial shell from Metasploit was non-interactive. The `sudo` command requires a proper terminal (TTY) to function, so the shell was upgraded using a standard Python one-liner.
    *   **Command:** `python3 -c 'import pty; pty.spawn("/bin/bash")'`
5.  **Sudo Privilege Check:** The `sudo -l` command confirmed that `cth` could run any command as root, using the guessed password `G00dP@$sw0rd2021`.
6.  **Root Access & Flag:** With sudo rights confirmed, a root shell was obtained (`sudo su`) and the root flag was read from `/root/root.txt`.

---
### Questions & Answers

*   **What is the user's old password?** `G00dP@$sw0rd2020`
*   **What is the root flag?** `THM{ad485b44f63393b6a9225974909da5fa}`

---

## Arsenal of Tools
*   **Nmap:** Network scanning and service enumeration.
*   **FTP Client:** Interacting with the vsftpd server.
*   **John the Ripper & ssh2john:** Cracking the encrypted SSH key.
*   **SSH:** Secure remote login and advanced port forwarding.
*   **WPScan:** Specialized WordPress vulnerability scanner.
*   **Metasploit Framework:** Exploiting the WordPress RCE.
*   **Python:** Used for spawning a fully interactive TTY shell.

---

## Summary & Key Learnings
*   **Insecure Storage of Secrets:** This machine demonstrated multiple failures in protecting secrets, including a private SSH key on an anonymous FTP server and a user password in a log file.
*   **Principle of Least Privilege:** The web server was misconfigured to run as a user (`cth`) who had full `sudo` rights, a critical security flaw. Web services should always run as dedicated, low-privilege accounts.
*   **Importance of Patching:** Using an outdated version of WordPress directly led to compromise via a well-known RCE vulnerability.
*   **Shell Stabilization:** The exercise highlighted the importance of knowing how to upgrade a non-interactive shell to a full TTY, as it is often a prerequisite for using privileged commands like `sudo`.
*   **Creative Enumeration:** When standard tools are missing, it's crucial to think creatively, such as using shell features like `/dev/tcp` for enumeration.