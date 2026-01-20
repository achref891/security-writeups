# TryHackMe Lab: Retro

## Introduction

*   **Lab:** [Retro on TryHackMe](https://tryhackme.com/room/retro)
*   **Description:** A beginner-friendly forensics and log analysis machine.

In this write-up, we will walk through the process of exploiting the 'Retro' machine on TryHackMe. We will cover the steps from initial enumeration to gaining root access.

## Tools Used
*   **Nmap:** Network scanning and service enumeration.
*   **Gobuster:** Web directory enumeration.
*   **Remmina:** RDP client for remote access.

## Enumeration

This section will detail the initial scanning and enumeration of the target machine to identify open ports, running services, and potential vulnerabilities.

*   **Nmap Scan:**
    *   Command: `nmap -A -sC 10.49.164.163 -Pn`
    *   Results:

                PORT     STATE SERVICE       VERSION
                80/tcp   open  http          Microsoft IIS httpd 10.0
                | http-methods:
                |_  Potentially risky methods: TRACE
                |_http-title: IIS Windows Server
                |_http-server-header: Microsoft-IIS/10.0
                3389/tcp open  ms-wbt-server Microsoft Terminal Services
                | rdp-ntlm-info:
                |   Target_Name: RETROWEB
                |   NetBIOS_Domain_Name: RETROWEB
                |   NetBIOS_Computer_Name: RETROWEB
                |   DNS_Domain_Name: RetroWeb
                |   DNS_Computer_Name: RetroWeb
                |   Product_Version: 10.0.14393
                |_  System_Time: 2026-01-17T00:12:45+00:00
                | ssl-cert: Subject: commonName=RetroWeb


        
*   **Web Directory Enumeration (e.g., Gobuster/Dirb):**
 *   Command: `gobuster dir -u 10.49.164.163 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
 *   Results:

          ===============================================================
              [+] Url:                     http://10.49.164.163
              [+] Method:                  GET
              [+] Threads:                 10
              [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
              [+] Negative Status codes:   404
              [+] User Agent:              gobuster/3.8.2
              [+] Timeout:                 10s
              ===============================================================
              Starting gobuster in directory enumeration mode
              ===============================================================
              retro                (Status: 301) [Size: 150] [--> http://10.49.164.163/retro/]


## Gaining Access

This section will describe the process of gaining an initial foothold on the machine.



*   **Vulnerability Exploited:** Reusing credentials found during web enumeration.
*   **Exploitation Steps:**
    1.  During web enumeration, a comment on the website revealed a username "wade" and a password "parzival".
    2.  Nmap scan identified an open RDP port (3389/tcp) and the domain "RETROWEB".
    3.  Installed `remmina` using `sudo apt install remmina`.
    4.  Launched `remmina` and configured a new RDP connection:
        *   Server: `10.49.164.163` (Target IP address)
        *   Username: `wade`
        *   Password: `parzival`
        *   Domain: `RETROWEB`
    5.  Successfully connected to the target machine via RDP.
    6.  Found `user.txt` on the desktop.
*   **Payload Used:** N/A (Direct RDP access with valid credentials)

## Privilege Escalation

This section will cover the steps taken to escalate privileges from a user shell to a root shell.

*   **Vulnerability Exploited:** CVE-2019-1388 - UAC Bypass in Windows Certificate Dialog.
*   **Exploitation Steps:** 
    1.  After connecting via RDP, the Recycle Bin was inspected and found to contain `hhupd.exe`.
    2.  The file `hhupd.exe` was executed as an administrator.
    3.  At the UAC prompt, instead of providing credentials, "Show more details" was selected.
    4.  Clicked the "Show information about the publisher's certificate" link.
    5.  In the certificate window, clicking the "Issued by" link opened an Internet Explorer window running with high privileges.
    6.  Used the elevated browser's "Save As" dialog to navigate to `C:\Windows\System32`.
    7.  Launched `cmd.exe` from this dialog to get a shell with `nt authority\system` privileges.
    8.  With a system-level shell, the root flag was read using the command: `type C:\Users\Administrator\Desktop\root.txt`.

## Conclusion

The 'Retro' lab highlights two common security oversights. Initial access was gained by leveraging credentials carelessly left in a public-facing website comment, allowing for a direct RDP login. Privilege escalation was then achieved by exploiting a well-documented UAC bypass vulnerability, CVE-2019-1388.

*   **Key Takeaways:** This lab serves as a crucial reminder to never hardcode or expose credentials in any public forum or code. It also underscores the importance of timely system patching to defend against known privilege escalation vectors.
*   **Recommendations:**
    *   **Secure Credential Management:** Implement strict policies against hardcoding credentials. Use secrets management tools.
    *   **Regular Patching:** Keep operating systems and software up-to-date to mitigate known vulnerabilities.
    *   **Principle of Least Privilege:** Ensure that applications and scheduled tasks do not run with higher privileges than necessary.
    *   **MFA on RDP:** Secure remote access points like RDP with Multi-Factor Authentication to prevent unauthorized access even if credentials are stolen.

***

*Disclaimer: The information provided in this write-up is for educational purposes only. The techniques described should only be used on systems for which you have explicit authorization.*
