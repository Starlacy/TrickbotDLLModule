# Trickbot-Module-DLL

anubisDll32

This is a man-in-the-browser module. It contains a full implementation of the IcedID main module. It can intercept web traffic on the victim machine. This module also contains embedded binary Anubis VNC (also known as HDESK Bot), which is a custom RAT based on the VNC (Virtual Network Computing) protocol that’s used by IcedID for remote control.

bcClientDll32

This is a reverse proxy module with custom implementation of SOCKS5 protocol. It is used to bypass traffic through the compromised host.

bvncDll32

This module is an implementation of Hidden VNC, which is a custom remote administration tool based on the VNC (Virtual Network Computing) protocol. Hidden means that this modification of the VNC creates an additional desktop hidden from the user, allowing attackers to work with the compromised system in the same way as via an RDP connection without attracting the user’s attention. Web sessions and user passwords saved in the browser are available in hVNC sessions. An attacker can freely run a web browser on a remote system, accessing any web service when there is an active user session.

cookiesDll32

The module steals cookie data from web browsers. It targets the storage databases of Chrome, Firefox, Internet Explorer and Microsoft Edge.

domainDll32

The module is also called DomainGrabber. It collects domain controller information on compromised systems by accessing the SYSVOL folder. The first modification of this module was querying for groups.xml, services.xml, scheduledtasks.xml, datasources.xml, printers.xml and drives.xml files. The current modification of this module only queries for group policies (groups.xml).

tdpwgrab32

This module is a password stealer module. It can steal credentials stored in registry, databases of different applications, configuration and “precious files”, i.e., private keys, SSL certificates and crypto wallet data files. It is also able to grab autofill information from web browsers. The module is capable of stealing data from the following applications: Git, TeamViewer, OpenSSH, OpenVPN, KeePass, Outlook, FileZilla, Internet Explorer, Mozilla Firefox, Google Chrome, Microsoft Edge, RDP, WinSCP, VNC, UltraVNC, RealVNC, TigerVNC, PuTTY, AnyConnect. Note that newer module versions may also target other applications.

fscanDll32

This is an FTP (File Transfer Protocol) and SFTP (SSH File Transfer Protocol) file scanner based on the open-source software project cURL. The module receives a list of rules for matching files and FTP/SSH resources, enumerates the files on the targeted resource and reports back to the C2.

importDll32

This module steals data from web browsers, including browser configuration, cookies, history, title, visit count, HTML5 local storage. The browsers Internet Explorer, Mozilla Firefox, Google Chrome, and Microsoft Edge are targeted. The module also gathers information about installed browser plugins and components.

injectDll32

This module is used to intercept activity related to banking websites in browsers. It uses web injects to steal financial information. Two types of attack are supported: “static” and “dynamic”. Static attacks redirect user requests to a malicious phishing page, while dynamic attacks pass all traffic through the malicious proxy server, making it possible to grab information from input forms and modify banking website responses by injecting additional malicious scripts in returned pages.

mailsearcher32

This module enumerates all disks and folders, and searches for email patterns in files. It ignores files with selected extensions: .avi, .mov, .mkv, .mpeg, .mpeg4, .mp4, .mp3, .wav’, .ogg, .jpeg, .jpg, .png, .bmp, .gif, .tiff, .ico. In addition it unpacks files with .xlsx, .docx, and .zip extensions, and performs the same email patterns search in the extracted file. Every time scanning of a disk ends, the module sends the list of found addresses back to the C2 server.

masrvDll32

This module is a network scanner based on source code of the Masscan software project. The module requests the range of IP addresses from the C2, scans all IPs in this range for the opened port, and sends the list of found addresses and ports back to the C2 server.

mlcDll32

This module implements the main functionality of the Gophe spambot. The Gophe spambot was used to propagate Dyre malware. As the successor to Dyre, it comes as no surprise that Trickbot has also inherited Gophe’s source code. It can grab emails from Outlook and send spam through Outlook using MAPI. It also removes traces of spamming by deleting emails from the Outlook Sent Items folder. This module is also propagated by Trickbot as a standalone executable known as TrickBooster.

networkDll32

This module gets information about the network from the local system. It uses the following ADSI (Active Directory Service Interfaces) property methods to gather information:

ComputerName;
SiteName;
DomainShortName;
DomainDNSName;
ForestDNSName;
DomainController.
It retrieves the DNS names of all the directory trees in the local computer’s forest. It also gets a full process list and system information snapshot (OS Architecture / ProductType / Version / Build / InstalationDate / LastBootUpTime / SerialNumber / User / Organization / TotalPhysicalMemory).

The module executes and gathers the results of selected commands:

“ipconfig /all”
“net config workstation”
“net view /all”
“net view /all /domain”
“nltest /domain_trusts”
“nltest /domain_trusts /all_trusts”
NewBCtestnDll32

This module is a reverse proxy module with custom implementation of the SOCKS5 protocol. It’s used to bypass traffic through the compromised host. The module can determine the external network IP address by STUN protocol using Google’s STUN servers. It can also create new processes by receiving a command line from a proxy-C2. It can’t download binaries for execution, but the ability to create new processes by starting powershell.exe with a Base64 encoded script in the command line transforms this module into a backdoor. Note that this is a common tactic for many actors.

outlookDll32

This module is written in Delphi, which is uncommon. The module tries to retrieve credentials from the Outlook profile stored in the system registry.

owaDll32

This module receives a list of domains, logins and passwords from the C2, and tries to find an OWA service on selected domains. To do so, it creates a URL by adding subdomains (‘webmail.’, ‘mail.’, ‘outlook.’) to domains from the list, and setting the URL path to ‘/owa’. After that it makes a POST request to the crafted URL, and checks the response for strings, tags or headers that are specific to an OWA service. The module then reports back to the C2 about the OWA URLs it finds. It can also perform a brute-force attack on the OWA URLs with logins and passwords received from the C2.

psfin32

Using Active Directory Service Interfaces (ADSI), this module makes Lightweight Directory Access Protocol (LDAP) and GlobalCatalog (GC) queries for organizational unit names, site name, group account name, personal account name, computer host name, with selected masks ‘*POS*’, ‘*REG*’, ‘*CASH*’, ‘*LANE*’, ‘*STORE*’, ‘*RETAIL*’, ‘*BOH*’, ‘*ALOHA*’, ‘*MICROS*’, ‘*TERM*’.

rdpscanDll32

This module receives a list of domains, IPs, logins and passwords from the C2, performs a check for RDP connection on the list of targets, and reports back to the C2 about the online status of targets. It can perform brute-force attacks on targeted systems, using the received logins and passwords. It also has the ability to brute force credentials by mutating IPs, domain names and logins, for instance, by replacing, swapping or removing letters, numbers, dots, switching from lower to upper case or vice versa, performing string inversion, etc.

shadDll32

This is the first implementation of the anubisDll32 module. It does not include the Anubis VNC embedded binary.

shareDll32

This module is used to spread Trickbot over the network. It downloads Trickbot from the URL http[:]//172[.]245.6.107/images/control.png and saves it as tempodile21.rec. It then enumerates network resources and tries to copy the downloaded Trickbot to selected shares C$ or ADMIN$ as nats21.exe. It then creates and starts a remote service on the compromised system in the following paths:

%SystemDrive%\nats21.exe
%SystemRoot%\system32\nats21.exe
The following service names are used to hide the presence of nats21.exe:

SystemServiceHnet
HnetSystemService
TechnoHnetService
AdvancedHnexTechnic
ServiceTechnoSysHnex
HnexDesktop
sharesinDll32

This module has the same functionality as shareDll32. However, the Trickbot binary dropped by this module has the name nicossc.exe, and the URL it uses to get Trickbot is http[:]//185[.]142.99.26/image/sdocuprint.pdf. The service names are also different:

CseServiceControl
ControlServiceCse
BoxCseService
TechCseService
AdvanceCseService
ServiceCseControl
CseServiceTech
TechCseServiceControl
sqlscanDll32

This module tries to implement the SQLi vulnerability scanner. It receives list of target domains, and tries to extend it with subdomains by querying the Entrust web interface https[:]//ctsearch.entrust[.]com/api/v1/certificates?fields=subjectDN&domain=<targeted_doma in>&includeExpired=true&exactMatch=false&limit=100. It then performs multiple HTTP queries with malformed data on pages and forms of the targeted domains, measures the time or difference in responses in order to check if the targeted resource is potentially vulnerable.

squDll32

This module gathers addresses of SQL servers. It enumerates registry values at HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL to obtain SQL server instances. It also makes a broadcast UDP request on ports 1433 and 1434 to obtain SQL server instances from the SQL Server Browser service that usually runs on these ports. After gathering SQL server instances, it drops the submodule mailCollector and passes the collected targets to it.

squlDll32

This is an old version of squDll32. It uses SQLDMO.dll to enumerate the available SQL server instances.

tabDll32

This module propagates Trickbot via the EternalRomance exploit. It enables WDigest Authentication by modifying the UseLogonCredential value in the HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest registry key. This modification is forced to save credentials in lsass.exe memory (Local Security Authority Subsystem Service). The tabDll32 module then injects the embedded module screenLocker in explorer.exe and locks the workstation with the lock screen, forcing the user to login again. It waits for next user login and scrapes the credentials from LSASS memory utilizing Mimikatz functionality. Stolen credentials are sent back to the C2. After that tabDll32 downloads the payload from hardcoded URLs – usually the Trickbot loader (downloader) – starts up to 256 threads and uses the EternalRomance exploit to rapidly spread the downloaded payload over the network. Another embedded module, ssExecutor_x86, is used to set up persistence for the downloaded payload on exploited systems. This module also contains the main code of the shareDll32 module, and uses it to spread over the network.

The module ssExecutor_x86 copies the payload into the C:\WINDOWS\SYSTEM32\ and C:\WINDOWS\SYSTEM32\TASKS folders, and executes the payload. It enumerates user profiles in registry, copies the payload to C:\Users\<User Profile>\AppData\Roaming\ and establishes persistence by creating shortcuts in the profile’s Startup folder and creating a ‘Run’ key in the profile’s registry.

The tabDll32 module also exists in the form of a standalone executable with the alias ‘spreader’.

systeminfo32

This module gathers basic system information. It uses WQL to get information about the OS name, architecture, version, CPU and RAM information. It also collects user account names on the local computer and gathers information about installed software and services by enumerating HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall’ and ‘HKLM\SYSTEM\CurrentControlSet\Services registry keys.

vpnDll32

This module uses an RAS (Remote Access Service) API to establish a VPN (Virtual Private Network) connection. The destination VPN server, and credentials for connection are provided by the C2’s command and configuration files.

webiDll32

This module is used to intercept activity related to banking websites in browsers. It uses web injects to steal financial information. In addition to typical static and dynamic injections, this modification also supports web injects in the Zeus format, and can modify pages on the client side

wormDll32

This module propagates Trickbot with the EternalBlue exploit. It enumerates computers using Network Management API and Active Directory Service Interfaces. It uses the EternalBlue exploit to inject shellcode in LSASS process memory. The injected shellcode downloads Trickbot from a hardcoded URL and executes it.


Description of other modules

Module	Description
adllog32	Debug version of adll32 module
bcClientDllNew32	Same as bcClientDll32
bcClientDllTestTest32	Same as bcClientDll32
bexecDll32	Same as aexecDll32
dpwgrab32	Same as tdpwgrab32
pwgrab32	Same as tdpwgrab32
pwgrabb32	Same as tdpwgrab32
sokinjectDll32	Same as injectDll32
tinjectDll32	Same as injectDll32
totinjectDll32	Same as injectDll32
mexecDll32	Same as aexecDll32
networknewDll32	Same as networkDll32
socksDll32	Same as NewBCtestnDll32
oimportDll32	Same as importDll32
onixDll32	Same as aexecDll32
pwgrab32	Same as dpwgrab32
pwgrabb32	Same as dpwgrab32
shadnewDll32	Same as anubisDll32
socksDll32	Same as NewBCtestnDll32
sokinjectDll32	Same as injectDll32
stabDll32	Same as tabDll32
tabtinDll32	Same as tabDll32
testtabDll32	Same as tabDll32
ttabDll32	Previous modification of tabDll32
timportDll32	Same as importDll32
tinjectDll32	Same as injectDll32
tnetworkDll32	Same as networkDll32
totinjectDll32	Same as injectDll32
tpwgrab32	Same as dpwgrab32
trdpscanDll32	Same as rdpscanDll32
tshareDll32	Same as shareDll32
ttabDll32	Same as tabDll32
tvncDll32	Same as bvncDll32
TwoBCtestDll32	Same as bcClientDll32
twormDll32	Same as wormDll32
wormwinDll32	Same as wormDll32
vncDll32	Same as bvncDll32
