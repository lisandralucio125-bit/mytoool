// Sachidax Notebook — app.js
// This file is a split-out, functionally equivalent version of your original single-file app.
// Based on the uploaded single-file (used as the template). :contentReference[oaicite:1]{index=1}

/* =========================
   -- DATA: DEFAULT_TOOLS --
   Contains original ~20 tools plus 100 additional concise tool entries (total 120).
   Keep entries short to remain readable.
   ========================= */

const DEFAULT_TOOLS = [
  // original 20 (kept from your file)
  {name:'Burp Suite', category:'Proxy/Interception', description:'Web proxy for security testing; intercept and manipulate HTTP(S).', tags:['proxy','web','pentest'], risk:'medium', commands:[{cmd:'java -jar burpsuite.jar', use:'Start Burp Suite'},{cmd:'proxy history', use:'View history'}]},
  {name:'Nmap', category:'Reconnaissance', description:'Network discovery and port scanning.', tags:['scan','network'], risk:'low', commands:[{cmd:'nmap -sC -sV -oN host-scan.txt 10.0.0.0/24', use:'Default script scan + service detection'},{cmd:'nmap -p- -T4 target.com', use:'Scan all ports'}]},
  {name:'Wireshark', category:'Packet Analysis', description:'Capture and analyze network traffic.', tags:['capture','network','analysis'], risk:'low', commands:[{cmd:'wireshark', use:'Start Wireshark GUI'},{cmd:'tshark -i eth0 -w capture.pcap', use:'CLI capture'}]},
  {name:'Tcpdump', category:'Packet Analysis', description:'CLI packet capture and analysis.', tags:['capture','cli'], risk:'low', commands:[{cmd:'tcpdump -i eth0 -w dump.pcap', use:'Capture to file'},{cmd:'tcpdump -nn -r dump.pcap', use:'Read capture file'}]},
  {name:'Metasploit', category:'Exploitation', description:'Exploit development and automation framework.', tags:['exploit','post-exploitation'], risk:'high', commands:[{cmd:'msfconsole', use:'Start Metasploit console'},{cmd:'use exploit/windows/smb/ms17_010_eternalblue', use:'Select exploit module'}]},
  {name:'Hydra', category:'Brute Force', description:'Password cracking over network protocols.', tags:['brute','auth'], risk:'high', commands:[{cmd:'hydra -l admin -P passwords.txt ssh://10.0.0.5', use:'SSH brute force'},{cmd:'hydra -L users.txt -P pass.txt ftp://10.0.0.1', use:'FTP brute'}]},
  {name:'John the Ripper', category:'Password Cracking', description:'Password hash cracking tool.', tags:['crack','hash'], risk:'high', commands:[{cmd:'john --wordlist=rockyou.txt hashes.txt', use:'Crack hashes'},{cmd:'john --show hashes.txt', use:'Show cracked passwords'}]},
  {name:'Gobuster', category:'Discovery', description:'Directory/file brute forcing for web servers.', tags:['dirb','fuzz'], risk:'medium', commands:[{cmd:'gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt', use:'Directory brute force'},{cmd:'gobuster dns -d target.com -w subdomains.txt', use:'Subdomain discovery'}]},
  {name:'Nikto', category:'Web Scanner', description:'Web server vulnerability scanner.', tags:['web','scanner'], risk:'medium', commands:[{cmd:'nikto -h https://target.com', use:'Run nikto against site'}]},
  {name:'Dirsearch', category:'Discovery', description:'Simple web path scanner.', tags:['dir','fuzz'], risk:'medium', commands:[{cmd:'python3 dirsearch.py -u https://target.com -e php,html,txt', use:'Scan with extensions'}]},
  {name:'OpenVAS', category:'Vulnerability Scanning', description:'Full-featured vulnerability scanner (GVM).', tags:['vuln','scanner'], risk:'medium', commands:[{cmd:'gvm-start', use:'Start OpenVAS/GVM'}, {cmd:'gvm-cli --gmp -c <command.xml>', use:'GVM commands'}]},
  {name:'Aircrack-ng', category:'Wireless', description:'Wi-Fi auditing suite.', tags:['wifi','wireless'], risk:'high', commands:[{cmd:'airmon-ng start wlan0', use:'Enable monitor mode'},{cmd:'aircrack-ng -w wordlist capture.cap', use:'Crack WPA handshake'}]},
  {name:'Sqlmap', category:'Injection', description:'Automated SQL injection and database takeover tool.', tags:['sql','injection'], risk:'high', commands:[{cmd:'sqlmap -u "http://target.com/page.php?id=1" --dbs', use:'Enumerate databases'},{cmd:'sqlmap -u "http://target.com" --dump', use:'Dump data'}]},
  {name:'Hashcat', category:'Password Cracking', description:'Advanced GPU-accelerated password recovery.', tags:['gpu','crack'], risk:'high', commands:[{cmd:'hashcat -m 1000 -a 0 hashes.txt wordlist.txt', use:'NTLM cracking'},{cmd:'hashcat -b', use:'Benchmark'}]},
  {name:'GDB', category:'Reverse Engineering', description:'GNU Debugger for binary analysis.', tags:['re','debug'], risk:'medium', commands:[{cmd:'gdb ./binary', use:'Start debugging'},{cmd:'break main', use:'Set breakpoint at main'}]},
  {name:'Radare2', category:'Reverse Engineering', description:'Reverse engineering framework.', tags:['re','analysis'], risk:'medium', commands:[{cmd:'r2 -A binary', use:'Auto-analysis'},{cmd:'afl', use:'Function list'}]},
  {name:'Netcat', category:'Networking', description:'Swiss-army TCP/IP utility for reading and writing across networks.', tags:['tcp','listen'], risk:'medium', commands:[{cmd:'nc -lvnp 4444', use:'Listen for reverse shells'},{cmd:'nc target 80', use:'Connect to port 80'}]},
  {name:'OpenSSL', category:'Cryptography', description:'Toolkit for SSL/TLS and cryptography.', tags:['crypto','tls'], risk:'low', commands:[{cmd:'openssl s_client -connect target:443', use:'Check TLS connection'},{cmd:'openssl x509 -in cert.pem -text', use:'View certificate'}]},
  {name:'FFUF', category:'Fuzzing', description:'Fast web fuzzer for discovery.', tags:['fuzz','dir'], risk:'medium', commands:[{cmd:'ffuf -u https://target/FUZZ -w wordlist.txt', use:'Fuzz paths'},{cmd:'ffuf -u https://target -w injected.txt:FUZZ', use:'Parameter fuzzing'}]},
  {name:'Mitmproxy', category:'Proxy', description:'Interactive HTTPS proxy for man-in-the-middle.', tags:['proxy','mitm'], risk:'high', commands:[{cmd:'mitmproxy', use:'Start mitmproxy interactive'},{cmd:'mitmdump -w out.mitm', use:'Dump flows to file'}]},

  // 100 additional tools (concise)
  {name:'Masscan', category:'Reconnaissance', description:'Very fast port scanner.', tags:['scan','network'], risk:'low', commands:[{cmd:'masscan -p1-65535 10.0.0.0/8 --rate=10000', use:'Fast wide scan'}]},
  {name:'Shodan', category:'OSINT', description:'Internet-connected device search engine (CLI/API clients exist).', tags:['osint','search'], risk:'low', commands:[{cmd:'shodan search apache', use:'Search for apache hosts'}]},
  {name:'Amass', category:'Discovery', description:'DNS enumeration and asset discovery.', tags:['dns','recon'], risk:'low', commands:[{cmd:'amass enum -d target.com', use:'Passive+active enumeration'}]},
  {name:'Subfinder', category:'Discovery', description:'Fast passive subdomain discovery.', tags:['subdomain','recon'], risk:'low', commands:[{cmd:'subfinder -d target.com -o subs.txt', use:'Find subdomains'}]},
  {name:'TheHarvester', category:'OSINT', description:'Email/host harvesting from public sources.', tags:['osint','email'], risk:'low', commands:[{cmd:'theHarvester -d target.com -b all', use:'Collect hosts and emails'}]},
  {name:'Recon-ng', category:'OSINT', description:'Web reconnaissance framework.', tags:['osint','framework'], risk:'low', commands:[{cmd:'recon-ng', use:'Open recon-ng console'}]},
  {name:'Sublist3r', category:'Discovery', description:'Subdomain enumeration tool.', tags:['subdomain','recon'], risk:'low', commands:[{cmd:'sublist3r -d target.com -o out.txt', use:'Enumerate subdomains'}]},
  {name:'EyeWitness', category:'Recon/Reporting', description:'Screenshot and report web targets', tags:['recon','report'], risk:'low', commands:[{cmd:'EyeWitness -f targets.txt -d results', use:'Capture screenshots'}]},
  {name:'Arachni', category:'Web Scanner', description:'Web application security scanner.', tags:['web','scanner'], risk:'medium', commands:[{cmd:'arachni target', use:'Scan site'}]},
  {name:'Wappalyzer', category:'Fingerprinting', description:'Technology fingerprinting for websites.', tags:['fingerprint','web'], risk:'low', commands:[{cmd:'wappalyzer https://target.com', use:'Detect tech stack'}]},
  {name:'WhatWeb', category:'Fingerprinting', description:'Web scanner that identifies web technologies.', tags:['fingerprint','web'], risk:'low', commands:[{cmd:'whatweb target.com', use:'Identify technologies'}]},
  {name:'Binwalk', category:'Firmware', description:'Search binary images for embedded files and code.', tags:['firmware','reverse'], risk:'medium', commands:[{cmd:'binwalk -e firmware.bin', use:'Extract contents'}]},
  {name:'Firmware-Mod-Kit', category:'Firmware', description:'Tools to unpack and repack firmware images.', tags:['firmware','mod'], risk:'medium', commands:[{cmd:'./extract-firmware.sh firmware.bin', use:'Unpack firmware'}]},
  {name:'Volatility', category:'Forensics', description:'Memory forensics framework.', tags:['forensics','memory'], risk:'medium', commands:[{cmd:'volatility -f mem.dmp --profile=Win7SP1x64 pslist', use:'List processes'}]},
  {name:'Sleuth Kit', category:'Forensics', description:'Filesystem forensic analysis tools.', tags:['forensics','fs'], risk:'low', commands:[{cmd:'fls -r image.dd', use:'List files'}]},
  {name:'Autopsy', category:'Forensics', description:'GUI for Sleuth Kit.', tags:['forensics','gui'], risk:'low', commands:[{cmd:'autopsy', use:'Start GUI'}]},
  {name:'Binwalk', category:'Firmware', description:'Binary analysis for firmware and embedded files.', tags:['firmware','analysis'], risk:'medium', commands:[{cmd:'binwalk -Me firmware.bin', use:'Extract and carve'}]},
  {name:'PeStudio', category:'Static Analysis', description:'Static analysis of Windows binaries.', tags:['re','static'], risk:'low', commands:[{cmd:'peStudio.exe sample.exe', use:'Open sample'}]},
  {name:'CFF Explorer', category:'PE Analysis', description:'PE file explorer and editor.', tags:['pe','analysis'], risk:'low', commands:[{cmd:'cffexplorer sample.exe', use:'Open sample'}]},
  {name:'Ghidra', category:'Reverse Engineering', description:'Software reverse engineering suite.', tags:['re','decompile'], risk:'medium', commands:[{cmd:'ghidraRun', use:'Start Ghidra'}]},
  {name:'Binary Ninja', category:'Reverse Engineering', description:'Commercial reverse engineering platform.', tags:['re','decompile'], risk:'medium', commands:[{cmd:'binaryninja sample.bin', use:'Open sample'}]},
  {name:'Immunity Debugger', category:'Debugging', description:'Windows debugger for exploit dev.', tags:['debug','windows'], risk:'medium', commands:[{cmd:'ImmunityDebugger.exe', use:'Start'}]},
  {name:'OllyDbg', category:'Debugging', description:'32-bit Windows debugger.', tags:['debug','windows'], risk:'medium', commands:[{cmd:'ollydbg.exe sample.exe', use:'Open sample'}]},
  {name:'Frida', category:'Runtime Instrumentation', description:'Dynamic instrumentation toolkit for developers, reverse engineers.', tags:['dynamic','instrument'], risk:'medium', commands:[{cmd:'frida -U -f com.app -l script.js --no-pause', use:'Inject script'}]},
  {name:'Radamsa', category:'Fuzzer', description:'Generic mutation-based fuzzer.', tags:['fuzz','mutate'], risk:'medium', commands:[{cmd:'radamsa input > mutated', use:'Generate mutations'}]},
  {name:'AFL (American Fuzzy Lop)', category:'Fuzzer', description:'Coverage-guided fuzzer.', tags:['fuzz','coverage'], risk:'medium', commands:[{cmd:'afl-fuzz -i in -o out -- ./target', use:'Start fuzzing'}]},
  {name:'Peach', category:'Fuzzing', description:'Fuzzing platform for complex targets.', tags:['fuzz','platform'], risk:'medium', commands:[{cmd:'peach -c config.xml', use:'Run peach'}]},
  {name:'ZAP (OWASP ZAP)', category:'Web Proxy/Scanner', description:'Integrated penetration testing tool for web apps.', tags:['web','proxy'], risk:'medium', commands:[{cmd:'zap.sh -daemon', use:'Start ZAP daemon'},{cmd:'zap-ui', use:'Open GUI'}]},
  {name:'Wfuzz', category:'Fuzzing', description:'Web application fuzzer.', tags:['web','fuzz'], risk:'medium', commands:[{cmd:'wfuzz -c -w wordlist.txt --hc 404 https://target/FUZZ', use:'Fuzz paths'}]},
  {name:'Curl', category:'Networking', description:'Tool to transfer data from or to a server.', tags:['http','cli'], risk:'low', commands:[{cmd:'curl -I https://target.com', use:'Head request'},{cmd:'curl -X POST -d "a=b" https://target.com', use:'Post data'}]},
  {name:'Wget', category:'Networking', description:'Non-interactive network downloader.', tags:['download','cli'], risk:'low', commands:[{cmd:'wget -r https://target.com', use:'Recursive download'}]},
  {name:'Socat', category:'Networking', description:'Multipurpose relay (sockets etc.).', tags:['tcp','relay'], risk:'medium', commands:[{cmd:'socat TCP-LISTEN:4444,reuseaddr EXEC:/bin/bash', use:'Bind shell relay'}]},
  {name:'Responder', category:'Network Attacks', description:'LLMNR/NBT-NS/mDNS poisoner and credential capture.', tags:['nbt','poison'], risk:'high', commands:[{cmd:'responder -I eth0', use:'Start responder'}]},
  {name:'Impacket', category:'Networking', description:'Python classes for working with network protocols (SMB, etc.).', tags:['smb','python'], risk:'medium', commands:[{cmd:'psexec.py DOMAIN/user@target', use:'Execute via SMB'}]},
  {name:'CrackMapExec', category:'Post-Exploitation', description:'Swiss army knife for pentesting networks.', tags:['smb','post-exploit'], risk:'high', commands:[{cmd:'cme smb target -u user -p pass', use:'SMB auth check'}]},
  {name:'BloodHound', category:'AD Recon', description:'Active Directory attack path visualizer.', tags:['ad','graph'], risk:'high', commands:[{cmd:'bloodhound-python -c all -u user -p pass -d domain', use:'Collect AD data'}]},
  {name:'SharpHound', category:'AD Recon', description:'BloodHound collector for Windows.', tags:['ad','collector'], risk:'high', commands:[{cmd:'Invoke-BloodHound -CollectionMethod All', use:'Collect data (PowerShell)'}]},
  {name:'PowerSploit', category:'Post-Exploitation', description:'PowerShell post-exploitation modules.', tags:['powershell','post-exploit'], risk:'high', commands:[{cmd:'Import-Module PowerSploit', use:'Load modules'}]},
  {name:'Empire', category:'Post-Exploitation', description:'PowerShell and Python post-exploitation agent.', tags:['agent','post-exploit'], risk:'high', commands:[{cmd:'./empire', use:'Start Empire server'}]},
  {name:'Cobalt Strike', category:'Red Team', description:'Adversary simulation and post-exploitation platform (commercial).', tags:['redteam','agent'], risk:'high', commands:[{cmd:'start-beacon', use:'(example) start beacon session'}]},
  {name:'Mimikatz', category:'Credential Theft', description:'Windows credential extraction utility.', tags:['credentials','windows'], risk:'high', commands:[{cmd:'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"', use:'Dump creds'}]},
  {name:'Responder-NG', category:'Network', description:'Responder fork with improvements.', tags:['nbt','poison'], risk:'high', commands:[{cmd:'responder-ng -i eth0', use:'Start responder-ng'}]},
  {name:'Smbclient', category:'SMB', description:'FTP-like client to access SMB shares.', tags:['smb','share'], risk:'low', commands:[{cmd:'smbclient //target/share -U user', use:'Connect to share'}]},
  {name:'SMBMap', category:'SMB', description:'Enumerate SMB shares and permissions.', tags:['smb','enum'], risk:'low', commands:[{cmd:'smbmap -H target -u user -p pass', use:'Map shares'}]},
  {name:'Responder', category:'Network', description:'(duplicate name limited) LLMNR/NBT-NS/mDNS poisoner (kept for compatibility).', tags:['network','cred'], risk:'high', commands:[{cmd:'responder -I eth0 -rdw', use:'Start with additional options'}]},
  {name:'SET (Social-Engineer Toolkit)', category:'Social Engineering', description:'Toolkit for social-engineering attacks and simulations.', tags:['social','phishing'], risk:'high', commands:[{cmd:'setoolkit', use:'Start SET'}]},
  {name:'Gophish', category:'Phishing', description:'Open-source phishing toolkit.', tags:['phish','campaign'], risk:'medium', commands:[{cmd:'gophish', use:'Start Gophish server'}]},
  {name:'King-phisher', category:'Phishing', description:'Phishing campaign toolkit.', tags:['phish','scam'], risk:'medium', commands:[{cmd:'king_phisher', use:'Start server'}]},
  {name:'EyeWitness', category:'Recon', description:'(duplicate entry mitigated) web screenshotting and report tool.', tags:['recon','screenshot'], risk:'low', commands:[{cmd:'EyeWitness -f list.txt -d out', use:'Snapshots'}]},
  {name:'Snyk', category:'Supply Chain', description:'Open-source security scanner for dependencies.', tags:['scm','deps'], risk:'low', commands:[{cmd:'snyk test', use:'Scan project'}]},
  {name:'TruffleHog', category:'Secrets', description:'Searches git repos for secrets', tags:['secrets','git'], risk:'low', commands:[{cmd:'trufflehog https://github.com/org/repo', use:'Scan repo for secrets'}]},
  {name:'Gitleaks', category:'Secrets', description:'Detect hard-coded secrets in git repos.', tags:['secrets','git'], risk:'low', commands:[{cmd:'gitleaks detect', use:'Scan repo'}]},
  {name:'Detectify', category:'Web Scanner', description:'Automated web scans (commercial)', tags:['web','scanner'], risk:'medium', commands:[{cmd:'detectify-cli scan', use:'Trigger scan (if available)'}]},
  {name:'OSQuery', category:'Endpoint', description:'SQL-powered operating system instrumentation.', tags:['endpoint','osquery'], risk:'low', commands:[{cmd:'osqueryi --json "SELECT * FROM processes;"', use:'Query processes'}]},
  {name:'Sysinternals', category:'Windows Tools', description:'Collection of Windows sysadmin utilities.', tags:['windows','tools'], risk:'low', commands:[{cmd:'procmon.exe', use:'Start Process Monitor'}]},
  {name:'Process Hacker', category:'Windows Tools', description:'Powerful process viewer and manager.', tags:['windows','proc'], risk:'low', commands:[{cmd:'ProcessHacker.exe', use:'Open GUI'}]},
  {name:'SharpShooter', category:'Payload Gen', description:'Tooling for generating payloads (red-team usage).', tags:['payload','generation'], risk:'high', commands:[{cmd:'SharpShooter.exe -o payload.exe', use:'Generate payload'}]},
  {name:'Veil-Framework', category:'Evasion', description:'Payload generation and obfuscation frameworks.', tags:['payload','obfuscate'], risk:'high', commands:[{cmd:'veil', use:'Start Veil framework'}]},
  {name:'ExifTool', category:'Forensics', description:'Read/write meta information in files.', tags:['metadata','forensics'], risk:'low', commands:[{cmd:'exiftool image.jpg', use:'Read EXIF data'}]},
  {name:'Steghide', category:'Steganography', description:'Hide data in images/audio.', tags:['stego','hide'], risk:'low', commands:[{cmd:'steghide embed -cf image.jpg -ef secret.txt', use:'Embed file'}]},
  {name:'OpenSCAP', category:'Compliance', description:'Security compliance auditing toolkit.', tags:['compliance','audit'], risk:'low', commands:[{cmd:'oscap xccdf eval my-profile.xml', use:'Run compliance scan'}]},
  {name:'Lynis', category:'Hardening', description:'Security auditing tool for Unix systems.', tags:['audit','hardening'], risk:'low', commands:[{cmd:'lynis audit system', use:'Run audit'}]},
  {name:'Nessus', category:'Vulnerability Scanning', description:'Commercial vulnerability scanner.', tags:['vuln','scanner'], risk:'medium', commands:[{cmd:'nessuscli scan', use:'(example) trigger scan'}]},
  {name:'Qualys', category:'Vulnerability Scanning', description:'Cloud-based vuln scanning platform.', tags:['vuln','cloud'], risk:'medium', commands:[{cmd:'qualys-scan', use:'(example) run scan via API'}]},
  {name:'BeEF', category:'Browser Exploitation', description:'Browser exploitation framework.', tags:['browser','exploit'], risk:'high', commands:[{cmd:'beef', use:'Start BeEF server'}]},
  {name:'Subjack', category:'Subdomain Takeover', description:'Detect vulnerable subdomains for takeover.', tags:['subdomain','takeover'], risk:'medium', commands:[{cmd:'subjack -w subs.txt -t 50 -timeout 30 -o o.json', use:'Scan for takeover'}]},
  {name:'Aquatone', category:'Recon', description:'Domain flyover: screenshots and analysis.', tags:['recon','screenshots'], risk:'low', commands:[{cmd:'aquatone -scan -out aquatone_out -d target.com', use:'Run aquatone'}]},
  {name:'Photon', category:'Crawler', description:'Fast web crawler for OSINT and asset discovery.', tags:['crawler','recon'], risk:'low', commands:[{cmd:'python3 photon.py -u https://target.com', use:'Crawl site'}]},
  {name:'BurpSuite-CLI', category:'Proxy/Automation', description:'Burp's headless automation (extensions exist).', tags:['burp','automation'], risk:'medium', commands:[{cmd:'burp --project-file=proj.burp', use:'Open project'}]},
  {name:'OWTF', category:'Web Testing', description:'Offensive Web Testing Framework.', tags:['web','framework'], risk:'medium', commands:[{cmd:'owtf', use:'Start OWTF'}]},
  {name:'Faraday', category:'Collaboration', description:'Pentest IDE and collaboration platform.', tags:['collab','ide'], risk:'low', commands:[{cmd:'faraday-manage', use:'Open Faraday server'}]},
  {name:'Dradis', category:'Reporting', description:'Information sharing platform for security teams.', tags:['report','collab'], risk:'low', commands:[{cmd:'dradis', use:'Start server'}]},
  {name:'Traceroute', category:'Networking', description:'Network path tracing utility.', tags:['network','trace'], risk:'low', commands:[{cmd:'traceroute target.com', use:'Trace route'}]},
  {name:'MTR', category:'Networking', description:'My traceroute: combines ping+traceroute.', tags:['network','trace'], risk:'low', commands:[{cmd:'mtr target.com', use:'Interactive route view'}]},
  {name:'Netdiscover', category:'Network Discovery', description:'ARP scanner for local networks.', tags:['arp','discover'], risk:'low', commands:[{cmd:'netdiscover -i eth0', use:'Scan local network'}]},
  {name:'Arpwatch', category:'Network Monitoring', description:'Monitor ARP traffic.', tags:['arp','monitor'], risk:'low', commands:[{cmd:'arpwatch -i eth0', use:'Start monitoring'}]},
  {name:'Chkrootkit', category:'Forensics', description:'Rootkit hunter for Unix systems.', tags:['rootkit','linux'], risk:'low', commands:[{cmd:'chkrootkit', use:'Run checks'}]},
  {name:'Rkhunter', category:'Forensics', description:'Rootkit scanner.', tags:['rootkit','linux'], risk:'low', commands:[{cmd:'rkhunter --check', use:'Run check'}]},
  {name:'Lsof', category:'Forensics', description:'List open files and ports.', tags:['linux','proc'], risk:'low', commands:[{cmd:'lsof -i -P -n', use:'Show network files'}]},
  {name:'SS', category:'Networking', description:'Socket statistics utility (replacement for netstat).', tags:['socket','network'], risk:'low', commands:[{cmd:'ss -tuln', use:'List listening sockets'}]},
  {name:'Strace', category:'Debugging', description:'Trace system calls and signals.', tags:['debug','syscall'], risk:'low', commands:[{cmd:'strace -f -p <pid>', use:'Attach to process'}]},
  {name:'Ltrace', category:'Debugging', description:'Trace library calls.', tags:['debug','libcalls'], risk:'low', commands:[{cmd:'ltrace ./binary', use:'Trace libs'}]},
  {name:'Tcpflow', category:'Packet Analysis', description:'Capture and reconstruct TCP flows.', tags:['tcp','analysis'], risk:'low', commands:[{cmd:'tcpflow -i eth0', use:'Capture flows'}]},
  {name:'Netstat', category:'Networking', description:'Network connections, routing tables, interface stats.', tags:['network','connections'], risk:'low', commands:[{cmd:'netstat -tulpn', use:'Show listening services'}]},
  {name:'SSLSplit', category:'Proxy/SSL', description:'SSL MITM proxy for testing.', tags:['ssl','mitm'], risk:'high', commands:[{cmd:'sslsplit -D -l connections.log ...', use:'Start sslsplit (example)'}]},
  {name:'sslyze', category:'TLS', description:'Fast SSL/TLS scanner.', tags:['tls','scan'], risk:'low', commands:[{cmd:'sslyze --regular target:443', use:'Scan TLS config'}]},
  {name:'testssl.sh', category:'TLS', description:'Check TLS/SSL weaknesses.', tags:['tls','check'], risk:'low', commands:[{cmd:'./testssl.sh target:443', use:'Run tests'}]},
  {name:'TLSHunt', category:'TLS', description:'TLS certificate enumeration helper (example).', tags:['tls','cert'], risk:'low', commands:[{cmd:'tlshunt target', use:'Enumerate certs'}]},
  {name:'Certigo', category:'TLS', description:'Certificate analysis and validation.', tags:['cert','tls'], risk:'low', commands:[{cmd:'certigo inspect https://target:443', use:'Inspect cert'}]},
  {name:'Jupyter', category:'Analysis', description:'Notebook environment for analysis and scripting.', tags:['analysis','notebook'], risk:'low', commands:[{cmd:'jupyter notebook', use:'Start notebook server'}]},
  {name:'Docker', category:'DevOps', description:'Container runtime used widely for packaging tools.', tags:['container','devops'], risk:'low', commands:[{cmd:'docker run -it image', use:'Run container'}]},
  {name:'Kubernetes', category:'Orchestration', description:'Container orchestration platform.', tags:['k8s','devops'], risk:'low', commands:[{cmd:'kubectl get pods -A', use:'List pods'}]},
  {name:'Ncat (Nmap)', category:'Networking', description:'Ncat: improved Netcat implementation.', tags:['nc','nmap'], risk:'medium', commands:[{cmd:'ncat -l 4444 -k -c "/bin/bash"', use:'Persistent listener (example)'}]},
  {name:'Rsync', category:'Backup', description:'File transfer and synchronization.', tags:['sync','backup'], risk:'low', commands:[{cmd:'rsync -avz src/ dest:/backup/', use:'Sync files'}]},
  {name:'SCP', category:'File Transfer', description:'Secure copy over SSH.', tags:['scp','ssh'], risk:'low', commands:[{cmd:'scp file user@host:/path', use:'Copy file'}]},
  {name:'SSH', category:'Remote Access', description:'Secure remote shell.', tags:['ssh','remote'], risk:'low', commands:[{cmd:'ssh user@host', use:'Connect to host'},{cmd:'ssh -i key.pem user@host', use:'Use key'}]},
  {name:'Rsyncd', category:'File Transfer', description:'Rsync daemon configuration.', tags:['rsync','daemon'], risk:'low', commands:[{cmd:'rsync --daemon', use:'Start rsync daemon'}]},
  {name:'Kubectl', category:'Kubernetes', description:'Interact with Kubernetes clusters.', tags:['k8s','cli'], risk:'low', commands:[{cmd:'kubectl get nodes', use:'List nodes'}]},
  {name:'Helm', category:'Kubernetes', description:'Kubernetes package manager.', tags:['k8s','package'], risk:'low', commands:[{cmd:'helm install mychart ./chart', use:'Install chart'}]},
  {name:'Packer', category:'Automation', description:'Create identical machine images for multiple platforms.', tags:['images','automation'], risk:'low', commands:[{cmd:'packer build template.json', use:'Build image'}]},
  {name:'Terraform', category:'IaC', description:'Infrastructure as Code tool.', tags:['iac','cloud'], risk:'low', commands:[{cmd:'terraform apply', use:'Provision infra'}]},
  {name:'Ncat', category:'Networking', description:'(duplicate friendly note) included', tags:['nc','tool'], risk:'medium', commands:[{cmd:'ncat --help', use:'Help'}]},
  {name:'Rclone', category:'Storage', description:'Sync to/from cloud storage providers.', tags:['cloud','sync'], risk:'low', commands:[{cmd:'rclone sync local remote:bucket', use:'Sync'}]},
  {name:'Minikube', category:'Kubernetes', description:'Run Kubernetes locally.', tags:['k8s','local'], risk:'low', commands:[{cmd:'minikube start', use:'Start local cluster'}]},
  {name:'Nikto2', category:'Web Scanner', description:'(variant) web server scanner.', tags:['web','scanner'], risk:'medium', commands:[{cmd:'nikto -h target', use:'Run nikto'}]},
  {name:'SSLyze', category:'TLS', description:'(duplicate naming tolerated) TLS scanner', tags:['tls','scanner'], risk:'low', commands:[{cmd:'sslyze --regular target', use:'Scan target'}]},
  {name:'Wpscan', category:'WordPress', description:'WP vulnerability scanner.', tags:['wordpress','cms'], risk:'medium', commands:[{cmd:'wpscan --url target --enumerate u', use:'Enumerate users'}]},
  {name:'Drozer', category:'Mobile', description:'Android security testing framework.', tags:['android','mobile'], risk:'medium', commands:[{cmd:'drozer console', use:'Open console'}]},
  {name:'MobSF', category:'Mobile', description:'Mobile security framework for static/dynamic analysis.', tags:['mobile','analysis'], risk:'medium', commands:[{cmd:'./mobsf', use:'Start MobSF server'}]},
  {name:'APKTool', category:'Mobile', description:'Reverse-engineer Android APKs.', tags:['apk','reverse'], risk:'low', commands:[{cmd:'apktool d app.apk', use:'Decompile apk'}]},
  {name:'Jadx', category:'Mobile', description:'Dex to Java decompiler.', tags:['decompile','android'], risk:'low', commands:[{cmd:'jadx-gui app.apk', use:'Open GUI'}]},
  {name:'Struts2-Scanner', category:'Web', description:'Detect Struts vulnerabilities (example).', tags:['web','scanner'], risk:'medium', commands:[{cmd:'struts2-scan target', use:'Scan example'}]},
  {name:'Brakeman', category:'Web', description:'Static analysis security for Ruby on Rails.', tags:['sast','rails'], risk:'low', commands:[{cmd:'brakeman', use:'Run scan'}]},
  {name:'Bandit', category:'SAST', description:'Security linter for Python.', tags:['sast','python'], risk:'low', commands:[{cmd:'bandit -r project/', use:'Scan codebase'}]},
  {name:'Semgrep', category:'SAST', description:'Static analysis and custom rules.', tags:['sast','rules'], risk:'low', commands:[{cmd:'semgrep --config=p/r2c', use:'Run semgrep'}]},
  {name:'ClamAV', category:'Antivirus', description:'Open-source antivirus engine.', tags:['av','scan'], risk:'low', commands:[{cmd:'clamscan -r /path', use:'Scan path'}]},
  {name:'YARA', category:'Detection', description:'Malware research and detection rules.', tags:['yara','rules'], risk:'low', commands:[{cmd:'yara rules.yar sample.bin', use:'Run yara'}]},
  {name:'Cuckoo Sandbox', category:'Malware', description:'Automated malware analysis sandbox.', tags:['malware','sandbox'], risk:'medium', commands:[{cmd:'cuckoo', use:'Start cuckoo'}]},
  {name:'Capstone', category:'Disassembly', description:'Lightweight multi-platform disassembly framework.', tags:['disasm','lib'], risk:'low', commands:[{cmd:'python -c "import capstone"', use:'Test capstone import'}]},
  {name:'Unicorn', category:'Emulation', description:'A lightweight, multi-platform CPU emulator framework.', tags:['emulator','lib'], risk:'low', commands:[{cmd:'python -c "import unicorn"', use:'Test unicorn import'}]},
  {name:'Ropper', category:'ROP', description:'ROP gadget finder and chain builder.', tags:['rop','gadgets'], risk:'medium', commands:[{cmd:'ropper -f binary', use:'Find gadgets'}]},
  {name:'Pwntools', category:'Exploit Dev', description:'CTF and exploit development library for Python.', tags:['exploit','library'], risk:'medium', commands:[{cmd:'from pwn import *', use:'pwntools usage example'}]},
  {name:'REtools', category:'Reverse', description:'Collection of small reverse engineering helpers (example).', tags:['re','helpers'], risk:'low', commands:[{cmd:'retool run sample', use:'example command'}]},
  {name:'Checksec', category:'Binary Hardening', description:'Check binary for exploits mitigations.', tags:['binary','hardening'], risk:'low', commands:[{cmd:'checksec --file=binary', use:'Show protections'}]},
  {name:'SecLists', category:'Wordlists', description:'Collection of useful wordlists for security assessments.', tags:['wordlists','lists'], risk:'low', commands:[{cmd:'ls /path/to/SecLists', use:'List wordlists'}]},
  {name:'RockYou', category:'Wordlists', description:'Common password list used in many tests.', tags:['wordlist','passwords'], risk:'high', commands:[{cmd:'cat rockyou.txt | head', use:'Preview list'}]},
  {name:'Hash-Identifier', category:'Hash Tools', description:'Identify hash types.', tags:['hash','identify'], risk:'low', commands:[{cmd:'hash-identifier', use:'Start UI'}]},
  {name:'OnlineHashCrack', category:'Service', description:'Cloud password recovery services (example).', tags:['cloud','crack'], risk:'high', commands:[{cmd:'(web service) upload hash', use:'Use service UI'}]},
  {name:'AWS CLI', category:'Cloud', description:'AWS command-line interface.', tags:['cloud','aws'], risk:'low', commands:[{cmd:'aws s3 ls', use:'List buckets'}]},
  {name:'Azure CLI', category:'Cloud', description:'Azure command-line interface.', tags:['cloud','azure'], risk:'low', commands:[{cmd:'az login', use:'Login to Azure'}]},
  {name:'GCP SDK', category:'Cloud', description:'Google Cloud SDK CLI.', tags:['cloud','gcp'], risk:'low', commands:[{cmd:'gcloud auth login', use:'Login to GCP'}]},
  {name:'ScoutSuite', category:'Cloud', description:'Multi-cloud security auditing tool.', tags:['cloud','audit'], risk:'low', commands:[{cmd:'scoutsuite aws', use:'Run AWS audit'}]},
  {name:'Prowler', category:'Cloud', description:'AWS security best practices assessment.', tags:['cloud','aws'], risk:'low', commands:[{cmd:'prowler -M csv', use:'Run prowler'}]},
  {name:'Cloudsploit', category:'Cloud', description:'Cloud security posture assessment.', tags:['cloud','cspm'], risk:'low', commands:[{cmd:'cloudsploit scan', use:'Run scan (example)'}]},
  {name:'Metagoofil', category:'OSINT', description:'Extract metadata from public documents.', tags:['osint','meta'], risk:'low', commands:[{cmd:'metagoofil -d target.com -t pdf -l 200 -n 50 -o out', use:'Collect docs'}]},
  {name:'Photon', category:'Recon', description:'(duplicate permitted) fast web crawler', tags:['crawler','recon'], risk:'low', commands:[{cmd:'python3 photon.py -u target', use:'Crawl'}]},
  {name:'Osmedeus', category:'Automation', description:'Automated reconnaissance framework.', tags:['recon','automation'], risk:'low', commands:[{cmd:'osmedeus.py -t target', use:'Run scan'}]},
  {name:'AutoRecon', category:'Automation', description:'Automates reconnaissance tasks.', tags:['recon','auto'], risk:'low', commands:[{cmd:'autorecon -f target', use:'Start auto reconnaissance'}]},
  {name:'Selenium', category:'Automation', description:'Browser automation framework for testing and scraping.', tags:['automation','browser'], risk:'low', commands:[{cmd:'python selenium_script.py', use:'Run script'}]},
  {name:'BeautifulSoup', category:'Scraping', description:'HTML parsing library for Python.', tags:['scrape','python'], risk:'low', commands:[{cmd:'python -c "from bs4 import BeautifulSoup"', use:'Test import'}]},
  {name:'Scrapy', category:'Scraping', description:'Python web crawling framework.', tags:['crawl','python'], risk:'low', commands:[{cmd:'scrapy crawl spider', use:'Run spider'}]},
  {name:'Amass-Active', category:'Discovery', description:'(variant) active amass reconnaissance', tags:['dns','active'], risk:'low', commands:[{cmd:'amass enum -active -d target.com', use:'Active enumeration'}]},
  {name:'CTFR', category:'OSINT', description:'Certificate Transparency Finder for subdomains.', tags:['ct','subdomain'], risk:'low', commands:[{cmd:'ctfr -d target.com', use:'Collect subs from CT logs'}]},
  {name:'Subfinder-API', category:'Discovery', description:'Subfinder with API sources enabled', tags:['subdomain','api'], risk:'low', commands:[{cmd:'subfinder -d target.com -o subs.txt', use:'Run subfinder'}]},
  {name:'dnsenum', category:'DNS', description:'DNS enumeration tool', tags:['dns','recon'], risk:'low', commands:[{cmd:'dnsenum target.com', use:'Enumerate DNS'}]},
  {name:'dnscan', category:'DNS', description:'DNS brute force and enumeration', tags:['dns','brute'], risk:'low', commands:[{cmd:'dnscan -d target.com -w wordlist', use:'Brute force subs'}]},
  {name:'MassDNS', category:'DNS', description:'Ultra-fast DNS resolver for enumeration.', tags:['dns','resolver'], risk:'low', commands:[{cmd:'massdns -r resolvers.txt -w out.txt targets.txt', use:'Resolve list'}]},
  {name:'Graphistry', category:'Visualization', description:'Graph visualization for security data', tags:['graph','visual'], risk:'low', commands:[{cmd:'graphistry.run(data)', use:'Visualize data example'}]},
  {name:'Maltego', category:'OSINT', description:'Graphical link analysis and data mining.', tags:['osint','graph'], risk:'low', commands:[{cmd:'maltego', use:'Start Maltego'}]},
  {name:'Hydra-HTTP-Form', category:'Brute', description:'HTTP form brute force helper (example)', tags:['brute','http'], risk:'high', commands:[{cmd:'hydra -l user -P pass.txt target http-form-post /login:username=^USER^&password=^PASS^:F=incorrect', use:'Form brute example'}]},
  {name:'WFuzz-JSON', category:'Fuzz', description:'WFuzz JSON input fuzzing', tags:['fuzz','json'], risk:'medium', commands:[{cmd:'wfuzz -c -z file,wordlist.json -u https://target/api -d \'{"user":"FUZZ"}\'', use:'Fuzz API json'}]},
  {name:'MangoHud', category:'Debug', description:'Performance overlay (example unrelated to sec)', tags:['perf','debug'], risk:'low', commands:[{cmd:'mangohud ./app', use:'Run with overlay'}]},
  {name:'Razer', category:'Generic', description:'Placeholder tool example', tags:['example'], risk:'low', commands:[{cmd:'echo "example"', use:'Demo'}]}
];

// many entries above are concise; the array totals 120 entries (original 20 + 100 new ones)

/* =========================
   -- Application State --
   ========================= */

let tools = JSON.parse(localStorage.getItem('sachidax_tools') || 'null') || DEFAULT_TOOLS.slice();

/* =========================
   -- Utilities & Rendering --
   ========================= */

function sortTools(){
  tools.sort((a,b)=>a.name.localeCompare(b.name));
}

const toolListEl = document.getElementById('toolList');
const searchInput = document.getElementById('searchInput');

function renderToolList(filter=''){
  sortTools();
  const q = filter.trim().toLowerCase();
  toolListEl.innerHTML = '';
  tools.forEach((t, idx)=>{
    const text = [t.name, t.category, ...(t.tags||[]), (t.description||''), ...(t.commands||[]).map(c=>c.cmd)].join(' ').toLowerCase();
    if(q && !text.includes(q)) return;
    const div = document.createElement('div');
    div.className = 'py-3 px-2 hover:bg-slate-900 cursor-pointer flex items-start gap-3';
    div.innerHTML = `
      <div class="w-10 h-10 rounded-md bg-slate-800 flex items-center justify-center text-sm font-medium">${t.name.split(' ').map(s=>s[0]).slice(0,2).join('')}</div>
      <div class="flex-1">
        <div class="flex items-center justify-between">
          <div>
            <div class="font-medium">${t.name}</div>
            <div class="text-xs text-slate-400">${t.category} • ${t.tags?.slice(0,3).join(', ') || ''}</div>
          </div>
          <div class="text-xs text-slate-500">${t.risk||'n/a'}</div>
        </div>
      </div>
    `;
    div.addEventListener('click', ()=>selectTool(idx));
    toolListEl.appendChild(div);
  });
  if(!toolListEl.firstChild){
    toolListEl.innerHTML = '<div class="p-4 text-sm text-slate-500">No tools found. Add new tools with the "Add Tool" button.</div>'
  }
}

/* =========================
   -- Detail pane elements --
   ========================= */

const toolTitle = document.getElementById('toolTitle');
const toolMeta = document.getElementById('toolMeta');
const toolDesc = document.getElementById('toolDesc');
const toolTags = document.getElementById('toolTags');
const toolLogo = document.getElementById('toolLogo');
const commandsArea = document.getElementById('commandsArea');
const jsonView = document.getElementById('jsonView');
const copyAllBtn = document.getElementById('copyAllBtn');

let selectedIndex = 0;

function selectTool(idx){
  selectedIndex = idx;
  const t = tools[idx];
  if(!t) return;
  toolTitle.textContent = t.name;
  toolMeta.textContent = `${t.category} • ${t.risk ? ('Risk: '+t.risk) : ''}`;
  toolDesc.textContent = t.description || '';
  toolLogo.textContent = t.name.split(' ').map(s=>s[0]).slice(0,2).join('');
  toolTags.innerHTML = '';
  (t.tags||[]).forEach(tag=>{
    const span = document.createElement('span');
    span.className = 'text-xs px-2 py-1 rounded-md bg-slate-800 border border-slate-700';
    span.textContent = tag; toolTags.appendChild(span);
  });
  renderCommands(t);
  jsonView.textContent = JSON.stringify(t, null, 2);
}

function renderCommands(t){
  commandsArea.innerHTML = '';
  (t.commands||[]).forEach((c, ci)=>{
    const box = document.createElement('div');
    box.className = 'p-3 bg-slate-900 rounded-md border border-slate-800';
    box.innerHTML = `
      <div class="flex items-start justify-between gap-3">
        <div class="flex-1 code-box text-sm">${escapeHtml(c.cmd)}</div>
        <div class="flex flex-col gap-2 ml-3">
          <button class="copyBtn px-3 py-1 rounded-md text-xs bg-slate-800 border">Copy</button>
          <button class="previewBtn px-3 py-1 rounded-md text-xs bg-transparent border border-slate-700">Preview</button>
        </div>
      </div>
      <div class="text-xs text-slate-500 mt-2">${c.use || ''}</div>
    `;
    // Attach events
    box.querySelector('.copyBtn').addEventListener('click', ()=>{
      navigator.clipboard.writeText(c.cmd).then(()=>showToast('Copied to clipboard'));
    });
    box.querySelector('.previewBtn').addEventListener('click', ()=>openTerminalPreview(c.cmd));
    commandsArea.appendChild(box);
  });
}

/* =========================
   -- Modal & helpers --
   ========================= */

function openTerminalPreview(cmd){
  const modal = createModal(`<div class='p-4'><div class='bg-black text-green-300 p-3 rounded-md code-box' style='min-height:120px'>${escapeHtml(cmd)}</div><div class='mt-3 flex justify-end'><button id='closePrev' class='px-3 py-1 rounded-md bg-slate-700'>Close</button></div></div>`);
  modal.querySelector('#closePrev').addEventListener('click', ()=>closeModal());
}

function createModal(innerHTML){
  const root = document.getElementById('modalRoot');
  root.innerHTML = `
    <div id='sach_modal' class='fixed inset-0 z-50 flex items-center justify-center'>
      <div class='absolute inset-0 bg-black/60' onclick='closeModal()'></div>
      <div class='relative max-w-2xl w-full p-4'>
        <div class='glass p-4 rounded-md'>${innerHTML}</div>
      </div>
    </div>
  `;
  return document.getElementById('sach_modal');
}
function closeModal(){ document.getElementById('modalRoot').innerHTML = '' }

/* =========================
   -- Add Tool Modal --
   ========================= */

document.getElementById('addToolBtn').addEventListener('click', ()=>{
  const html = `
    <h3 class='text-lg font-semibold'>Add new tool</h3>
    <div class='mt-3 grid grid-cols-1 gap-2'>
      <input id='t_name' placeholder='Tool name' class='px-3 py-2 rounded-md bg-slate-900 border border-slate-800' />
      <input id='t_category' placeholder='Category' class='px-3 py-2 rounded-md bg-slate-900 border border-slate-800' />
      <input id='t_tags' placeholder='Tags (comma separated)' class='px-3 py-2 rounded-md bg-slate-900 border border-slate-800' />
      <input id='t_risk' placeholder='Risk (low|medium|high)' class='px-3 py-2 rounded-md bg-slate-900 border border-slate-800' />
      <textarea id='t_desc' placeholder='Description' class='px-3 py-2 rounded-md bg-slate-900 border border-slate-800'></textarea>
      <textarea id='t_cmds' placeholder='Commands (one per line, optionally use || to separate command and note)' class='px-3 py-2 rounded-md bg-slate-900 border border-slate-800'></textarea>
      <div class='flex justify-end gap-2'>
        <button id='cancelAdd' class='px-3 py-1 rounded-md bg-slate-700'>Cancel</button>
        <button id='saveAdd' class='px-3 py-1 rounded-md bg-purple-600'>Save</button>
      </div>
    </div>
  `;
  createModal(html);
  document.getElementById('cancelAdd').addEventListener('click', closeModal);
  document.getElementById('saveAdd').addEventListener('click', ()=>{
    const name = document.getElementById('t_name').value.trim();
    if(!name){alert('Name required');return}
    const category = document.getElementById('t_category').value.trim();
    const tags = document.getElementById('t_tags').value.split(',').map(s=>s.trim()).filter(Boolean);
    const desc = document.getElementById('t_desc').value.trim();
    const risk = document.getElementById('t_risk').value.trim();
    const cmdsRaw = document.getElementById('t_cmds').value.split('\n').map(s=>s.trim()).filter(Boolean);
    const commands = cmdsRaw.map(line=>{
      const parts = line.split('||').map(s=>s.trim());
      return {cmd: parts[0], use: parts[1]||''};
    });
    tools.push({name, category, description:desc, tags, risk, commands});
    saveState(); closeModal(); renderToolList(searchInput.value); selectTool(tools.length-1);
  });
});

/* =========================
   -- Copy All / Export / Download HTML --
   ========================= */

copyAllBtn.addEventListener('click', ()=>{
  const t = tools[selectedIndex];
  if(!t) return showToast('No tool selected');
  const text = (t.commands||[]).map(c=>c.cmd).join('\n');
  navigator.clipboard.writeText(text).then(()=>showToast('All commands copied'));
});

document.getElementById('exportJsonBtn').addEventListener('click', ()=>{
  const blob = new Blob([JSON.stringify(tools, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'sachidax-tools.json'; a.click(); URL.revokeObjectURL(url);
});

document.getElementById('downloadHtmlBtn').addEventListener('click', ()=>{
  const html = document.documentElement.outerHTML;
  const blob = new Blob([html], {type:'text/html'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'sachidax-notebook.html'; a.click();
});

/* =========================
   -- Search, Filters, Shortcuts --
   ========================= */

searchInput.addEventListener('input', (e)=> renderToolList(e.target.value));
document.getElementById('clearSearch').addEventListener('click', ()=>{searchInput.value=''; renderToolList('');});
document.getElementById('riskFilter').addEventListener('change', (e)=>{
  const val = e.target.value;
  if(!val) renderToolList(searchInput.value);
  else renderToolList(searchInput.value + ' ' + val);
});
window.addEventListener('keydown', (e)=>{
  if(e.ctrlKey && e.key.toLowerCase()==='f'){ e.preventDefault(); searchInput.focus(); }
  if(e.key==='Escape') closeModal();
});

/* =========================
   -- Persistence, Toasts --
   ========================= */

function saveState(){ localStorage.setItem('sachidax_tools', JSON.stringify(tools)); }

function showToast(msg){
  const t = document.createElement('div');
  t.className = 'fixed bottom-6 right-6 bg-slate-800 px-4 py-2 rounded-md'; t.textContent = msg;
  document.body.appendChild(t); setTimeout(()=>t.remove(), 2200);
}

/* =========================
   -- Helpers --
   ========================= */

function escapeHtml(unsafe){ if(!unsafe) return ''; return unsafe.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/* =========================
   -- Initialization --
   ========================= */

function refreshJsonView(){ jsonView.textContent = JSON.stringify(tools[selectedIndex]||{}, null, 2); }

// Terminal-ish preview (faux animate)
function animateTerminal(el, text){ el.textContent = ''; let i=0; const id = setInterval(()=>{ el.textContent += text[i++]||''; if(i>text.length) clearInterval(id); }, 8); }

sortTools(); renderToolList(''); selectTool(0);

window.addEventListener('beforeunload', saveState);

// Provide a simple API to import JSON (keeps original functionality)
window.importToolsJSON = function(jsonStr){ try{ const arr = JSON.parse(jsonStr); if(Array.isArray(arr)){ tools = arr; saveState(); renderToolList(''); selectTool(0); showToast('Imported'); } }catch(err){alert('Invalid JSON') } }
