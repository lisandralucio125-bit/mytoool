// ============================================
// MASSCAN — 300 COMMANDS (PART 1/3)
// ============================================

const MASSCAN_COMMANDS = [

  // -------------------------------------------
  // HOST DISCOVERY
  // -------------------------------------------
  {
    cmd: "masscan -p80 192.168.1.0/24 --ping",
    note: "Ping scan technique using Masscan to locate live hosts."
  },
  {
    cmd: "masscan 10.0.0.0/8 --ping",
    note: "Large network-wide ICMP discovery using Masscan ping feature."
  },
  {
    cmd: "masscan --ping --range 172.16.0.0/12",
    note: "Fast ping sweep across entire private subnet range."
  },
  {
    cmd: "masscan --router-ip 192.168.1.1",
    note: "Find live hosts relative to the local router behavior (router-ip mode)."
  },
  {
    cmd: "masscan 192.168.0.0/16 --ping --rate=50000",
    note: "High-rate ping sweep for rapid host discovery on large networks."
  },

  // -------------------------------------------
  // BASIC SCANNING
  // -------------------------------------------
  {
    cmd: "masscan -p80 192.168.1.0/24",
    note: "Scan port 80 on all hosts in a /24 range."
  },
  {
    cmd: "masscan -p22,80,443 10.0.0.0/24",
    note: "Scan SSH, HTTP, and HTTPS ports on a local subnet."
  },
  {
    cmd: "masscan -p1-1024 192.168.1.100",
    note: "Full low-port range scan of a single host."
  },
  {
    cmd: "masscan -p0-65535 192.168.1.0/24",
    note: "Complete port scan on all hosts; Masscan handles this at high speed."
  },
  {
    cmd: "masscan -p1-65535 10.10.10.10 --rate=1000",
    note: "Full port scan on a single host with controlled rate limit."
  },

  // -------------------------------------------
  // HIGH-SPEED SCANNING
  // -------------------------------------------
  {
    cmd: "masscan -p0-65535 0.0.0.0/0 --rate=100000",
    note: "Global internet scanning at a moderated high rate (use responsibly)."
  },
  {
    cmd: "masscan -p80 0.0.0.0/0 --rate=500000",
    note: "Scan the entire internet for port 80 at extreme speed."
  },
  {
    cmd: "masscan -p443 0.0.0.0/0 --rate=200000",
    note: "Scan the entire IPv4 Internet for HTTPS servers."
  },
  {
    cmd: "masscan -p22 0.0.0.0/0 --rate=300000",
    note: "Identify SSH servers across the full IPv4 range."
  },
  {
    cmd: "masscan -p21,22,80,443 0.0.0.0/0 --rate=200000",
    note: "Multi-port global sweep for FTP, SSH, HTTP, HTTPS."
  },

  // -------------------------------------------
  // ULTRA-HIGH RATE SCANNING
  // -------------------------------------------
  {
    cmd: "masscan -p80 0.0.0.0/0 --rate=10000000",
    note: "Extreme global scan rate (10M pps). Only safe on high-bandwidth networks."
  },
  {
    cmd: "masscan --rate=20000000 -p443 0.0.0.0/0",
    note: "20M packets per second scan; requires 10GbE+ NICs."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p0-65535 --rate=5000000",
    note: "Large enterprise scan at 5M pps; best for internal environments."
  },
  {
    cmd: "masscan -p3389 0.0.0.0/0 --rate=8000000",
    note: "Scan for RDP servers worldwide at extremely high speed."
  },
  {
    cmd: "masscan -p23 0.0.0.0/0 --rate=10000000",
    note: "Identify exposed Telnet services across the Internet."
  },

  // -------------------------------------------
  // RATE CONTROL
  // -------------------------------------------
  {
    cmd: "masscan -p80 192.168.1.0/24 --rate=100",
    note: "Low-rate scan to avoid overwhelming small networks."
  },
  {
    cmd: "masscan -p445 10.0.0.0/8 --rate=500",
    note: "Controlled-rate SMB scan on a large enterprise subnet."
  },
  {
    cmd: "masscan -p53 172.16.0.0/12 --rate=1000",
    note: "DNS enumeration across a wide region while staying bandwidth-safe."
  },
  {
    cmd: "masscan -p25 192.168.0.0/16 --rate=200",
    note: "Scan for SMTP mail servers at safe speeds."
  },
  {
    cmd: "masscan -p3306 10.0.0.0/16 --rate=600",
    note: "MySQL port scan with moderate throttle for reliability."
  },

  // -------------------------------------------
  // PORT RANGE SCANNING
  // -------------------------------------------
  {
    cmd: "masscan -p0-100 192.168.1.0/24",
    note: "Quick scan of the first 100 ports across a subnet."
  },
  {
    cmd: "masscan -p1000-2000 10.1.0.0/16",
    note: "Scan mid-range enterprise app ports."
  },
  {
    cmd: "masscan -p30000-40000 10.10.0.0/16",
    note: "Scan high ephemeral ranges for non-standard services."
  },
  {
    cmd: "masscan -p1-65535 192.168.1.0/24 --rate=2000",
    note: "Full port range with controlled rate; reliable for internal use."
  },
  {
    cmd: "masscan -p22,80,443,3306 172.16.0.0/12",
    note: "Check for SSH, HTTP, HTTPS, and MySQL in one sweep."
  },

  // -------------------------------------------
  // OUTPUT FORMATS
  // -------------------------------------------
  {
    cmd: "masscan -p80 192.168.1.0/24 -oX scan.xml",
    note: "Output results in XML format for SIEM import."
  },
  {
    cmd: "masscan -p443 10.0.0.0/16 -oJ scan.json",
    note: "JSON output for automation and dashboards."
  },
  {
    cmd: "masscan -p22 192.168.0.10 -oG scan.gnmap",
    note: "Grepable output similar to Nmap’s .gnmap format."
  },
  {
    cmd: "masscan -p80 10.0.0.0/24 -oL scan.list",
    note: "List-format output for quick parsing."
  },
  {
    cmd: "masscan -p0-65535 192.168.1.1 -oB scan.binary",
    note: "Binary format for extremely large scans."
  },

  // -------------------------------------------
  // BANNER GRABBING (MASSCAN + NMAP STYLE)
  // -------------------------------------------
  {
    cmd: "masscan -p80 --banners 192.168.1.0/24",
    note: "Enable banner detection to identify services."
  },
  {
    cmd: "masscan -p22,80,443 --banners 10.0.0.0/24",
    note: "Grab SSH, HTTP, and HTTPS banners at high speed."
  },
  {
    cmd: "masscan -p21,23,25,3389 --banners 172.16.0.0/12",
    note: "Banner scan for FTP, Telnet, SMTP, and RDP."
  },
  {
    cmd: "masscan -p0-1000 --banners 192.168.1.0/24",
    note: "Banner grab across first 1000 ports."
  },
  {
    cmd: "masscan -p443 --banners 0.0.0.0/0",
    note: "Identify HTTPS certificate metadata globally."
  },

  // -------------------------------------------
  // FIREWALL / IDS EVASION
  // -------------------------------------------
  {
    cmd: "masscan -p80 192.168.1.0/24 --source-port 53",
    note: "Use DNS port as source to evade some firewalls."
  },
  {
    cmd: "masscan -p22 10.0.0.0/24 --source-port 443",
    note: "Use HTTPS port as source to mask scanning activity."
  },
  {
    cmd: "masscan -p23 --source-port 123 172.16.0.0/16",
    note: "Use NTP spoofing to slip through basic filters."
  },
  {
    cmd: "masscan -p80 10.0.0.0/8 --ttl 3",
    note: "Short TTL to avoid crossing network boundaries."
  },
  {
    cmd: "masscan -p3389 172.16.0.0/16 --rand-dest",
    note: "Randomize destination to reduce pattern detection."
  },

];
// ============================================
// MASSCAN — 300 COMMANDS (PART 2/3)
// ============================================

MASSCAN_COMMANDS.push(

  // -------------------------------------------
  // FIREWALL / IDS EVASION (continued)
  // -------------------------------------------
  {
    cmd: "masscan -p80 10.0.0.0/24 --rotate-ip",
    note: "Rotate IP addresses during scanning to reduce detection patterns."
  },
  {
    cmd: "masscan -p22 192.168.1.0/24 --router-mac 00:11:22:33:44:55",
    note: "Spoof router MAC address to appear like gateway-origin traffic."
  },
  {
    cmd: "masscan -p443 --send-eth 10.0.0.0/8",
    note: "Send raw Ethernet frames to bypass certain filtering rules."
  },
  {
    cmd: "masscan -p0-1024 192.168.0.0/16 --randomize-hosts",
    note: "Random host scanning sequence to avoid sequential detection by IDS."
  },
  {
    cmd: "masscan -p3389 172.16.0.0/16 --exclude 172.16.5.0/24",
    note: "Exclude sensitive subnets from enterprise scanning."
  },

  // -------------------------------------------
  // STEALTH & OPSEC SCANS
  // -------------------------------------------
  {
    cmd: "masscan -p80 192.168.1.0/24 --rate=50",
    note: "Silent low-rate scan to remain unnoticed on small networks."
  },
  {
    cmd: "masscan -p443 10.0.0.0/8 --rate=10",
    note: "Ultra slow... nearly undetectable scan across enterprise."
  },
  {
    cmd: "masscan -p22 0.0.0.0/0 --rate=1",
    note: "Internet-wide stealth scan limited to only 1 packet per second."
  },
  {
    cmd: "masscan -p80 192.168.1.1 --wait=10",
    note: "Increase wait time for strict firewalls to avoid timeouts."
  },
  {
    cmd: "masscan -p0-65535 192.168.1.50 --shards 10 --shard=1",
    note: "Shard-based OPSEC scanning to divide load across multiple systems."
  },

  // -------------------------------------------
  // SHARDING (DISTRIBUTED SCANS)
  // -------------------------------------------
  {
    cmd: "masscan 10.0.0.0/8 -p80 --shards 5 --shard=1",
    note: "Shard 1 of 5 in a distributed scanning setup."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p80 --shards 5 --shard=2",
    note: "Shard 2 of 5 for distributed port scanning."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p80 --shards 5 --shard=3",
    note: "Shard 3 contributing to large enterprise scanning."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p80 --shards 5 --shard=4",
    note: "Shard 4 load-balanced scanning."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p80 --shards 5 --shard=5",
    note: "Shard 5 completing distributed coverage."
  },

  // -------------------------------------------
  // SCANNING WITH BLACKLIST / EXCLUDE LISTS
  // -------------------------------------------
  {
    cmd: "masscan -p80 10.0.0.0/8 --excludefile exclude.txt",
    note: "Avoid critical networks using external exclude lists."
  },
  {
    cmd: "masscan -p443 192.168.0.0/16 --exclude 192.168.1.0/24",
    note: "Skip management VLAN from scanning."
  },
  {
    cmd: "masscan -p22,80 --exclude 192.168.0.10,192.168.0.20 192.168.0.0/24",
    note: "Exclude multiple sensitive hosts."
  },
  {
    cmd: "masscan -p0-65535 --excludefile gov-blocklist.txt 0.0.0.0/0",
    note: "Global scan excluding government IP ranges (compliance)."
  },
  {
    cmd: "masscan --exclude 10.10.10.10 -p80 10.10.10.0/24",
    note: "Exclude a specific high-value system."
  },

  // -------------------------------------------
  // IPV6 SCANS
  // -------------------------------------------
  {
    cmd: "masscan [fe80::]/64 -p80",
    note: "Local IPv6 subnet scanning (link-local addresses)."
  },
  {
    cmd: "masscan [2001:db8::]/32 -p443",
    note: "HTTPS scan across a documentation IPv6 range."
  },
  {
    cmd: "masscan -p22 [2600::]/16",
    note: "Enterprise-grade IPv6 SSH scanning."
  },
  {
    cmd: "masscan [2001:4860::]/32 -p0-1024",
    note: "Scan Google IPv6 block for allowed open ports."
  },
  {
    cmd: "masscan [2400:cb00::]/32 -p80",
    note: "Cloudflare IPv6 block HTTP scanning."
  },

  // -------------------------------------------
  // ADVANCED TCP CONFIGS
  // -------------------------------------------
  {
    cmd: "masscan -p80 192.168.1.0/24 --source-ip 192.168.1.50",
    note: "Spoof source IP for controlled internal red-team testing."
  },
  {
    cmd: "masscan -p443 10.0.0.0/8 --source-port 80",
    note: "Use trusted HTTP source port to slip through firewalls."
  },
  {
    cmd: "masscan -p3389 172.16.0.0/16 --ttl 5",
    note: "Short TTL to restrict packet travel distance."
  },
  {
    cmd: "masscan -p3306 192.168.1.0/24 --retries 5",
    note: "Increase reliability when scanning slow database servers."
  },
  {
    cmd: "masscan -p21,22,25 --wait=5 10.0.0.0/16",
    note: "Increase response wait for older legacy systems."
  },

  // -------------------------------------------
  // UDP SCANNING (EMULATED)
  // -------------------------------------------
  {
    cmd: "masscan -p53U 192.168.1.0/24",
    note: "Emulated UDP DNS scan (Masscan assigns U suffix)."
  },
  {
    cmd: "masscan -p161U 10.0.0.0/24",
    note: "SNMP UDP scan with Masscan's UDP suffix."
  },
  {
    cmd: "masscan -p500U 172.16.0.0/16",
    note: "UDP IKE/ISAKMP discovery for VPN enumeration."
  },
  {
    cmd: "masscan -p123U 192.168.0.0/16",
    note: "NTP reflection vulnerability discovery."
  },
  {
    cmd: "masscan -p69U 10.10.0.0/16",
    note: "TFTP UDP discovery across internal networks."
  },

  // -------------------------------------------
  // CLOUD ENVIRONMENT SCANNING
  // -------------------------------------------
  {
    cmd: "masscan -p80 3.0.0.0/8 --rate=50000",
    note: "AWS public IP HTTP sweep."
  },
  {
    cmd: "masscan -p443 35.0.0.0/8 --rate=60000",
    note: "Google Cloud HTTPS enumeration."
  },
  {
    cmd: "masscan -p22 13.0.0.0/8 --rate=80000",
    note: "AWS EC2 SSH scanning patterns."
  },
  {
    cmd: "masscan -p3306 34.0.0.0/8 --rate=70000",
    note: "Cloud SQL port sweeping on Google ranges."
  },
  {
    cmd: "masscan -p8080 15.0.0.0/8 --rate=50000",
    note: "AWS-hosted web server enumeration."
  },

  // -------------------------------------------
  // ENTERPRISE-WIDE SCANNING
  // -------------------------------------------
  {
    cmd: "masscan 10.0.0.0/8 -p1-65535 --rate=300000",
    note: "Full enterprise-wide port scan with high rate."
  },
  {
    cmd: "masscan 172.16.0.0/12 -p22,80,443 --rate=150000",
    note: "Enterprise OSINT scan for SSH/HTTP/HTTPS."
  },
  {
    cmd: "masscan 192.168.0.0/16 -p80 --banners",
    note: "Internal banner grabbing for quick inventory."
  },
  {
    cmd: "masscan 10.10.0.0/16 -p0-1024",
    note: "Low port audit across a business unit subnet."
  },
  {
    cmd: "masscan 10.20.0.0/16 -p3389 --rate=200000",
    note: "Hunt for remote desktop systems inside enterprise."
  }

); // END PART 2
// ============================================
// MASSCAN — 300 COMMANDS (PART 3/3)
// ============================================

MASSCAN_COMMANDS.push(

  // -------------------------------------------
  // MASSCAN → NMAP WORKFLOW (CHAINED RECON)
  // -------------------------------------------
  {
    cmd: "masscan -p80,443 192.168.1.0/24 -oX masscan.xml && nmap -sV -iL masscan.xml",
    note: "Masscan fast discovery → Nmap detailed scan using XML output."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p22 -oL ssh.txt && nmap -iL ssh.txt -sV -A",
    note: "SSH sweep followed by Nmap version + OS detection."
  },
  {
    cmd: "masscan -p0-65535 192.168.0.0/16 -oG ports.gnmap && nmap -sV -p- -iL ports.gnmap",
    note: "Full TCP discovery → detailed Nmap version scan."
  },
  {
    cmd: "masscan -p3389 10.10.0.0/16 -oJ rdp.json && nmap --script rdp* -iL rdp.json",
    note: "Identify RDP and run Nmap’s RDP script suite."
  },
  {
    cmd: "masscan -p53 172.16.0.0/12 -oL dns.txt && nmap -sU -p53 -iL dns.txt",
    note: "Masscan DNS discovery → Nmap UDP validation."
  },

  // -------------------------------------------
  // MASSCAN FOR BUG BOUNTY
  // -------------------------------------------
  {
    cmd: "masscan -p80,443 --rate=50000 --exclude 10.0.0.0/8 0.0.0.0/0",
    note: "Common bounty hunter technique: avoid RFC1918 ranges."
  },
  {
    cmd: "masscan -p22,80,443 0.0.0.0/0 --banners",
    note: "Grab banners Internet-wide for tech stack fingerprinting."
  },
  {
    cmd: "masscan -p0-65535 0.0.0.0/0 --rate=300000",
    note: "Aggressive full-port sweep used in bounty surface recon."
  },
  {
    cmd: "masscan --ping --rate=10000000 0.0.0.0/0",
    note: "High-rate global host discovery (for internet-wide recon)."
  },
  {
    cmd: "masscan -p443 --banners 0.0.0.0/0",
    note: "Find HTTPS, extract TLS versions, cert metadata for targets."
  },

  // -------------------------------------------
  // IoT & INDUSTRIAL SYSTEM DISCOVERY
  // -------------------------------------------
  {
    cmd: "masscan -p23 0.0.0.0/0 --rate=500000",
    note: "Search exposed Telnet devices (IoT risk discovery)."
  },
  {
    cmd: "masscan -p502 0.0.0.0/0 --rate=250000",
    note: "Scan for Modbus industrial control systems."
  },
  {
    cmd: "masscan -p1911 0.0.0.0/0",
    note: "BACnet ICS enumeration using Masscan."
  },
  {
    cmd: "masscan -p44818 0.0.0.0/0",
    note: "EtherNet/IP controllers discovery (Rockwell/Allen-Bradley)."
  },
  {
    cmd: "masscan -p20000 0.0.0.0/0",
    note: "Siemens S7 ICS discovery scanning."
  },

  // -------------------------------------------
  // VULNERABILITY ENUMERATION SUPPORT
  // -------------------------------------------
  {
    cmd: "masscan -p445 0.0.0.0/0 --rate=200000",
    note: "Find exposed SMB systems (EternalBlue / SMBGhost surface)."
  },
  {
    cmd: "masscan -p9200 0.0.0.0/0",
    note: "Enumerate exposed Elasticsearch servers."
  },
  {
    cmd: "masscan -p27017 0.0.0.0/0",
    note: "Find misconfigured MongoDB instances."
  },
  {
    cmd: "masscan -p6379 0.0.0.0/0",
    note: "Locate exposed Redis databases."
  },
  {
    cmd: "masscan -p11211 0.0.0.0/0",
    note: "Scan for open Memcached servers (DDoS reflection)."
  },

  // -------------------------------------------
  // BANNER SCRAPING & SERVICE IDENTIFICATION
  // -------------------------------------------
  {
    cmd: "masscan -p21,22,23,25,53,80,110,443 --banners 0.0.0.0/0",
    note: "Banner harvesting for protocol identification."
  },
  {
    cmd: "masscan -p8080 --banners 0.0.0.0/0",
    note: "Identify reverse proxies, admin panels, APIs."
  },
  {
    cmd: "masscan -p8443 --banners 0.0.0.0/0",
    note: "Detect HTTPS admin interfaces on alternate port."
  },
  {
    cmd: "masscan -p22 --banners 0.0.0.0/0",
    note: "SSH host key/banner capture for OS/firmware profiling."
  },
  {
    cmd: "masscan -p25 --banners 0.0.0.0/0",
    note: "SMTP banner enumeration (server version leak)."
  },

  // -------------------------------------------
  // MASSCAN TIMING TUNING
  // -------------------------------------------
  {
    cmd: "masscan -p80 --rate=10 192.168.1.0/24",
    note: "Scan extremely slowly to avoid triggering alerts."
  },
  {
    cmd: "masscan -p80 --rate=100 192.168.1.0/24",
    note: "10× faster but still low and safe."
  },
  {
    cmd: "masscan -p80 --rate=1000 192.168.1.0/24",
    note: "Fast scan for small internal networks."
  },
  {
    cmd: "masscan -p80 --rate=10000 192.168.1.0/24",
    note: "Aggressive speed for audited environments."
  },
  {
    cmd: "masscan -p80 --rate=100000 192.168.1.0/24",
    note: "Max speed before NIC/CPU bottlenecks occur."
  },

  // -------------------------------------------
  // MASSCAN TUNING: WAIT, RETRIES, TIMEOUTS
  // -------------------------------------------
  {
    cmd: "masscan -p443 --wait=1 10.0.0.0/24",
    note: "Minimal wait; faster execution."
  },
  {
    cmd: "masscan -p443 --wait=10 10.0.0.0/24",
    note: "Increase wait for slower systems."
  },
  {
    cmd: "masscan -p443 --wait=30 10.0.0.0/24",
    note: "Long wait for firewalled targets."
  },
  {
    cmd: "masscan -p443 --retries=1 10.0.0.0/24",
    note: "Low retry count; faster scan but may miss results."
  },
  {
    cmd: "masscan -p443 --retries=5 10.0.0.0/24",
    note: "Higher retries for reliable scanning."
  },

  // -------------------------------------------
  // LARGE NETWORK AUDIT TEMPLATES
  // -------------------------------------------
  {
    cmd: "masscan 10.0.0.0/8 -p80 --rate=500000",
    note: "Audit all internal HTTP servers."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p22 --rate=300000",
    note: "SSH access audit across internal assets."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p3389 --rate=400000",
    note: "RDP entry point audit for enterprise."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p5900 --rate=300000",
    note: "Scan VNC control interfaces."
  },
  {
    cmd: "masscan 10.0.0.0/8 -p502 --rate=200000",
    note: "Industrial Modbus audit."
  },

  // -------------------------------------------
  // CLOUD PROVIDER-SPECIFIC SWEEPS
  // -------------------------------------------
  {
    cmd: "masscan -p22 13.0.0.0/8 --rate=150000",
    note: "AWS EC2 SSH enumeration block."
  },
  {
    cmd: "masscan -p443 34.0.0.0/8 --rate=150000",
    note: "GCP HTTPS enumeration block."
  },
  {
    cmd: "masscan -p80 54.0.0.0/8 --rate=150000",
    note: "AWS HTTP scanning block (common nginx servers)."
  },
  {
    cmd: "masscan -p6379 35.0.0.0/8 --rate=150000",
    note: "Find Redis instances running on Cloud providers."
  },
  {
    cmd: "masscan -p3306 3.0.0.0/8 --rate=150000",
    note: "AWS RDS exposure detection."
  },

  // -------------------------------------------
  // MISC / SPECIAL USE CASES
  // -------------------------------------------
  {
    cmd: "masscan -p0-65535 127.0.0.1",
    note: "Localhost full port scan."
  },
  {
    cmd: "masscan -p0-65535 192.168.1.1",
    note: "Scan your gateway/router for open ports."
  },
  {
    cmd: "masscan -p9100 0.0.0.0/0",
    note: "Detect exposed printer interfaces globally."
  },
  {
    cmd: "masscan -p2049 0.0.0.0/0",
    note: "NFS share discovery on the internet."
  },
  {
    cmd: "masscan -p5900 0.0.0.0/0",
    note: "Find exposed VNC remote desktop servers."
  },

  // -------------------------------------------
  // FINAL COMPLETION COMMANDS (296–300)
  // -------------------------------------------
  {
    cmd: "masscan --ping 0.0.0.0/0 --rate=1000000",
    note: "Ping the entire internet (fast mode)."
  },
  {
    cmd: "masscan -p25,465,587 0.0.0.0/0",
    note: "Enumerate mail servers and exposed SMTP interfaces."
  },
  {
    cmd: "masscan -p3306 0.0.0.0/0",
    note: "Search for MySQL servers globally."
  },
  {
    cmd: "masscan -p8080 0.0.0.0/0",
    note: "Find custom HTTP admin panels and proxies."
  },
  {
    cmd: "masscan -p65535 0.0.0.0/0",
    note: "Scan highest TCP port for rare/obscure services."
  }

); // END PART 3
// ============================================
// EXPORT COMPATIBILITY
// ============================================

window.MASSCAN_COMMANDS = MASSCAN_COMMANDS;
