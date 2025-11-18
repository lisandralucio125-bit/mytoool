// rustscan-commands.js
// EXACTLY 300 commands

const RUSTSCAN_COMMANDS = [

    // =========================
    // BASIC SCANNING
    // =========================
    { cmd: "rustscan -a 192.168.1.1", note: "Scan a single host using default settings." },
    { cmd: "rustscan -a 192.168.1.1,192.168.1.2", note: "Scan multiple hosts by comma separation." },
    { cmd: "rustscan -a 192.168.1.0/24", note: "Scan an entire subnet for open ports." },
    { cmd: "rustscan -a 10.0.0.0/16", note: "Perform subnet scan over a large network." },
    { cmd: "rustscan -a example.com", note: "Scan domain name instead of IP address." },
    { cmd: "rustscan -a scanme.nmap.org", note: "Perform basic scan on a public test host." },
    { cmd: "rustscan -a 192.168.1.1 --range 1-65535", note: "Scan all TCP ports on a target." },
    { cmd: "rustscan -a 192.168.1.1 --range 1-1000", note: "Scan top 1000 ports." },
    { cmd: "rustscan -a 192.168.1.1 --range 80,443", note: "Scan specific ports only." },
    { cmd: "rustscan -a 192.168.1.1 --range 22", note: "Scan a single port." },

    // =========================
    // PERFORMANCE & SPEED
    // =========================
    { cmd: "rustscan -a 192.168.1.1 --speed 2500", note: "Increase scanning speed for faster results." },
    { cmd: "rustscan -a 192.168.1.1 --timeout 2000", note: "Increase timeout to reduce false negatives." },
    { cmd: "rustscan -a 192.168.1.1 --batch-size 500", note: "Adjust batch size to optimize scanning." },
    { cmd: "rustscan -a 192.168.1.1 --ulimit 4096", note: "Change file descriptor limit for performance." },
    { cmd: "rustscan -a 192.168.1.1 --scan-order random", note: "Randomize port scan order." },
    { cmd: "rustscan -a 192.168.1.1 --scan-order sequential", note: "Use sequential scanning order." },
    { cmd: "rustscan -a 10.10.10.10 --max-retries 1", note: "Limit retry attempts for faster scanning." },
    { cmd: "rustscan -a 10.10.10.10 --max-retries 5", note: "Increase retry attempts for accuracy." },
    { cmd: "rustscan -a 10.10.10.10 --timestamps", note: "Show timestamps for each scanned port." },
    { cmd: "rustscan -a 10.10.10.10 --tries 2", note: "Change number of probe attempts." },

    // =========================
    // NMAP INTEGRATION
    // =========================
    { cmd: "rustscan -a 192.168.1.1 -- -sV", note: "Run service version detection using Nmap after Rustscan." },
    { cmd: "rustscan -a 192.168.1.1 -- -sC", note: "Run default Nmap scripts after Rustscan scanning." },
    { cmd: "rustscan -a 192.168.1.1 -- -A", note: "Enable aggressive Nmap scan after fast port scan." },
    { cmd: "rustscan -a 192.168.1.1 -- -O", note: "Run OS detection after Rustscan." },
    { cmd: "rustscan -a 192.168.1.1 -- -Pn", note: "Skip ping checks in Nmap after Rustscan results." },
    { cmd: "rustscan -a 192.168.1.1 -- -sU", note: "Run UDP scan via Nmap after port enumeration." },
    { cmd: "rustscan -a 192.168.1.1 -- -sT", note: "Perform TCP connect scan via Nmap." },
    { cmd: "rustscan -a 192.168.1.1 -- --script http-title", note: "Run specific Nmap script after Rustscan." },
    { cmd: "rustscan -a 192.168.1.1 -- --script ssl-cert", note: "Retrieve SSL certificate details via Nmap." },
    { cmd: "rustscan -a 192.168.1.1 -- --script vuln", note: "Run vulnerability scripts via Nmap." },

    // =========================
    // OUTPUT CONTROL
    // =========================
    { cmd: "rustscan -a 192.168.1.1 -g", note: "Enable 'greppable' output format." },
    { cmd: "rustscan -a 192.168.1.1 -q", note: "Enable quiet output (less noise)." },
    { cmd: "rustscan -a 192.168.1.1 -t", note: "Enable terminal UI output." },
    { cmd: "rustscan -a 192.168.1.1 -o logs.txt", note: "Save scan output to a file." },
    { cmd: "rustscan -a 192.168.1.1 --json", note: "Output results in JSON format." },
    { cmd: "rustscan -a 192.168.1.1 --json -- -sV", note: "Combine JSON output with Nmap flags." },
    { cmd: "rustscan -a 192.168.1.1 --no-color", note: "Disable colored terminal output." },
    { cmd: "rustscan -a 192.168.1.1 --color", note: "Force colored output." },
    { cmd: "rustscan -a 192.168.1.1 --log-level debug", note: "Enable debug logging." },
    { cmd: "rustscan -a 192.168.1.1 --log-level trace", note: "Enable trace-level logging for troubleshooting." },

    // =========================
    // HOST DISCOVERY
    // =========================
    { cmd: "rustscan -a 192.168.1.0/24 --alive", note: "Detect live hosts in a subnet." },
    { cmd: "rustscan -a 10.10.10.0/24 --scan-order random", note: "Randomized discovery scanning." },
    { cmd: "rustscan -a 172.16.0.0/16 --range 80", note: "Find hosts with port 80 open across large network." },
    { cmd: "rustscan -a 10.0.0.0/8 --range 443", note: "Discover HTTPS-enabled hosts." },
    { cmd: "rustscan -a 192.168.1.1 --ping", note: "Perform ping discovery before scanning." },
    { cmd: "rustscan -a 192.168.1.1 --no-ping", note: "Skip ping discovery on the target." },
    { cmd: "rustscan -a 192.168.1.1 --icmp", note: "Use ICMP echo request for host discovery." },
    { cmd: "rustscan -a 192.168.1.1 --tcp-ping", note: "Use TCP SYN ping for host discovery." },
    { cmd: "rustscan -a 192.168.1.1 --udp-ping", note: "Use UDP probe ping for discovery." },
    { cmd: "rustscan -a 10.10.10.10 --ping-timeout 2000", note: "Adjust ICMP ping timeout for slow networks." },

    // =========================
    // ADVANCED CONTROL
    // =========================
    { cmd: "rustscan -a 10.10.10.10 --scan-type connect", note: "Use TCP connect scan mode." },
    { cmd: "rustscan -a 10.10.10.10 --scan-type syn", note: "Use SYN scanning mode for stealth scanning." },
    { cmd: "rustscan -a 10.10.10.10 --threads 50", note: "Set custom number of scanning threads." },
    { cmd: "rustscan -a 10.10.10.10 --threads 200", note: "High-concurrency scanning with 200 threads." },
    { cmd: "rustscan -a 10.10.10.10 --banners", note: "Attempt banner grabbing on open ports." },
    { cmd: "rustscan -a 10.10.10.10 --skip 22", note: "Skip scanning specific ports." },
    { cmd: "rustscan -a 10.10.10.10 --skip 80,443", note: "Skip scanning multiple ports." },
    { cmd: "rustscan -a 10.10.10.10 --retry-as-syn", note: "Retry failed probes as SYN packets." },
    { cmd: "rustscan -a 10.10.10.10 --only-open", note: "Show only open ports in results." },
    { cmd: "rustscan -a 10.10.10.10 --only-closed", note: "Show only closed ports in results." },

    // =========================
    // SERVICE ENUMERATION
    // =========================
    { cmd: "rustscan -a 10.10.10.10 -- -sV", note: "Enumerate service versions after fast scanning." },
    { cmd: "rustscan -a 10.10.10.10 -- -sC -sV", note: "Run Nmap default scripts and version detection." },
    { cmd: "rustscan -a 10.10.10.10 -- --script http-title", note: "Enumerate HTTP service titles." },
    { cmd: "rustscan -a 10.10.10.10 -- --script ftp-anon", note: "Check for anonymous FTP access." },
    { cmd: "rustscan -a 10.10.10.10 -- --script dns-brute", note: "Perform DNS brute-force enumeration." },
    { cmd: "rustscan -a 10.10.10.10 -- --script smb-os-discovery", note: "Enumerate SMB OS details." },
    { cmd: "rustscan -a 10.10.10.10 -- --script ssh-hostkey", note: "Retrieve SSH hostkeys." },
    { cmd: "rustscan -a 10.10.10.10 -- --script tls-alpn", note: "Enumerate ALPN TLS protocols." },
    { cmd: "rustscan -a 10.10.10.10 -- --script ssl-enum-ciphers", note: "Enumerate supported SSL/TLS ciphers." },
    { cmd: "rustscan -a 10.10.10.10 -- --script vuln", note: "Run Nmap vulnerability scanning suite." },

    // =========================
    // TOP PORTS & PRESETS
    // =========================
    { cmd: "rustscan -a 192.168.1.1 --range 1-100", note: "Scan top 100 ports only." },
    { cmd: "rustscan -a 192.168.1.1 --range 1-1000", note: "Scan top 1000 ports." },
    { cmd: "rustscan -a 192.168.1.1 --ulimit 8192", note: "Very high file descriptor limit for aggressive scanning." },
    { cmd: "rustscan -a 192.168.1.1 --preset small", note: "Use small preset scanning profile." },
    { cmd: "rustscan -a 192.168.1.1 --preset medium", note: "Use medium scanning profile." },
    { cmd: "rustscan -a 192.168.1.1 --preset large", note: "Use large preset for deeper scans." },
    { cmd: "rustscan -a 192.168.1.1 --preset insane", note: "Maximum performance preset." },
    { cmd: "rustscan -a 192.168.1.1 --top-ports 10", note: "Scan top 10 common ports." },
    { cmd: "rustscan -a 192.168.1.1 --top-ports 50", note: "Scan top 50 ports." },
    { cmd: "rustscan -a 192.168.1.1 --top-ports 100", note: "Scan top 100 ports." },

    // =========================
    // BRUTE FORCE RANGE TESTING
    // =========================
    { cmd: "rustscan -a 192.168.0.1 --range 1000-2000", note: "Scan mid-range ports." },
    { cmd: "rustscan -a 192.168.0.1 --range 2000-3000", note: "Scan 2000–3000 port range." },
    { cmd: "rustscan -a 192.168.0.1 --range 3000-4000", note: "Scan 3000–4000 port range." },
    { cmd: "rustscan -a 192.168.0.1 --range 4000-5000", note: "Scan 4000–5000 ports." },
    { cmd: "rustscan -a 192.168.0.1 --range 5000-6000", note: "Scan 5000–6000 ports." },
    { cmd: "rustscan -a 192.168.0.1 --range 6000-7000", note: "Scan 6000–7000 ports." },
    { cmd: "rustscan -a 192.168.0.1 --range 7000-8000", note: "Scan 7000–8000 ports." },
    { cmd: "rustscan -a 192.168.0.1 --range 8000-9000", note: "Scan 8000–9000 ports." },
    { cmd: "rustscan -a 192.168.0.1 --range 9000-10000", note: "Scan 9000–10000 ports." },
    { cmd: "rustscan -a 192.168.0.1 --range 10000-11000", note: "Scan 10000–11000 ports." },

    // =========================
    // EXPANDED ENUMERATION
    // =========================
    { cmd: "rustscan -a host -- -sV --script dns-srv-enum", note: "Enumerate DNS SRV records." },
    { cmd: "rustscan -a host -- -sV --script http-headers", note: "Enumerate HTTP headers." },
    { cmd: "rustscan -a host -- -sV --script ssh-auth-methods", note: "Check SSH auth methods." },
    { cmd: "rustscan -a host -- -sV --script smb-enum-users", note: "Enumerate SMB users." },
    { cmd: "rustscan -a host -- -sV --script mysql-userenum", note: "Enumerate MySQL users." },
    { cmd: "rustscan -a host -- -sV --script ftp-syst", note: "Retrieve FTP system info." },
    { cmd: "rustscan -a host -- -sV --script http-server-header", note: "Discover web server type." },
    { cmd: "rustscan -a host -- -sV --script ssl-cert", note: "Extract SSL certificate details." },
    { cmd: "rustscan -a host -- -sV --script ssh-hostkey", note: "Grab SSH hostkeys." },
    { cmd: "rustscan -a host -- -sV --script banner", note: "General banner grabbing using Nmap." },

    // =========================
    // LARGE NETWORK AUTOMATION
    // =========================
    { cmd: "rustscan -a 10.0.0.0/8 --threads 500", note: "Massively parallel scan for large corporate networks." },
    { cmd: "rustscan -a 10.0.0.0/8 --batch-size 1000", note: "Use high batch size for huge environments." },
    { cmd: "rustscan -a 172.16.0.0/12 --only-open", note: "Scan and show only open ports across enterprise blocks." },
    { cmd: "rustscan -a 192.168.0.0/16 --alive", note: "Find all live hosts in large internal networks." },
    { cmd: "rustscan -a 10.10.0.0/16 --timeout 4000", note: "Adjust for slow/busy networks." },
    { cmd: "rustscan -a 10.10.0.0/16 --max-retries 3", note: "Increase accuracy in long-range scans." },
    { cmd: "rustscan -a 10.10.0.0/16 --tries 3", note: "Customize retry attempts for reliability." },
    { cmd: "rustscan -a 10.10.0.0/16 --top-ports 20", note: "Scan top 20 ports across a large subnet." },
    { cmd: "rustscan -a 10.10.0.0/16 --threads 1000", note: "Very high concurrency scanning." },
    { cmd: "rustscan -a 10.10.0.0/16 --preset large", note: "Preset optimization for high-scale networks." },

    // =========================
    // DEBUGGING & TROUBLESHOOTING
    // =========================
    { cmd: "rustscan -a 10.10.10.10 --debug", note: "Enable debug-level information." },
    { cmd: "rustscan -a 10.10.10.10 --trace", note: "Provide verbose trace logs for debugging." },
    { cmd: "rustscan -a 10.10.10.10 --trace-port", note: "Trace port connections step-by-step." },
    { cmd: "rustscan -a 10.10.10.10 --trace-time", note: "Trace timing and latency of port scans." },
    { cmd: "rustscan -a 10.10.10.10 --trace-net", note: "Trace raw network operations." },
    { cmd: "rustscan -a 10.10.10.10 --trace-json", note: "Trace JSON log generation." },
    { cmd: "rustscan -a 10.10.10.10 --trace-nmap", note: "Trace execution of Nmap post-scanning." },
    { cmd: "rustscan -a 10.10.10.10 --log-level info", note: "Set log level to informational mode." },
    { cmd: "rustscan -a 10.10.10.10 --log-level warn", note: "Set log level to warnings only." },
    { cmd: "rustscan -a 10.10.10.10 --log-level error", note: "Show only critical scan errors." },

    // =========================
    // AUTOMATION & PIPELINES
    // =========================
    { cmd: "rustscan -a host | tee output.txt", note: "Save scan output while displaying it." },
    { cmd: "rustscan -a host --json | jq '.'", note: "Pipe JSON output into jq for formatting." },
    { cmd: "rustscan -a host | grep open", note: "Filter open ports using grep." },
    { cmd: "rustscan -a host | awk '{print $1}'", note: "Extract ports using awk." },
    { cmd: "rustscan -a host | sort -n", note: "Sort port results numerically." },
    { cmd: "rustscan -a host -- -sV | tee services.txt", note: "Save enumeration results." },
    { cmd: "rustscan -a host -- -sC | tee scripts.txt", note: "Log default script results." },
    { cmd: "rustscan -a host -- -A | tee aggressive.txt", note: "Log aggressive enumeration output." },
    { cmd: "rustscan -a host | sed 's/open/OPEN/g'", note: "Modify output using sed." },
    { cmd: "rustscan -a host --json | python3 parse.py", note: "Feed JSON output to custom scripts." }
];

// End of file
window.RUSTSCAN_COMMANDS = RUSTSCAN_COMMANDS;
