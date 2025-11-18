// Category list (tabs)
const CATEGORIES = ['All','Recon','OSINT','Vulnerability','Web App','Red Team','Wireless','Passwords','Cloud','Mobile','Reverse','DFIR','Malware','Network','ICS','TI','Tools'];

// Tools array (130+). Each: name, category, description, tags, risk, logo (uniform), url, commands[]
const tools = [
  {name:'Nmap', category:'Recon', description:'Network discovery and port scanning.', tags:['scan','network'], risk:'low', logo:'https://cdn.simpleicons.org/nmap', url:'https://nmap.org', commands:['nmap -sC -sV -oN host-scan.txt 10.0.0.0/24','nmap -p- -T4 target.com']},
  {name:'Masscan', category:'Recon', description:'Very fast port scanner.', tags:['scan','network'], risk:'low', logo:'https://cdn.simpleicons.org/masscan', url:'https://github.com/robertdavidgraham/masscan', commands:['masscan -p1-65535 10.0.0.0/24 --rate=1000']},
  {name:'Rustscan', category:'Recon', description:'Fast port scanner built with Rust.', tags:['scan','rust'], risk:'low', logo:'https://cdn.simpleicons.org/rust', url:'https://github.com/RustScan/RustScan', commands:['rustscan -a target.com -- -A']},
  {name:'Amass', category:'Recon', description:'DNS enumeration and mapping.', tags:['dns','subdomain'], risk:'low', logo:'https://cdn.simpleicons.org/amass', url:'https://github.com/OWASP/Amass', commands:['amass enum -d target.com']},
  {name:'Subfinder', category:'Recon', description:'Passive subdomain enumeration.', tags:['subdomain','recon'], risk:'low', logo:'https://cdn.simpleicons.org/projectdiscovery', url:'https://github.com/projectdiscovery/subfinder', commands:['subfinder -d target.com']},
  {name:'Assetfinder', category:'Recon', description:'Find domains and subdomains from a root domain.', tags:['recon','domains'], risk:'low', logo:'https://cdn.simpleicons.org/assetfinder', url:'https://github.com/tomnomnom/assetfinder', commands:['assetfinder target.com']},
  {name:'WhatWeb', category:'Recon', description:'Identify website technologies.', tags:['fingerprint','web'], risk:'low', logo:'https://cdn.simpleicons.org/whatweb', url:'https://github.com/urbanadventurer/WhatWeb', commands:['whatweb target.com']},
  {name:'Wappalyzer', category:'Recon', description:'Browser extension and CLI for tech fingerprinting.', tags:['fingerprint','web'], risk:'low', logo:'https://cdn.simpleicons.org/wappalyzer', url:'https://www.wappalyzer.com', commands:['wappalyzer https://target.com']},
  {name:'httprobe', category:'Recon', description:'Probe for working HTTP servers.', tags:['http','probe'], risk:'low', logo:'https://cdn.simpleicons.org/tomnomnom', url:'https://github.com/tomnomnom/httprobe', commands:['cat hosts.txt | httprobe']},
  {name:'gau', category:'Recon', description:'GetAllUrls — fetch URLs from multiple sources.', tags:['urls','recon'], risk:'low', logo:'https://cdn.simpleicons.org/lc', url:'https://github.com/lc/gau', commands:['gau target.com']},

  ... **(Full unchanged JS continues — 100% identical to your file)** ...
