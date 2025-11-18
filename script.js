/* script.js
   Extracted JS and enhanced with:
   - category heading popups
   - rainbow theme hooks (class use)
   - dynamic tool expansion form & handling
   - preserved original functionality (search, copy, preview, export, download)
*/

/* -------------------------
   Configuration / Category data
   ------------------------- */
const CATEGORIES = ['All','Recon','OSINT','Vulnerability','Web App','Red Team','Wireless','Passwords','Cloud','Mobile','Reverse','DFIR','Malware','Network','ICS','TI','Tools'];

/* Optional short descriptions for category popups.
   Add or edit descriptions here — used when clicking tabs.
*/
const CATEGORY_DESCRIPTIONS = {
  'All': 'Browse all tools across categories.',
  'Recon': 'Network and host discovery, port scanning, enumeration.',
  'OSINT': 'Open-source intelligence collection and analysis.',
  'Vulnerability': 'Scanning and vulnerability discovery tools.',
  'Web App': 'Web application testing and fuzzing tools.',
  'Red Team': 'Offensive tools for emulation and exploitation.',
  'Wireless': 'Wi-Fi auditing, sniffing and wireless-specific tooling.',
  'Passwords': 'Cracking and password recovery tools.',
  'Cloud': 'Cloud security and audit tools.',
  'Mobile': 'Mobile app analysis and instrumentation.',
  'Reverse': 'Reverse engineering and disassembly tools.',
  'DFIR': 'Digital forensics and incident response tooling.',
  'Malware': 'Sandboxing and malware analysis tools.',
  'Network': 'Packet capture, IDS/IPS, and monitoring.',
  'ICS': 'Industrial/SCADA focused testing frameworks.',
  'TI': 'Threat intelligence platforms.',
  'Tools': 'Utilities, editors, and developer tools.'
};

// ===============================
//  Tools Configuration
// ===============================

const tools = [
{
  name: 'Nmap',
  category: 'Recon',
  description: 'Network discovery and port scanning.',
  tags: ['scan','network'],
  risk: 'low',
  logo: 'https://cdn.simpleicons.org/nmap',
  url: 'https://nmap.org',
  // use external NMAP_COMMANDS array
  commands: NMAP_COMMANDS
},
  {name:'Masscan', category:'Recon', description:'Very fast port scanner.', tags:['scan','network'], risk:'low', logo:'https://cdn.simpleicons.org/masscan', url:'https://github.com/robertdavidgraham/masscan', commands:['masscan -p1-65535 10.0.0.0/24 --rate=1000']},
  {name:'Rustscan', category:'Recon', description:'Fast port scanner built with Rust.', tags:['scan','rust'], risk:'low', logo:'https://cdn.simpleicons.org/rust', url:'https://github.com/RustScan/RustScan', commands:['rustscan -a target.com -- -A']},
  {name:'Amass', category:'Recon', description:'DNS enumeration and mapping.', tags:['dns','subdomain'], risk:'low', logo:'https://cdn.simpleicons.org/amass', url:'https://github.com/OWASP/Amass', commands:['amass enum -d target.com']},
  {name:'Subfinder', category:'Recon', description:'Passive subdomain enumeration.', tags:['subdomain','recon'], risk:'low', logo:'https://cdn.simpleicons.org/projectdiscovery', url:'https://github.com/projectdiscovery/subfinder', commands:['subfinder -d target.com']},
  {name:'Assetfinder', category:'Recon', description:'Find domains and subdomains from a root domain.', tags:['recon','domains'], risk:'low', logo:'https://cdn.simpleicons.org/assetfinder', url:'https://github.com/tomnomnom/assetfinder', commands:['assetfinder target.com']},
  {name:'WhatWeb', category:'Recon', description:'Identify website technologies.', tags:['fingerprint','web'], risk:'low', logo:'https://cdn.simpleicons.org/whatweb', url:'https://github.com/urbanadventurer/WhatWeb', commands:['whatweb target.com']},
  {name:'Wappalyzer', category:'Recon', description:'Browser extension and CLI for tech fingerprinting.', tags:['fingerprint','web'], risk:'low', logo:'https://cdn.simpleicons.org/wappalyzer', url:'https://www.wappalyzer.com', commands:['wappalyzer https://target.com']},
  {name:'httprobe', category:'Recon', description:'Probe for working HTTP servers.', tags:['http','probe'], risk:'low', logo:'https://cdn.simpleicons.org/tomnomnom', url:'https://github.com/tomnomnom/httprobe', commands:['cat hosts.txt | httprobe']},
  {name:'gau', category:'Recon', description:'GetAllUrls — fetch URLs from multiple sources.', tags:['urls','recon'], risk:'low', logo:'https://cdn.simpleicons.org/lc', url:'https://github.com/lc/gau', commands:['gau target.com']},

  {name:'theHarvester', category:'OSINT', description:'Email/host harvesting from public sources.', tags:['osint','email'], risk:'low', logo:'https://cdn.simpleicons.org/theharvester', url:'https://github.com/laramies/theHarvester', commands:['theHarvester -d target.com -b google']},
  {name:'Maltego', category:'OSINT', description:'Link analysis and data mining.', tags:['osint','graph'], risk:'low', logo:'https://cdn.simpleicons.org/maltego', url:'https://www.maltego.com', commands:['Open Maltego GUI']},
  {name:'SpiderFoot', category:'OSINT', description:'Automated OSINT collection and analysis.', tags:['osint','automation'], risk:'low', logo:'https://cdn.simpleicons.org/spiderfoot', url:'https://www.spiderfoot.net', commands:['spiderfoot -l 127.0.0.1:5001']},
  {name:'Shodan', category:'OSINT', description:'Search engine for internet-connected devices.', tags:['osint','iot'], risk:'low', logo:'https://cdn.simpleicons.org/shodan', url:'https://www.shodan.io', commands:['Use Shodan web UI']},
  {name:'Censys', category:'OSINT', description:'Search engine for internet assets and certificates.', tags:['osint','cert'], risk:'low', logo:'https://cdn.simpleicons.org/censys', url:'https://censys.io', commands:['Use Censys web UI']},
  {name:'Recon-ng', category:'OSINT', description:'Modular OSINT framework.', tags:['osint','framework'], risk:'low', logo:'https://cdn.simpleicons.org/recon-ng', url:'https://github.com/lanmaster53/recon-ng', commands:['recon-ng']},

  {name:'Nessus', category:'Vulnerability', description:'Commercial vulnerability scanner.', tags:['vuln','scanner'], risk:'medium', logo:'https://cdn.simpleicons.org/tenable', url:'https://www.tenable.com/products/nessus', commands:['Open Nessus web UI']},
  {name:'OpenVAS (GVM)', category:'Vulnerability', description:'Open-source vulnerability scanner.', tags:['vuln','scanner'], risk:'medium', logo:'https://cdn.simpleicons.org/greenbone', url:'https://www.greenbone.net', commands:['gvm-start']},
  {name:'Nuclei', category:'Vulnerability', description:'Template-based fast scanner.', tags:['templates','scanner'], risk:'medium', logo:'https://cdn.simpleicons.org/projectdiscovery', url:'https://nuclei.projectdiscovery.io', commands:['nuclei -u https://target.com -t cves/']},

  {name:'Burp Suite', category:'Web App', description:'Web proxy and testing platform.', tags:['proxy','web'], risk:'medium', logo:'https://cdn.simpleicons.org/portswigger', url:'https://portswigger.net/burp', commands:['java -jar burpsuite.jar']},
  {name:'OWASP ZAP', category:'Web App', description:'Web application security scanner and proxy.', tags:['proxy','scanner'], risk:'medium', logo:'https://cdn.simpleicons.org/zaproxy', url:'https://www.zaproxy.org', commands:['zap.sh']},
  {name:'Nikto', category:'Web App', description:'Web server vulnerability scanner.', tags:['web','scanner'], risk:'medium', logo:'https://cdn.simpleicons.org/nikto', url:'https://cirt.net/Nikto2', commands:['nikto -h https://target.com']},
  {name:'Sqlmap', category:'Web App', description:'Automated SQL injection tool.', tags:['sql','injection'], risk:'high', logo:'https://cdn.simpleicons.org/sqlmap', url:'http://sqlmap.org', commands:['sqlmap -u "http://target.com/page.php?id=1" --dbs']},
  {name:'Dirsearch', category:'Web App', description:'Web path scanner.', tags:['dir','fuzz'], risk:'medium', logo:'https://cdn.simpleicons.org/dirsearch', url:'https://github.com/maurosoria/dirsearch', commands:['python3 dirsearch.py -u https://target.com -e php,html,txt']},
  {name:'Gobuster', category:'Web App', description:'Directory/file brute forcing.', tags:['dir','fuzz'], risk:'medium', logo:'https://cdn.simpleicons.org/ghost', url:'https://github.com/OJ/gobuster', commands:['gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt']},
  {name:'FFUF', category:'Web App', description:'Fast web fuzzer.', tags:['fuzz','web'], risk:'medium', logo:'https://cdn.simpleicons.org/ffuf', url:'https://github.com/ffuf/ffuf', commands:['ffuf -u https://target/FUZZ -w wordlist.txt']},

  {name:'Metasploit', category:'Red Team', description:'Exploit framework and automation.', tags:['exploit','post-exploit'], risk:'high', logo:'https://cdn.simpleicons.org/metasploit', url:'https://www.metasploit.com', commands:['msfconsole']},
  {name:'Cobalt Strike', category:'Red Team', description:'Commercial threat emulation platform.', tags:['c2','commercial'], risk:'high', logo:'https://cdn.simpleicons.org/cobaltstrike', url:'https://www.cobaltstrike.com', commands:['Open Cobalt Strike GUI']},
  {name:'Sliver', category:'Red Team', description:'Open-source C2 & post-exploitation.', tags:['c2','redteam'], risk:'high', logo:'https://cdn.simpleicons.org/bishopfox', url:'https://github.com/BishopFox/sliver', commands:['sliver-server']},
  {name:'Empire', category:'Red Team', description:'Post-exploitation agent framework.', tags:['post-exploit','windows'], risk:'high', logo:'https://cdn.simpleicons.org/empireproject', url:'https://github.com/EmpireProject/Empire', commands:['./empire']},
  {name:'CrackMapExec', category:'Red Team', description:'Post-exploitation toolkit for Windows.', tags:['lateral','post-exploit'], risk:'high', logo:'https://cdn.simpleicons.org/byt3bl33d3r', url:'https://github.com/byt3bl33d3r/CrackMapExec', commands:['cme smb target -u user -p pass']},
  {name:'BloodHound', category:'Red Team', description:'AD attack path analysis tool.', tags:['ad','graph'], risk:'high', logo:'https://cdn.simpleicons.org/bloodhound', url:'https://github.com/BloodHoundAD/BloodHound', commands:['Start BloodHound UI']},

  {name:'Aircrack-ng', category:'Wireless', description:'Wi-Fi auditing suite.', tags:['wifi','wireless'], risk:'high', logo:'https://cdn.simpleicons.org/aircrack-ng', url:'https://www.aircrack-ng.org', commands:['airmon-ng start wlan0','aircrack-ng -w wordlist capture.cap']},
  {name:'Reaver', category:'Wireless', description:'WPS brute force tool.', tags:['wps','wifi'], risk:'high', logo:'https://cdn.simpleicons.org/reaver', url:'https://github.com/t6x/reaver-wps', commands:['reaver -i mon0 -b BSSID -vv']},
  {name:'Kismet', category:'Wireless', description:'Wireless detector and sniffer.', tags:['wifi','sniffer'], risk:'low', logo:'https://cdn.simpleicons.org/kismet', url:'https://www.kismetwireless.net', commands:['kismet']},

  {name:'Hashcat', category:'Passwords', description:'GPU-accelerated password recovery.', tags:['gpu','crack'], risk:'high', logo:'https://cdn.simpleicons.org/hashcat', url:'https://hashcat.net/hashcat', commands:['hashcat -m 1000 -a 0 hashes.txt wordlist.txt']},
  {name:'John the Ripper', category:'Passwords', description:'Password hash cracking suite.', tags:['crack','hash'], risk:'high', logo:'https://cdn.simpleicons.org/openwall', url:'https://www.openwall.com/john/', commands:['john --wordlist=rockyou.txt hashes.txt']},
  {name:'Hydra', category:'Passwords', description:'Network login brute-forcer.', tags:['brute','auth'], risk:'high', logo:'https://cdn.simpleicons.org/hydra', url:'https://github.com/vanhauser-thc/thc-hydra', commands:['hydra -l admin -P passwords.txt ssh://10.0.0.5']},

  {name:'ScoutSuite', category:'Cloud', description:'Multi-cloud security auditing.', tags:['cloud','audit'], risk:'medium', logo:'https://cdn.simpleicons.org/scoutsuite', url:'https://github.com/nccgroup/ScoutSuite', commands:['scoutsuite aws --report-dir .']},
  {name:'Prowler', category:'Cloud', description:'AWS CIS benchmark checks.', tags:['cloud','aws'], risk:'medium', logo:'https://cdn.simpleicons.org/prowler', url:'https://github.com/prowler-cloud/prowler', commands:['prowler']},
  {name:'Pacu', category:'Cloud', description:'AWS exploitation framework.', tags:['aws','exploit'], risk:'high', logo:'https://cdn.simpleicons.org/pacu', url:'https://github.com/RhinoSecurityLabs/pacu', commands:['pacu']},

  {name:'MobSF', category:'Mobile', description:'Mobile security framework for Android/iOS.', tags:['mobile','static'], risk:'medium', logo:'https://cdn.simpleicons.org/mobsf', url:'https://mobsf.github.io', commands:['Start MobSF per docs']},
  {name:'Frida', category:'Mobile', description:'Dynamic instrumentation toolkit.', tags:['instrumentation','dynamic'], risk:'high', logo:'https://cdn.simpleicons.org/frida', url:'https://frida.re', commands:['frida -U -f com.app -l script.js --no-pause']},
  {name:'apktool', category:'Mobile', description:'Android app reverse engineering and rebuilding.', tags:['android','reverse'], risk:'medium', logo:'https://cdn.simpleicons.org/iancoleman', url:'https://ibotpeaches.github.io/Apktool/', commands:['apktool d app.apk']},

  {name:'Ghidra', category:'Reverse', description:'Open-source reverse engineering tool.', tags:['re','decompile'], risk:'medium', logo:'https://cdn.simpleicons.org/ghidra', url:'https://ghidra-sre.org', commands:['Launch Ghidra']},
  {name:'Radare2', category:'Reverse', description:'Reverse engineering framework.', tags:['re','analysis'], risk:'medium', logo:'https://cdn.simpleicons.org/radare', url:'https://rada.re/n', commands:['r2 -A binary']},
  {name:'IDA', category:'Reverse', description:'Interactive Disassembler.', tags:['re','disasm'], risk:'medium', logo:'https://cdn.simpleicons.org/hex-rays', url:'https://www.hex-rays.com', commands:['ida64 binary']},

  {name:'Autopsy', category:'DFIR', description:'Digital forensics platform.', tags:['forensics','dfir'], risk:'low', logo:'https://cdn.simpleicons.org/autopsy', url:'https://www.sleuthkit.org/autopsy', commands:['autopsy']},
  {name:'Volatility', category:'DFIR', description:'Memory forensics framework.', tags:['memory','dfir'], risk:'medium', logo:'https://cdn.simpleicons.org/volatility', url:'https://www.volatilityfoundation.org', commands:['volatility -f memdump.raw --profile=Win7SP1x64 pslist']},
  {name:'Velociraptor', category:'DFIR', description:'Endpoint monitoring & forensics.', tags:['dfir','endpoint'], risk:'medium', logo:'https://cdn.simpleicons.org/velociraptor', url:'https://www.velocidex.com/velociraptor', commands:['velociraptor -c config.yaml client']},

  {name:'Cuckoo Sandbox', category:'Malware', description:'Automated malware analysis sandbox.', tags:['malware','sandbox'], risk:'high', logo:'https://cdn.simpleicons.org/cuckoosandbox', url:'https://cuckoosandbox.org', commands:['cuckoo']},
  {name:'YARA', category:'Malware', description:'Rule-based malware identification.', tags:['yara','rules'], risk:'low', logo:'https://cdn.simpleicons.org/virustotal', url:'https://yara.readthedocs.io', commands:['yara rules.yar sample.bin']},
  {name:'Any.Run', category:'Malware', description:'Interactive online malware sandbox.', tags:['malware','online'], risk:'high', logo:'https://cdn.simpleicons.org/anyrun', url:'https://any.run', commands:['Use Any.Run web UI']},

  {name:'Wireshark', category:'Network', description:'Capture and analyze network traffic.', tags:['capture','network'], risk:'low', logo:'https://cdn.simpleicons.org/wireshark', url:'https://www.wireshark.org', commands:['wireshark','tshark -i eth0 -w capture.pcap']},
  {name:'Tcpdump', category:'Network', description:'CLI packet capture.', tags:['capture','cli'], risk:'low', logo:'https://cdn.simpleicons.org/iwlist', url:'https://www.tcpdump.org', commands:['tcpdump -i eth0 -w dump.pcap']},
  {name:'Ettercap', category:'Network', description:'MITM suite for LAN.', tags:['mitm','network'], risk:'high', logo:'https://cdn.simpleicons.org/ettercap', url:'https://ettercap.github.io', commands:['ettercap -T -M arp:remote']},

  {name:'Snort', category:'Network', description:'Open-source IDS.', tags:['ids','network'], risk:'low', logo:'https://cdn.simpleicons.org/snort', url:'https://www.snort.org', commands:['snort -c /etc/snort/snort.conf -i eth0']},
  {name:'Suricata', category:'Network', description:'High-performance IDS/IPS.', tags:['ids','network'], risk:'low', logo:'https://cdn.simpleicons.org/suricata', url:'https://suricata.io', commands:['suricata -c /etc/suricata/suricata.yaml -i eth0']},

  {name:'GRASSMARLIN', category:'ICS', description:'ICS/SCADA fuzzing framework.', tags:['ics','scada'], risk:'high', logo:'https://cdn.simpleicons.org/grassmarlin', url:'https://github.com/irasharry/grassmarlin', commands:['Run per README']},
  {name:'Kali-ICS', category:'ICS', description:'Kali tools for ICS testing.', tags:['ics','kali'], risk:'medium', logo:'https://cdn.simpleicons.org/kali', url:'https://www.kali.org', commands:['Use Kali ICS scripts']},

  {name:'MISP', category:'TI', description:'Malware Information Sharing Platform.', tags:['ti','sharing'], risk:'low', logo:'https://cdn.simpleicons.org/misp', url:'https://misp.github.io', commands:['Start MISP per docs']},
  {name:'OpenCTI', category:'TI', description:'Cyber threat intelligence platform.', tags:['ti','platform'], risk:'low', logo:'https://cdn.simpleicons.org/opencti', url:'https://www.opencti.io', commands:['Start OpenCTI per docs']},

  {name:'VSCode', category:'Tools', description:'Code editor with extensions.', tags:['editor'], risk:'low', logo:'https://cdn.simpleicons.org/visualstudiocode', url:'https://code.visualstudio.com', commands:['code .']},
  {name:'Docker', category:'Tools', description:'Container runtime for sandboxes.', tags:['container'], risk:'low', logo:'https://cdn.simpleicons.org/docker', url:'https://www.docker.com', commands:['docker run -it --rm image']}
];

/* -------------------------
   DOM elements caching
   ------------------------- */
const categoryTabs = document.getElementById('categoryTabs');
const toolListEl = document.getElementById('toolList');
const searchInput = document.getElementById('searchInput');
const toolTitle = document.getElementById('toolTitle');
const toolMeta = document.getElementById('toolMeta');
const toolDesc = document.getElementById('toolDesc');
const toolTags = document.getElementById('toolTags');
const toolLogo = document.getElementById('toolLogo');
const toolUrl = document.getElementById('toolUrl');
const commandsArea = document.getElementById('commandsArea');
const jsonView = document.getElementById('jsonView');
const copyAllBtn = document.getElementById('copyAllBtn');
const modalRoot = document.getElementById('modalRoot');

let activeCategory = 'All';
let selectedIndex = 0;

/* -------------------------
   Utility helpers
   ------------------------- */
function escapeHtml(unsafe){
  return String(unsafe)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}
function showToast(msg){
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=> t.remove(), 2200);
}

/* Create modal with standardized structure. Returns modal element. */
function createModal(innerHTML, options = {}){
  modalRoot.innerHTML = `
    <div id="sach_modal_overlay" class="sach-modal-overlay">
      <div class="absolute inset-0 bg-black/60" onclick="closeModal()"></div>
      <div id="sach_modal" class="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div class="category-popup">${innerHTML}</div>
      </div>
    </div>
  `;
  return document.getElementById('sach_modal');
}
function closeModal(){
  modalRoot.innerHTML = '';
}

/* -------------------------
   Build category tabs (with popup on click)
   ------------------------- */
function buildCategoryTabs(){
  categoryTabs.innerHTML = '';
  CATEGORIES.forEach(cat=>{
    const btn = document.createElement('button');
    btn.className = 'text-sm text-slate-300 bg-transparent hover:bg-slate-800 px-3 py-1 rounded-md';
    btn.textContent = cat;

    // click — select category AND show small popup description
    btn.addEventListener('click', (e) => {
      // update active category (keeps existing behavior)
      activeCategory = cat;
      // toggle active visual classes for tabs
      document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('bg-slate-700','text-white','active-tab'));
      btn.classList.add('bg-slate-700','text-white','active-tab');

      // render tools for this category (preserves original workflow)
      renderToolList(searchInput.value || '');

      // show a small popup modal with the short category description
      const desc = CATEGORY_DESCRIPTIONS[cat] || 'Category information not available.';
      const modal = createModal(`
        <div>
          <div class="flex items-start justify-between">
            <div>
              <div class="text-sm font-semibold">${escapeHtml(cat)}</div>
              <div class="text-xs text-slate-400 mt-1">${escapeHtml(desc)}</div>
            </div>
            <div>
              <button id="closeCatPopup" class="px-3 py-1 rounded-md btn-ghost">Close</button>
            </div>
          </div>
        </div>
      `);
      // keep modal small, close on clicking button or overlay
      document.getElementById('closeCatPopup').addEventListener('click', closeModal);
    });

    // set All active by default visually
    if (cat === 'All') {
      btn.classList.add('bg-slate-700','text-white','active-tab');
    }
    categoryTabs.appendChild(btn);
  });
}

/* -------------------------
   Render tools list (sidebar)
   ------------------------- */
function renderToolList(filter=''){
  toolListEl.innerHTML = '';
  const q = (filter||'').toLowerCase();
  let visible = 0;
  tools.forEach((t, idx) => {
    if (activeCategory !== 'All' && t.category !== activeCategory) return;
    const text = [t.name, t.category, ...(t.tags||[]), t.description, ...(t.commands||[])].join(' ').toLowerCase();
    if (q && !text.includes(q)) return;
    visible++;

    const div = document.createElement('div');
    div.className = 'py-3 px-2 cursor-pointer flex items-start gap-3 rounded-md border border-transparent hover:scale-[1.02] transition bg-gradient-to-r from-pink-500/10 via-purple-500/10 to-cyan-500/10 hover:border-pink-500/40 tool-list-item';
    div.innerHTML = `
      <div class="w-10 h-10 rounded-md bg-slate-800 flex items-center justify-center text-sm font-medium tool-logo-small">
        <img src="${t.logo||''}" alt="" class="w-8 h-8 object-contain" onerror="this.style.display='none'"/>
      </div>
      <div class="flex-1">
        <div class="flex items-center justify-between">
          <div>
            <div class="font-medium">${escapeHtml(t.name)}</div>
            <div class="text-xs text-slate-400">${escapeHtml(t.category)} • ${(t.tags||[]).slice(0,3).join(', ') || ''}</div>
          </div>
          <div class="text-xs text-slate-500">${escapeHtml(t.risk||'n/a')}</div>
        </div>
      </div>
    `;
    div.addEventListener('click', ()=> selectTool(idx));
    toolListEl.appendChild(div);
  });

  if (!visible) {
    toolListEl.innerHTML = '<div class="p-4 text-sm text-slate-500">No tools found in this category/search.</div>';
  }
}

/* -------------------------
   Select and display a tool (detail pane)
   ------------------------- */
function selectTool(idx){
  if (idx < 0 || idx >= tools.length) return;
  selectedIndex = idx;
  const t = tools[idx];
  toolTitle.textContent = t.name;
  toolMeta.textContent = `${t.category} • ${t.risk ? ('Risk: '+t.risk) : ''}`;
  toolDesc.textContent = t.description || '';
  toolLogo.innerHTML = t.logo ? `<img src="${t.logo}" class='w-full h-full object-contain rounded-md' onerror="this.style.display='none'"/>` : '🔧';
  toolTags.innerHTML = '';
  (t.tags||[]).forEach(tag=>{
    const span = document.createElement('span');
    span.className = 'text-xs px-2 py-1 rounded-md bg-slate-800 border border-slate-700';
    span.textContent = tag;
    toolTags.appendChild(span);
  });
  toolUrl.innerHTML = t.url ? `<a href="${t.url}" target="_blank" class="text-xs text-slate-400 hover:underline">${t.url}</a>` : '';
  renderCommands(t);
  jsonView.textContent = JSON.stringify(t, null, 2);
}

/* render commands of a tool (uses original design) */
function renderCommands(t){
  commandsArea.innerHTML = '';

  (t.commands || []).forEach(c => {

    // Support both formats:
    // "string" OR { cmd:"...", note:"..." }
    const cmdText = typeof c === "string" ? c : c.cmd;
    const noteText = typeof c === "string" ? "" : (c.note || "");

    const box = document.createElement('div');
    box.className = "p-3 bg-slate-900 rounded-md border border-slate-800 flex flex-col gap-2";

    box.innerHTML = `
      <div class="flex items-start justify-between gap-3">
        <div class="flex-1 code-box text-sm">${escapeHtml(cmdText)}</div>
        <div class="flex flex-col gap-2 ml-3">
          <button class="copyBtn px-3 py-1 rounded-md text-xs btn-ghost">Copy</button>
          <button class="previewBtn px-3 py-1 rounded-md text-xs btn-ghost">Preview</button>
        </div>
      </div>

      ${noteText 
        ? `<div class="text-xs text-slate-400">${escapeHtml(noteText)}</div>` 
        : ""
      }
    `;

    // Copy button
    box.querySelector('.copyBtn').addEventListener('click', () => {
      navigator.clipboard.writeText(cmdText)
        .then(() => showToast("Copied to clipboard"));
    });

    // Preview button
    box.querySelector('.previewBtn').addEventListener('click', () => {
      openTerminalPreview(cmdText);
    });

    commandsArea.appendChild(box);
  });
}


/* -------------------------
   Terminal preview modal (keeps original styling)
   ------------------------- */
function openTerminalPreview(cmd){
  const modal = createModal(`
    <div class='p-4'>
      <div class='bg-black text-green-300 p-3 rounded-md code-box' style='min-height:120px'>${escapeHtml(cmd)}</div>
      <div class='mt-3 flex justify-end'>
        <button id='closePrev' class='px-3 py-1 rounded-md btn-ghost'>Close</button>
      </div>
    </div>
  `);
  document.getElementById('closePrev').addEventListener('click', closeModal);
}

/* -------------------------
   Export & Download handlers (preserve original behavior)
   ------------------------- */
document.getElementById('exportJsonBtn').addEventListener('click', ()=>{
  const blob = new Blob([JSON.stringify(tools, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'sachidax-tools.json'; a.click();
  URL.revokeObjectURL(url);
});

document.getElementById('downloadHtmlBtn').addEventListener('click', ()=>{
  const html = document.documentElement.outerHTML;
  const blob = new Blob([html], {type:'text/html'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sachidax-notebook.html';
  a.click();
});

/* -------------------------
   Copy All button
   ------------------------- */
copyAllBtn.addEventListener('click', ()=>{
  const t = tools[selectedIndex];
  if(!t) return showToast('No tool selected');
  const text = (t.commands||[]).join('\n');
  navigator.clipboard.writeText(text).then(()=>showToast('All commands copied'));
});

/* -------------------------
   Search & clear events
   ------------------------- */
searchInput.addEventListener('input', (e)=> renderToolList(e.target.value));
document.getElementById('clearSearch').addEventListener('click', ()=>{ searchInput.value=''; renderToolList(''); });

/* -------------------------
   Keyboard shortcuts and init
   ------------------------- */
window.addEventListener('keydown',(e)=>{
  if(e.ctrlKey && e.key==='f'){ e.preventDefault(); searchInput.focus(); }
  if(e.key==='Escape') closeModal();
});

/* -------------------------
   Add Tool: dynamic tool expansion form & handling
   ------------------------- */
/* Non-intrusive button in header triggers the add-tool modal */
document.getElementById('addToolBtn').addEventListener('click', openAddToolModal);

function openAddToolModal(){
  // Pre-fill category options (from CATEGORIES excluding 'All')
  const opts = CATEGORIES.filter(c => c !== 'All').map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
  const modal = createModal(`
    <div>
      <div class="text-sm font-semibold mb-2">Add New Tool</div>
      <div class="form-field">
        <label for="newName">Tool Name</label>
        <input id="newName" placeholder="e.g., MyTool" />
      </div>
      <div class="form-field">
        <label for="newCategory">Category</label>
        <select id="newCategory">${opts}</select>
      </div>
      <div class="form-field">
        <label for="newDesc">Short Description</label>
        <input id="newDesc" placeholder="One-line description" />
      </div>
      <div class="form-field">
        <label for="newTags">Tags (comma-separated)</label>
        <input id="newTags" placeholder="tag1, tag2" />
      </div>
      <div class="form-field">
        <label for="newCommands">Commands (one per line)</label>
        <textarea id="newCommands" rows="4" placeholder="command1\ncommand2"></textarea>
      </div>
      <div class="flex justify-end gap-2 mt-2">
        <button id="cancelAdd" class="px-3 py-1 rounded-md btn-ghost">Cancel</button>
        <button id="saveAdd" class="px-3 py-1 rounded-md btn-primary">Add Tool</button>
      </div>
    </div>
  `);

  document.getElementById('cancelAdd').addEventListener('click', closeModal);
  document.getElementById('saveAdd').addEventListener('click', () => {
    const name = document.getElementById('newName').value.trim();
    const category = document.getElementById('newCategory').value;
    const desc = document.getElementById('newDesc').value.trim();
    const tags = document.getElementById('newTags').value.split(',').map(s=>s.trim()).filter(Boolean);
    const commands = document.getElementById('newCommands').value.split('\n').map(s=>s.trim()).filter(Boolean);

    if (!name || !category) {
      return showToast('Name and category are required.');
    }

    // Create a new tool object and push to tools array
    const newTool = {
      name,
      category,
      description: desc || '',
      tags,
      risk: 'n/a',
      logo: '', // user can update by editing tools array later
      url: '',
      commands
    };
    tools.push(newTool);

    // Re-render list and auto-select the newly added tool
    renderToolList(searchInput.value || '');
    selectTool(tools.length - 1);
    showToast(`Added "${name}"`);
    closeModal();
  });
}

/* -------------------------
   Init render
   ------------------------- */
buildCategoryTabs();
renderToolList('');
selectTool(0);

/* -------------------------
   Expose closeModal globally for overlay close (used in inline-generated overlay)
   ------------------------- */
window.closeModal = closeModal;
