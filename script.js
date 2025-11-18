// ===========================
// CATEGORY TABS
// ===========================
const CATEGORIES = [
  'All','Recon','OSINT','Vulnerability','Web App','Red Team','Wireless',
  'Passwords','Cloud','Mobile','Reverse','DFIR','Malware','Network','ICS','TI','Tools'
];

// ===========================
// FULL TOOLS ARRAY (OLD FORMAT SUPPORTED)
// ===========================
const tools = [ /* ⚠️ YOUR FULL TOOLS ARRAY HERE — OLD FORMAT OK */ ];
{
{
  name: "Nmap",
  category: "Recon",
  description: "Network discovery and port scanning.",
  tags: ["scan", "network"],
  risk: "low",
  logo: "https://cdn.simpleicons.org/nmap",
  url: "https://nmap.org",

  commands: [

    {
      cmd: "nmap -sC -sV target.com",
      desc: "Default scripts + service version detection.",
      when: "Initial scanning stage.",
      why: "Gives quick overview of ports + services."
    },

    {
      cmd: "nmap -sV --version-all target.com",
      desc: "Aggressive version detection.",
      when: "When you need exact software version.",
      why: "Helps identify vulnerable versions."
    },

    {
      cmd: "nmap -p- target.com",
      desc: "Scan all 65535 TCP ports.",
      when: "Full recon, bug bounty.",
      why: "Find hidden services on uncommon ports."
    },

    {
      cmd: "nmap -p80,443,8080 target.com",
      desc: "Scan specific ports manually.",
      when: "Focused scanning of web ports.",
      why: "Saves time vs full port scan."
    },

    {
      cmd: "nmap -sS target.com",
      desc: "Stealth SYN scan.",
      when: "Pentesting without full connection.",
      why: "Harder to detect by firewalls."
    },

    {
      cmd: "nmap -sT target.com",
      desc: "Full TCP connect scan.",
      when: "When SYN scan is blocked.",
      why: "Reliable alternative to stealth scanning."
    },

    {
      cmd: "nmap -sU target.com",
      desc: "UDP port scanning.",
      when: "Services like DNS, SNMP, NTP.",
      why: "UDP ports often overlooked in scans."
    },

    {
      cmd: "nmap -sC -sV -p- target.com",
      desc: "Full ports + default scripts + version detection.",
      when: "Deep recon.",
      why: "Gives maximum visibility into the system."
    },

    {
      cmd: "nmap -A target.com",
      desc: "OS detection + script scan + traceroute.",
      when: "Aggressive scan allowed.",
      why: "Best mode when you want everything in one scan."
    },

    {
      cmd: "nmap -O target.com",
      desc: "Identify operating system.",
      when: "Fingerprinting hosts.",
      why: "OS-specific exploits require OS info."
    },

    {
      cmd: "nmap --traceroute target.com",
      desc: "Run traceroute during scan.",
      when: "Network path mapping.",
      why: "Helps find intermediate network nodes."
    },

    {
      cmd: "nmap --script vuln target.com",
      desc: "Run vulnerability detection scripts.",
      when: "Finding CVEs quickly.",
      why: "Automated vuln identification."
    },

    {
      cmd: "nmap --script http-title target.com",
      desc: "Get website titles.",
      when: "Quick web enumeration.",
      why: "Useful for asset discovery."
    },

    {
      cmd: "nmap --script dns-brute target.com",
      desc: "Brute force subdomains.",
      when: "Subdomain enumeration.",
      why: "Helps discover subdomains without separate tools."
    },

    {
      cmd: "nmap -sn 10.0.0.0/24",
      desc: "Ping scan, host discovery only (no ports).",
      when: "Finding alive hosts.",
      why: "Fastest way to map a network."
    },

    {
      cmd: "nmap -Pn target.com",
      desc: "Disable host discovery (treat all hosts as alive).",
      when: "Firewall blocks ping.",
      why: "Scan hosts even when ICMP disabled."
    },

    {
      cmd: "nmap -T4 target.com",
      desc: "Faster timing scan.",
      when: "You want faster results.",
      why: "Good balance of speed + accuracy."
    },

    {
      cmd: "nmap -T5 target.com",
      desc: "Insane speed mode.",
      when: "Bug bounty / massive network.",
      why: "Fastest but risky—might cause detection."
    },

    {
      cmd: "nmap -oN result.txt target.com",
      desc: "Save output to text file.",
      when: "Pentest reporting.",
      why: "Keeps results for later analysis."
    },

    {
      cmd: "nmap -oX result.xml target.com",
      desc: "Save output as XML.",
      when: "Automation or reporting tools.",
      why: "XML integrates well with tools like Nessus/Burp."
    },

    {
      cmd: "nmap -oG result.gnmap target.com",
      desc: "Grepable output format.",
      when: "Script automation.",
      why: "Easy to parse with grep/awk/sed."
    },

    {
      cmd: "nmap -sW target.com",
      desc: "TCP window scan.",
      when: "Firewall evasion.",
      why: "Alternate stealth scan technique."
    },

    {
      cmd: "nmap -f target.com",
      desc: "Fragment scan packets.",
      when: "Trying to bypass packet filters.",
      why: "Sometimes helps evade simple firewalls."
    },

    {
      cmd: "nmap --source-port 53 target.com",
      desc: "Spoof source port.",
      when: "Evasion attempts.",
      why: "Some firewalls trust traffic on port 53 (DNS)."
    }

  ]
}



// ===========================
// ELEMENTS
// ===========================
const categoryTabs = document.getElementById('categoryTabs');
let activeCategory = 'All';

CATEGORIES.forEach(cat=>{
  const btn = document.createElement('button');
  btn.className = 'text-sm text-slate-300 bg-transparent hover:bg-slate-800';
  btn.textContent = cat;
  btn.onclick = ()=>{
    activeCategory = cat;
    document.querySelectorAll('.tabs button')
      .forEach(b=>b.classList.remove('bg-slate-700','text-white'));
    btn.classList.add('bg-slate-700','text-white');
    renderToolList(searchInput.value || '');
  };
  if(cat === 'All') btn.classList.add('bg-slate-700','text-white');
  categoryTabs.appendChild(btn);
});


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

let selectedIndex = 0;


// ===========================
// SEARCHABLE TOOL LIST
// ===========================
function renderToolList(filter=''){
  toolListEl.innerHTML = '';
  const q = (filter || '').toLowerCase();
  let visible = 0;

  tools.forEach((t, idx)=>{
    if(activeCategory !== 'All' && t.category !== activeCategory) return;

    const text = [
      t.name, t.category, ...(t.tags || []), t.description,
      ...(t.commands || []).map(c => typeof c === "string" ? c : c.cmd)
    ].join(' ').toLowerCase();

    if(q && !text.includes(q)) return;

    visible++;

    const div = document.createElement('div');
    div.className = 'py-3 px-2 hover:bg-slate-900 cursor-pointer flex items-start gap-3';

    div.innerHTML = `
      <div class="w-10 h-10 rounded-md bg-slate-800 flex items-center justify-center">
        <img src="${t.logo || ''}" class="w-8 h-8 object-contain" onerror="this.style.display='none'"/>
      </div>
      <div class="flex-1">
        <div class="font-medium">${t.name}</div>
        <div class="text-xs text-slate-400">${t.category} • ${t.tags?.slice(0,3).join(', ') || ''}</div>
      </div>
      <div class="text-xs text-slate-500">${t.risk || 'n/a'}</div>
    `;

    div.addEventListener('click', ()=>selectTool(idx));
    toolListEl.appendChild(div);
  });

  if(!visible)
    toolListEl.innerHTML = '<div class="p-4 text-sm text-slate-500">No tools found.</div>';
}


// ===========================
// TOOL DETAIL PANEL
// ===========================
function selectTool(idx){
  selectedIndex = idx;
  const t = tools[idx];

  toolTitle.textContent = t.name;
  toolMeta.textContent = `${t.category} • ${t.risk ? "Risk: "+t.risk : ''}`;
  toolDesc.textContent = t.description || '';

  toolLogo.innerHTML = t.logo
    ? `<img src='${t.logo}' class='w-full h-full object-contain rounded-md' />`
    : '🔧';

  toolTags.innerHTML = '';
  (t.tags || []).forEach(tag=>{
    const span = document.createElement('span');
    span.className = 'text-xs px-2 py-1 rounded-md bg-slate-800 border border-slate-700';
    span.textContent = tag;
    toolTags.appendChild(span);
  });

  toolUrl.innerHTML = t.url
    ? `<a href="${t.url}" target="_blank" class="text-xs text-slate-400 hover:underline">${t.url}</a>`
    : '';

  renderCommands(t);

  jsonView.textContent = JSON.stringify(t, null, 2);
}


// ===========================
// 🔥 UNIVERSAL COMMAND RENDERER (STRING + OBJECT BOTH WORK)
// ===========================
function renderCommands(t){
  commandsArea.innerHTML = '';

  (t.commands || []).forEach(entry => {

    // Support for old simple string format
    const obj = typeof entry === "string"
      ? { cmd: entry }
      : entry;

    const box = document.createElement('div');
    box.className =
      'p-3 bg-slate-900 rounded-md border border-slate-800 mb-3';

    box.innerHTML = `
      <div class="flex justify-between">
        <div class="code-box text-sm flex-1">${escapeHtml(obj.cmd)}</div>
        <button class="copyBtn px-3 py-1 rounded-md text-xs bg-slate-800 border">Copy</button>
      </div>

      ${
        (obj.desc || obj.when || obj.why)
        ? `
        <div class="mt-3 text-xs text-slate-400 space-y-1">
          ${obj.desc ? `<p><b>Description:</b> ${obj.desc}</p>` : ''}
          ${obj.when ? `<p><b>When:</b> ${obj.when}</p>` : ''}
          ${obj.why ? `<p><b>Why:</b> ${obj.why}</p>` : ''}
        </div>
        `
        : ''
      }
    `;

    box.querySelector('.copyBtn').addEventListener('click', ()=>{
      navigator.clipboard.writeText(obj.cmd)
        .then(()=>showToast("Copied"));
    });

    commandsArea.appendChild(box);
  });
}


// ===========================
// TERMINAL PREVIEW MODAL
// ===========================
function openTerminalPreview(cmd){
  const modal = createModal(`
    <div class="p-4">
      <div class="bg-black text-green-300 p-3 rounded-md code-box"
           style="min-height:120px">${escapeHtml(cmd)}</div>
      <div class="mt-3 text-right">
        <button id="closePrev" class="px-3 py-1 bg-slate-700 rounded-md">Close</button>
      </div>
    </div>
  `);

  modal.querySelector('#closePrev')
    .addEventListener('click', ()=>closeModal());
}

function createModal(innerHTML){
  const root = document.getElementById('modalRoot');
  root.innerHTML = `
    <div id="sach_modal" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/60" onclick="closeModal()"></div>
      <div class="relative max-w-2xl w-full p-4">
        <div class="glass p-4 rounded-md">${innerHTML}</div>
      </div>
    </div>
  `;
  return document.getElementById('sach_modal');
}

function closeModal(){
  document.getElementById('modalRoot').innerHTML = '';
}


// ===========================
// UTILS
// ===========================
function escapeHtml(text){
  return String(text)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function showToast(msg){
  const t = document.createElement('div');
  t.className =
    'fixed bottom-6 right-6 bg-slate-800 px-4 py-2 rounded-md text-sm';
  t.textContent = msg;

  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 2200);
}


// ===========================
// EXPORT JSON
// ===========================
document.getElementById('exportJsonBtn').addEventListener('click', ()=>{
  const blob = new Blob([JSON.stringify(tools, null, 2)], {
    type:'application/json'
  });

  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'sachidax-tools.json';
  a.click();
});


// ===========================
// DOWNLOAD HTML
// ===========================
document.getElementById('downloadHtmlBtn').addEventListener('click', ()=>{
  const blob = new Blob([document.documentElement.outerHTML],
    {type:'text/html'});

  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sachidax-notebook.html';
  a.click();
});


// ===========================
// SEARCH
// ===========================
searchInput.addEventListener('input', (e)=>{
  renderToolList(e.target.value);
});

document.getElementById('clearSearch')
  .addEventListener('click', ()=>{
    searchInput.value = '';
    renderToolList('');
  });


// ===========================
// COPY ALL
// ===========================
copyAllBtn.addEventListener('click', ()=>{
  const t = tools[selectedIndex];
  if(!t) return showToast('No tool selected');

  const text = (t.commands || [])
    .map(c => typeof c === "string" ? c : c.cmd)
    .join('\n');

  navigator.clipboard.writeText(text)
    .then(()=>showToast('All commands copied'));
});


// ===========================
// INIT
// ===========================
renderToolList('');
selectTool(0);


// ===========================
// KEYBOARD SHORTCUTS
// ===========================
window.addEventListener('keydown', (e)=>{
  if(e.ctrlKey && e.key === 'f'){
    e.preventDefault();
    searchInput.focus();
  }
  if(e.key === 'Escape') closeModal();
});
