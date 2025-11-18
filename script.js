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
