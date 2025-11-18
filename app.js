// app.js
// Make sure this loads after the DOM (we use defer in index.htm)

const categoryTabsEl = document.getElementById('categoryTabs');
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

let CATEGORIES = [];
let tools = [];
let commandsMap = {};
let activeCategory = 'All';
let selectedIndex = 0;

async function loadData(){
  try {
    const catResp = await fetch('data/categories.json'); if(!catResp.ok) throw new Error('categories.json missing');
    const toolsResp = await fetch('data/tools.json'); if(!toolsResp.ok) throw new Error('tools.json missing');
    const cmdResp = await fetch('data/commands.json'); if(!cmdResp.ok) throw new Error('commands.json missing');

    const catJson = await catResp.json();
    const toolsJson = await toolsResp.json();
    const cmdJson = await cmdResp.json();

    // Categories can be array of strings or objects {name,desc}
    CATEGORIES = Array.isArray(catJson) ? catJson : [];
    // normalize categories to objects:
    CATEGORIES = CATEGORIES.map(c => (typeof c === 'string') ? {name:c, desc:''} : c);

    tools = toolsJson.map(t => ({...t, commands: cmdJson[t.name] || []}));
    commandsMap = cmdJson || {};

    // Render categories and initial UI
    renderCategoryTabs(CATEGORIES);
    renderToolList('');
    selectTool(0);
  } catch (err) {
    console.error('Load data error:', err);
    toolListEl.innerHTML = `<div class="p-4 text-sm text-slate-500">Error loading data. Check <code>data/</code> files.</div>`;
  }
}

// Render category tabs with hover tooltip
function renderCategoryTabs(categoriesData){
  categoryTabsEl.innerHTML = '';
  categoriesData.forEach((cat, idx) => {
    const btn = document.createElement('button');
    btn.className = 'text-sm text-slate-300 bg-transparent hover:bg-slate-800 relative px-3 py-1';
    btn.textContent = cat.name;
    if(cat.name === 'All') { btn.classList.add('bg-slate-700','text-white'); activeCategory = 'All'; }

    // create tooltip element
    const tip = document.createElement('div');
    tip.className = 'category-tooltip';
    tip.textContent = cat.desc || (cat.name === 'All' ? 'All categories combined — browse everything.' : '');

    btn.appendChild(tip);

    // show/hide on hover with small delay
    let hoverTimer;
    btn.addEventListener('mouseenter', () => {
      clearTimeout(hoverTimer);
      btn.classList.add('show-tip');
      // ensure visible
      tip.style.opacity = '1';
      tip.style.transform = 'translateY(0)';
    });
    btn.addEventListener('mouseleave', () => {
      hoverTimer = setTimeout(()=> {
        btn.classList.remove('show-tip');
        tip.style.opacity = '0';
        tip.style.transform = 'translateY(6px)';
      }, 100);
    });

    btn.addEventListener('click', () => {
      activeCategory = cat.name;
      document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('bg-slate-700','text-white'));
      btn.classList.add('bg-slate-700','text-white');
      renderToolList(searchInput.value || '');
    });

    categoryTabsEl.appendChild(btn);
  });
}

// Render tool list (left)
function renderToolList(filter=''){
  toolListEl.innerHTML = '';
  const q = (filter || '').toLowerCase();
  let visible = 0;
  tools.forEach((t, idx) => {
    if(activeCategory !== 'All' && t.category !== activeCategory) return;
    const text = [t.name, t.category, ...(t.tags||[]), t.description, ...(t.commands||[])].join(' ').toLowerCase();
    if(q && !text.includes(q)) return;
    visible++;
    const div = document.createElement('div');
    div.className = 'py-3 px-2 cursor-pointer flex items-start gap-3 rounded-md border border-transparent hover:scale-[1.02] transition bg-gradient-to-r from-pink-500/10 via-purple-500/10 to-cyan-500/10 hover:border-pink-500/40';
    div.innerHTML = `
      <div class="w-10 h-10 rounded-md bg-slate-800 flex items-center justify-center text-sm font-medium"><img src="${t.logo||''}" alt="${t.name}" class="w-8 h-8 object-contain" onerror="this.style.display='none'"/></div>
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

  if(!visible) toolListEl.innerHTML = '<div class="p-4 text-sm text-slate-500">No tools found in this category/search.</div>';
}

// Select tool and populate details pane
function selectTool(idx){
  if(!tools[idx]) return;
  selectedIndex = idx;
  const t = tools[idx];
  toolTitle.textContent = t.name;
  toolMeta.textContent = `${t.category} • ${t.risk ? ('Risk: '+t.risk) : ''}`;
  toolDesc.textContent = t.description || '';
  toolLogo.innerHTML = t.logo ? `<img src="${t.logo}" class='w-full h-full object-contain rounded-md' onerror="this.style.display='none'"/>` : '🔧';
  toolTags.innerHTML = '';
  (t.tags||[]).forEach(tag=>{
    const span = document.createElement('span');
    span.className='text-xs px-2 py-1 rounded-md bg-slate-800 border border-slate-700';
    span.textContent=tag; toolTags.appendChild(span);
  });
  toolUrl.innerHTML = t.url ? `<a href="${t.url}" target="_blank" class="text-xs text-slate-400 hover:underline">${t.url}</a>` : '';
  renderCommands(t);
  jsonView.textContent = JSON.stringify(t, null, 2);
}

// Render commands list for a tool
function renderCommands(t){
  commandsArea.innerHTML = '';
  (t.commands||[]).forEach((c, ci)=>{
    const box = document.createElement('div');
    box.className = 'p-3 bg-slate-900 rounded-md border border-slate-800 flex items-start justify-between gap-3';
    box.innerHTML = `
      <div class="flex-1 code-box text-sm">${escapeHtml(c)}</div>
      <div class="flex flex-col gap-2 ml-3">
        <button class="copyBtn px-3 py-1 rounded-md text-xs btn-ghost">Copy</button>
        <button class="previewBtn px-3 py-1 rounded-md text-xs btn-ghost">Preview</button>
      </div>
    `;
    box.querySelector('.copyBtn').addEventListener('click', ()=>{ navigator.clipboard.writeText(c).then(()=>showToast('Copied to clipboard'))});
    box.querySelector('.previewBtn').addEventListener('click', ()=>openTerminalPreview(c));
    commandsArea.appendChild(box);
  });
}

// Terminal preview modal
function openTerminalPreview(cmd){
  const modal = createModal(`<div class='p-4'><div class='bg-black text-green-300 p-3 rounded-md code-box' style='min-height:120px'>${escapeHtml(cmd)}</div><div class='mt-3 flex justify-end'><button id='closePrev' class='px-3 py-1 rounded-md btn-ghost'>Close</button></div></div>`);
  modal.querySelector('#closePrev').addEventListener('click', ()=>closeModal());
}

// Modal helpers
function createModal(innerHTML){
  modalRoot.innerHTML = `
    <div id='sach_modal' class='fixed inset-0 z-50 flex items-center justify-center'>
      <div class='absolute inset-0 bg-black/60' onclick='document.getElementById("modalRoot").innerHTML=""'></div>
      <div class='relative max-w-2xl w-full p-4'>
        <div class='glass p-4 rounded-md'>${innerHTML}</div>
      </div>
    </div>
  `;
  return document.getElementById('sach_modal');
}
function closeModal(){ modalRoot.innerHTML = '' }

// Escape HTML
function escapeHtml(unsafe){ return String(unsafe).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Toast
function showToast(msg){ const t = document.createElement('div'); t.className='fixed bottom-6 right-6 bg-slate-800 px-4 py-2 rounded-md'; t.textContent=msg; document.body.appendChild(t); setTimeout(()=>t.remove(),2200); }

// Export JSON
document.getElementById('exportJsonBtn').addEventListener('click', ()=>{ const blob = new Blob([JSON.stringify(tools, null, 2)], {type:'application/json'}); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'sachidax-tools.json'; a.click(); URL.revokeObjectURL(url); });

// Download HTML
document.getElementById('downloadHtmlBtn').addEventListener('click', ()=>{ const html = document.documentElement.outerHTML; const blob = new Blob([html], {type:'text/html'}); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'sachidax-notebook.html'; a.click(); });

// Search & filter
searchInput.addEventListener('input', (e)=> renderToolList(e.target.value));
document.getElementById('clearSearch').addEventListener('click', ()=>{ searchInput.value=''; renderToolList(''); });

// Copy All
copyAllBtn.addEventListener('click', ()=>{ const t = tools[selectedIndex]; if(!t) return showToast('No tool selected'); const text = (t.commands||[]).join('\n'); navigator.clipboard.writeText(text).then(()=>showToast('All commands copied')); });

// Keyboard
window.addEventListener('keydown',(e)=>{ if(e.ctrlKey && e.key==='f'){ e.preventDefault(); searchInput.focus(); } if(e.key==='Escape') closeModal(); });

// Initialize load
loadData();
