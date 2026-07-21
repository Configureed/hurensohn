async function fetchFiles() {
  const res = await fetch('/api/files');
  const files = await res.json();
  const list = document.getElementById('filesList');
  list.innerHTML = '';
  files.forEach(f => {
    const el = document.createElement('div'); el.className = 'file';
    el.innerHTML = `<div style="flex:1"><a href="/file/${f.id}" target="_blank">${escapeHtml(f.originalname || f.filename)}</a><div class="meta">${f.mimetype} · ${formatSize(f.size)} · ${new Date(f.created_at).toLocaleString()}</div></div>`;
    list.appendChild(el);
  });
}

function formatSize(n){ if(!n) return ''; if(n<1024) return n+' B'; if(n<1024*1024) return (n/1024).toFixed(1)+' KB'; return (n/1024/1024).toFixed(2)+' MB'; }
function escapeHtml(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

document.getElementById('uploadForm').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fileInput = document.getElementById('fileInput');
  if (!fileInput.files.length) return alert('Bitte Datei wählen');
  const fd = new FormData(); fd.append('file', fileInput.files[0]);
  const btn = document.getElementById('uploadBtn'); btn.disabled = true; btn.textContent = 'Hochladen...';
  try{
    const res = await fetch('/api/upload', { method:'POST', body: fd });
    const data = await res.json();
    if (data.error) alert(data.error);
    else {
      alert('Hochgeladen: ' + (data.url || data.id));
      fileInput.value = '';
      fetchFiles();
    }
  }catch(err){ alert('Fehler'); }
  btn.disabled = false; btn.textContent = 'Datei hochladen';
});

fetchFiles();
