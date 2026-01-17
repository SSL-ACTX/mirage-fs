// src/web_assets.rs

pub const HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MirageFS | Secure Storage</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
        body { font-family: 'Inter', sans-serif; background-color: #09090b; }
        .mono { font-family: 'JetBrains+Mono', monospace; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #18181b; }
        ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #52525b; }
    </style>
</head>
<body class="text-zinc-300 h-screen flex flex-col overflow-hidden selection:bg-orange-500/30">

    <div id="drag-overlay" class="fixed inset-0 z-50 hidden bg-zinc-950/90 backdrop-blur-sm flex-col items-center justify-center pointer-events-none transition-opacity">
        <svg class="w-20 h-20 text-orange-500 mb-6 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
        <h2 class="text-3xl font-bold text-white tracking-tight">Drop files to encrypt</h2>
    </div>

    <header class="h-16 border-b border-zinc-800 bg-zinc-900/50 flex items-center justify-between px-6 shrink-0">
        <div class="flex items-center gap-3 select-none">
            <div class="bg-orange-600 text-white font-bold px-2 py-1 rounded text-sm shadow-lg shadow-orange-900/20">M</div>
            <span class="font-semibold tracking-tight text-lg text-white">MirageFS <span class="text-zinc-500 font-normal">Web</span></span>
        </div>
        <div class="flex items-center gap-4">
            <div class="hidden md:flex items-center gap-2 text-xs font-medium text-zinc-500 bg-zinc-900 border border-zinc-800 px-3 py-1 rounded-full">
                <div class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                v1.3.0
            </div>
        </div>
    </header>

    <div class="h-14 border-b border-zinc-800 bg-zinc-950/30 px-4 flex items-center gap-3 shrink-0">
        <button onclick="navigate('..')" class="flex items-center gap-2 px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 hover:border-zinc-600 rounded-md text-sm transition-all active:scale-95 text-zinc-300">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18"></path></svg>
            Up
        </button>

        <div class="w-px h-6 bg-zinc-800 mx-1"></div>

        <button onclick="openModal()" class="flex items-center gap-2 px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 hover:border-zinc-600 rounded-md text-sm transition-all active:scale-95 text-zinc-300">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"></path></svg>
            New Folder
        </button>

        <div class="flex-grow"></div>

        <button onclick="refresh()" class="p-2 text-zinc-400 hover:text-white hover:bg-zinc-800 rounded-md transition-colors" title="Refresh">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
        </button>

        <button onclick="document.getElementById('file-input').click()" class="flex items-center gap-2 px-4 py-1.5 bg-orange-600 hover:bg-orange-500 text-white rounded-md text-sm font-bold transition-all shadow-lg shadow-orange-900/20 hover:shadow-orange-900/40 active:scale-95">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"></path></svg>
            Upload
        </button>
        <input type="file" id="file-input" class="hidden" multiple onchange="handleUpload(this.files)">
    </div>

    <div id="breadcrumbs" class="px-6 py-2.5 text-sm text-zinc-500 border-b border-zinc-800 bg-zinc-900/20 flex items-center gap-1 shrink-0 overflow-x-auto whitespace-nowrap mono">
        </div>

    <main class="flex-grow overflow-auto relative">
        <table class="w-full text-left border-collapse">
            <thead class="bg-zinc-950/80 backdrop-blur sticky top-0 z-10 text-xs font-medium text-zinc-500 uppercase tracking-wider border-b border-zinc-800">
                <tr>
                    <th class="py-3 px-6 w-1/2">Name</th>
                    <th class="py-3 px-6 text-right">Size</th>
                    <th class="py-3 px-6 text-right">Modified</th>
                    <th class="py-3 px-6 text-right w-16">Action</th>
                </tr>
            </thead>
            <tbody id="file-list" class="divide-y divide-zinc-800/50 text-sm">
                </tbody>
        </table>
    </main>

    <div id="modal" class="fixed inset-0 bg-black/80 z-[60] hidden flex-col items-center justify-center backdrop-blur-sm p-4 transition-all">
        <div class="bg-zinc-900 border border-zinc-700 p-6 rounded-xl w-full max-w-sm shadow-2xl scale-100 ring-1 ring-white/10">
            <h3 class="text-lg font-bold text-white mb-1">Create Folder</h3>
            <p class="text-zinc-500 text-sm mb-5">Enter a name for the new directory.</p>
            <input type="text" id="folder-name" class="w-full bg-black/50 border border-zinc-700 rounded-lg px-4 py-2.5 text-white outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500 transition-all mb-6 placeholder-zinc-600" placeholder="e.g. Documents" autocomplete="off">
            <div class="flex justify-end gap-3">
                <button onclick="closeModal()" class="px-4 py-2 text-sm text-zinc-400 hover:text-white transition-colors">Cancel</button>
                <button onclick="createFolder()" class="px-4 py-2 bg-orange-600 hover:bg-orange-500 text-white text-sm rounded-lg font-semibold transition-colors">Create Folder</button>
            </div>
        </div>
    </div>

    <script>
        let currentPath = "/";
        window.Maps = async function(path) {
            await navigate(path);
        };

        async function navigate(path) {
            if (path === '..') {
                const parts = currentPath.split('/').filter(p => p);
                parts.pop();
                currentPath = '/' + parts.join('/');
            } else if (path.startsWith('/')) {
                currentPath = path;
            } else {
                currentPath = (currentPath === '/' ? '' : currentPath) + '/' + path;
            }

            // Normalize path to avoid double slashes
            if (!currentPath.startsWith('/')) currentPath = '/' + currentPath;
            currentPath = currentPath.replace(/\/+/g, '/');

            await refresh();
        }

        async function refresh() {
            renderBreadcrumbs();
            const tbody = document.getElementById('file-list');
            tbody.innerHTML = '<tr><td colspan="4" class="text-center py-12 text-zinc-600 animate-pulse">Decrypting Metadata...</td></tr>';

            try {
                const res = await fetch(currentPath, { method: 'PROPFIND', headers: { 'Depth': '1' } });

                if (!res.ok) throw new Error(res.statusText);

                const text = await res.text();
                const parser = new DOMParser();
                const xml = parser.parseFromString(text, "text/xml");

                const responses = Array.from(xml.querySelectorAll('response'));
                const items = [];

                responses.forEach(resp => {
                    const href = decodeURIComponent(resp.querySelector('href').textContent);

                    // Normalization for comparison
                    const normHref = href.endsWith('/') ? href : href + '/';
                    const normCurr = currentPath.endsWith('/') ? currentPath : currentPath + '/';

                    // Skip self
                    if (normHref === normCurr) return;

                    const name = href.split('/').filter(p => p).pop();
                    if (!name) return;

                    const props = resp.querySelector('prop');
                    // Check standard WebDAV collection properties
                    const isDir = props.querySelector('collection') !== null || props.querySelector('iscollection')?.textContent === '1';
                    const size = props.querySelector('getcontentlength')?.textContent || 0;
                    const date = props.querySelector('getlastmodified')?.textContent;

                    items.push({ name, href, isDir, size: parseInt(size), date });
                });

                // Sort: Folders on top
                items.sort((a, b) => (b.isDir - a.isDir) || a.name.localeCompare(b.name));

                if (items.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="text-center py-20 text-zinc-600 italic select-none">Directory is empty</td></tr>';
                    return;
                }

                tbody.innerHTML = items.map(i => `
                    <tr class="hover:bg-zinc-900/60 group transition-colors border-b border-zinc-800/30 last:border-0 cursor-pointer"
                        onclick="${i.isDir ? `Maps('${i.name}')` : `window.open('${i.href}', '_blank')`}">

                        <td class="py-3 px-6 select-none">
                            <div class="flex items-center gap-3">
                                <span class="text-lg opacity-70 group-hover:opacity-100 group-hover:scale-110 transition-all text-zinc-400 group-hover:text-orange-500">
                                    ${i.isDir ?
                                    '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z"/></svg>' :
                                    '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clip-rule="evenodd"/></svg>'}
                                </span>
                                <span class="font-medium text-zinc-300 group-hover:text-white transition-colors truncate">${i.name}</span>
                            </div>
                        </td>

                        <td class="py-3 px-6 text-right font-mono text-xs text-zinc-500 group-hover:text-zinc-400">
                            ${i.isDir ? '--' : fmtSize(i.size)}
                        </td>

                        <td class="py-3 px-6 text-right text-xs text-zinc-500 group-hover:text-zinc-400">
                            ${fmtDate(i.date)}
                        </td>

                        <td class="py-3 px-6 text-right" onclick="event.stopPropagation()">
                            <button onclick="deleteItem('${i.href}')" class="text-zinc-600 hover:text-red-500 hover:bg-red-500/10 p-1.5 rounded-md transition-all opacity-0 group-hover:opacity-100" title="Delete">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                            </button>
                        </td>
                    </tr>
                `).join('');

            } catch (e) {
                console.error(e);
                tbody.innerHTML = `<tr><td colspan="4" class="text-center py-12 text-red-500">Connection Error: ${e.message}</td></tr>`;
            }
        }

        function renderBreadcrumbs() {
            const parts = currentPath.split('/').filter(p => p);
            let html = `<span class="cursor-pointer hover:text-white hover:bg-zinc-800 px-1.5 py-0.5 rounded transition-colors" onclick="navigate('/')">root</span>`;
            let build = "";
            parts.forEach(p => {
                build += "/" + p;
                html += ` <span class="text-zinc-600">/</span> <span class="cursor-pointer hover:text-white hover:bg-zinc-800 px-1.5 py-0.5 rounded transition-colors" onclick="navigate('${build}')">${p}</span>`;
            });
            document.getElementById('breadcrumbs').innerHTML = html;
        }

        // --- Actions ---

        const fmtSize = (bytes) => {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        };

        const fmtDate = (str) => {
            if (!str) return '-';
            try {
                const d = new Date(str);
                return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
            } catch { return str; }
        };

        async function deleteItem(href) {
            if (!confirm('Permanently delete this item? This cannot be undone.')) return;
            try {
                await fetch(href, { method: 'DELETE' });
                refresh();
            } catch (e) { alert(e.message); }
        }

        async function createFolder() {
            const name = document.getElementById('folder-name').value;
            if (!name) return;
            const url = (currentPath.endsWith('/') ? currentPath : currentPath + '/') + name;
            try {
                await fetch(url, { method: 'MKCOL' });
                closeModal();
                refresh();
            } catch (e) { alert("Failed to create folder: " + e.message); }
        }

        async function handleUpload(files) {
            document.getElementById('drag-overlay').classList.add('hidden');
            document.getElementById('drag-overlay').classList.remove('flex');

            // Simple toast/notification could go here
            for (let file of files) {
                const url = (currentPath.endsWith('/') ? currentPath : currentPath + '/') + file.name;
                try {
                    await fetch(url, { method: 'PUT', body: file });
                } catch (e) { console.error(e); }
            }
            // Clear input so same file can be selected again if needed
            document.getElementById('file-input').value = '';
            refresh();
        }

        // --- Modals ---
        function openModal() {
            const m = document.getElementById('modal');
            m.classList.remove('hidden');
            m.classList.add('flex');
            setTimeout(() => document.getElementById('folder-name').focus(), 50);
        }
        function closeModal() {
            const m = document.getElementById('modal');
            m.classList.add('hidden');
            m.classList.remove('flex');
            document.getElementById('folder-name').value = '';
        }
        // Submit on Enter
        document.getElementById('folder-name').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') createFolder();
            if (e.key === 'Escape') closeModal();
        });

        // --- Drag & Drop ---
        let dragCounter = 0;
        const overlay = document.getElementById('drag-overlay');

        function handleDragEnter(e) {
            e.preventDefault();
            dragCounter++;
            overlay.classList.remove('hidden');
            overlay.classList.add('flex');
        }
        function handleDragLeave(e) {
            e.preventDefault();
            dragCounter--;
            if (dragCounter === 0) {
                overlay.classList.add('hidden');
                overlay.classList.remove('flex');
            }
        }
        function handleDrop(e) {
            e.preventDefault();
            dragCounter = 0;
            overlay.classList.add('hidden');
            overlay.classList.remove('flex');
            if (e.dataTransfer.files.length > 0) handleUpload(e.dataTransfer.files);
        }
        refresh();
    </script>
</body>
</html>
"#;
