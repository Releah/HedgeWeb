import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';

type Profile = { id: string; name: string; host: string; port: number; username: string; folder: string; shell?: 'default' | 'nu'; hostKeySha256?: string };
type RdpProfile = { id: string; name: string; host: string; port: number; username: string; domain: string; security: 'any' | 'nla' | 'tls' };
type Identity = { username: string; admin: boolean; source: 'local' | 'authentik' };
type VpnStatus = { configured: boolean; authenticationRequired?: boolean; state: 'not_configured' | 'disconnected' | 'authenticating' | 'connecting' | 'connected' | 'error'; identity: string; endpoint: string | null; address: string | null; accessScope: string; connectedAt: string | null; expiresAt: string | null; bytesReceived: number; bytesSent: number; error?: string };
type VpnConfigView = { configured: boolean; endpointLabel?: string; accessScope?: string; leaseMinutes?: number; certificateOnly?: boolean; updatedAt?: string };
type AppId = 'ssh' | 'rdp' | 'browser' | 'settings' | 'about';
type ManagedWindow = { id: string; element: HTMLElement; task: HTMLButtonElement; fit?: FitAddon; socket?: WebSocket; cleanup?: () => void };
const qs = <T extends HTMLElement>(selector: string, root: ParentNode = document) => root.querySelector<T>(selector)!;
let profiles: Profile[] = [], rdpProfiles: RdpProfile[] = [], identity: Identity | null = null, authMode = '', pendingProfile: Profile | null = null, pendingPassword = '', topZ = 20, terminalSequence = 0;
const windows = new Map<string, ManagedWindow>();
let applicationScale = Number(localStorage.getItem('hedgeweb.applicationScale') || '0.85');
if (![0.75, 0.85, 1, 1.1].includes(applicationScale)) applicationScale = 0.85;
document.documentElement.style.setProperty('--application-scale', String(applicationScale));
const neonTerminalTheme = {
  background: '#02070d', foreground: '#62f5d2', cursor: '#e8ff48', cursorAccent: '#02070d', selectionBackground: '#963dccd9', selectionInactiveBackground: '#692a9199', selectionForeground: '#ffffff',
  black: '#071018', red: '#ff3e8a', green: '#27f7a8', yellow: '#e8ff48', blue: '#27cfff', magenta: '#dd45ff', cyan: '#20f5e1', white: '#c8e7e4',
  brightBlack: '#41606a', brightRed: '#ff72ad', brightGreen: '#6dffc4', brightYellow: '#f5ff83', brightBlue: '#70e5ff', brightMagenta: '#ef83ff', brightCyan: '#7efff2', brightWhite: '#f3fffd'
};

async function request<T>(url: string, init?: RequestInit): Promise<T> { const response = await fetch(url, { ...init, credentials: 'include', headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) } }); if (!response.ok) { const message = (await response.json()).error || 'Request failed'; if (response.status === 401 && url !== '/api/auth/login') { sessionStorage.setItem('hedgeweb.authNotice', 'Your HedgeWeb session expired. Sign in again to continue.'); location.reload(); } throw new Error(message); } return response.json(); }
function show(id: string) { document.querySelectorAll<HTMLElement>('[data-view]').forEach(node => node.hidden = node.id !== id); }
function escapeHtml(value: string) { const node = document.createElement('span'); node.textContent = value; return node.innerHTML; }
function updateClock() { qs('#clock').textContent = new Intl.DateTimeFormat(undefined, { weekday: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date()); }
function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`; if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`; return `${(value / 1024 ** 3).toFixed(1)} GB`; }
function formatDuration(milliseconds: number) { const total = Math.max(0, Math.floor(milliseconds / 1000)); const hours = Math.floor(total / 3600); const minutes = Math.floor(total % 3600 / 60); const seconds = total % 60; return [hours, minutes, seconds].map(value => String(value).padStart(2, '0')).join(':'); }
let vpnStatus: VpnStatus | null = null;
function renderVpnStatus() {
  if (!vpnStatus) return;
  const connected = vpnStatus.state === 'connected', label = vpnStatus.state === 'not_configured' ? 'OFFLINE' : vpnStatus.state.toUpperCase().replace('_', ' ');
  const busy = vpnStatus.state === 'authenticating' || vpnStatus.state === 'connecting'; qs('#vpn-monitor-button').classList.toggle('connected', connected); qs('#vpn-monitor-button').classList.toggle('busy', busy);
  qs('#vpn-tray-state').textContent = `VPN ${label}`; qs('#vpn-tray-scope').textContent = vpnStatus.accessScope.toUpperCase();
  qs('#vpn-state-badge').textContent = label; qs('#vpn-state-badge').className = `vpn-state-badge state-${vpnStatus.state}`;
  qs('#vpn-identity').textContent = vpnStatus.identity; qs('#vpn-endpoint').textContent = vpnStatus.endpoint || 'Not configured'; qs('#vpn-address').textContent = vpnStatus.address || '—'; qs('#vpn-access-scope').textContent = vpnStatus.accessScope;
  qs('#vpn-duration').textContent = vpnStatus.connectedAt ? formatDuration(Date.now() - Date.parse(vpnStatus.connectedAt)) : '00:00:00';
  qs('#vpn-lease').textContent = vpnStatus.expiresAt ? formatDuration(Date.parse(vpnStatus.expiresAt) - Date.now()) : '—'; qs('#vpn-received').textContent = formatBytes(vpnStatus.bytesReceived); qs('#vpn-sent').textContent = formatBytes(vpnStatus.bytesSent);
  const action = qs<HTMLButtonElement>('#vpn-action'); action.disabled = busy; action.classList.toggle('disconnect', connected);
  action.textContent = !vpnStatus.configured ? 'CONFIGURE VPN' : connected ? 'DISCONNECT' : busy ? 'AUTHENTICATING…' : 'REQUEST INTERNAL ACCESS';
}
async function refreshVpnStatus() { try { vpnStatus = await request<VpnStatus>('/api/vpn/status'); renderVpnStatus(); } catch { qs('#vpn-tray-state').textContent = 'VPN UNKNOWN'; } }
function setupVpnMonitor() {
  const button = qs<HTMLButtonElement>('#vpn-monitor-button'), panel = qs('#vpn-monitor');
  button.onclick = event => { event.stopPropagation(); panel.hidden = !panel.hidden; button.setAttribute('aria-expanded', String(!panel.hidden)); if (!panel.hidden) void refreshVpnStatus(); };
  panel.addEventListener('click', event => event.stopPropagation()); document.addEventListener('click', () => { panel.hidden = true; button.setAttribute('aria-expanded', 'false'); });
  document.addEventListener('keydown', event => { if (event.key === 'Escape') { panel.hidden = true; button.setAttribute('aria-expanded', 'false'); } });
  qs('#vpn-settings-link').addEventListener('click', () => { panel.hidden = true; openVpnSettings(); });
  qs('#vpn-action').addEventListener('click', async () => { if (!vpnStatus?.configured) return openVpnSettings(); if (vpnStatus.state === 'connected') { await request('/api/vpn/disconnect', { method: 'POST' }); return void refreshVpnStatus(); } if (vpnStatus.authenticationRequired === false) { if (!confirm('Connect using certificate-only test mode? No user authentication will be requested.')) return; await request('/api/vpn/connect', { method: 'POST', body: '{}' }); return void refreshVpnStatus(); } qs<HTMLFormElement>('#vpn-connect-form').reset(); qs('#vpn-connect-error').textContent = ''; qs<HTMLDialogElement>('#vpn-connect-dialog').showModal(); requestAnimationFrame(() => qs<HTMLInputElement>('#vpn-username').focus()); });
  void refreshVpnStatus(); setInterval(() => { if (!panel.hidden) void refreshVpnStatus(); else renderVpnStatus(); }, 1000);
}

async function boot() { const status = await request<{ identity: Identity | null; authMode: string }>('/api/auth/status'); if (!status.identity) { show('login-view'); const notice = sessionStorage.getItem('hedgeweb.authNotice'); if (notice) { qs('#login-error').textContent = notice; sessionStorage.removeItem('hedgeweb.authNotice'); } return; } identity = status.identity; authMode = status.authMode; show('desktop-view'); qs('#current-user').textContent = identity.username; qs('#auth-source').textContent = identity.source === 'authentik' ? 'Authentik' : 'Local account'; qs('.avatar').textContent = identity.username[0]!.toUpperCase(); updateClock(); setInterval(updateClock, 30_000); setupVpnMonitor(); await Promise.all([loadProfiles(), loadRdpProfiles()]); }
function focusWindow(win: ManagedWindow) { const wasHidden = win.element.hidden; topZ++; win.element.style.zIndex = String(topZ); win.element.hidden = false; win.task.classList.add('active'); if (wasHidden) requestAnimationFrame(() => win.fit?.fit()); }
function closeWindow(id: string) { const win = windows.get(id); if (!win) return; win.cleanup?.(); win.socket?.close(); win.element.remove(); win.task.remove(); windows.delete(id); }

function createWindow(id: string, icon: string, title: string, content: Node, options: { width?: number; height?: number; x?: number; y?: number } = {}) {
  const existing = windows.get(id); if (existing) { focusWindow(existing); return existing; }
  const element = document.createElement('article'); element.className = 'app-window'; element.style.cssText = `width:${options.width || 760}px;height:${options.height || 520}px;left:${options.x ?? 110 + windows.size * 28}px;top:${options.y ?? 86 + windows.size * 24}px`;
  element.innerHTML = `<header class="window-titlebar"><div><span class="mini-icon">${icon}</span><strong>${escapeHtml(title)}</strong></div><div class="window-actions"><button data-minimize>−</button><button data-maximize>□</button><button data-window-close>×</button></div></header><div class="window-content"></div>`; qs('.window-content', element).append(content); qs('#window-layer').append(element);
  const task = document.createElement('button'); task.className = 'task-item active'; task.textContent = title; qs('#task-items').append(task); const managed: ManagedWindow = { id, element, task }; windows.set(id, managed); focusWindow(managed);
  element.addEventListener('pointerdown', () => { if (element.style.zIndex !== String(topZ)) focusWindow(managed); }); task.onclick = () => element.hidden ? focusWindow(managed) : (element.hidden = true, task.classList.remove('active')); qs<HTMLButtonElement>('[data-window-close]', element).onclick = () => closeWindow(id); qs<HTMLButtonElement>('[data-minimize]', element).onclick = () => { element.hidden = true; task.classList.remove('active'); }; qs<HTMLButtonElement>('[data-maximize]', element).onclick = () => { element.classList.toggle('maximized'); requestAnimationFrame(() => managed.fit?.fit()); }; makeDraggable(element, qs('.window-titlebar', element)); return managed;
}
function makeDraggable(element: HTMLElement, handle: HTMLElement) { let startX = 0, startY = 0, left = 0, top = 0; handle.addEventListener('pointerdown', event => { if ((event.target as HTMLElement).closest('button') || element.classList.contains('maximized')) return; startX = event.clientX; startY = event.clientY; left = element.offsetLeft; top = element.offsetTop; handle.setPointerCapture(event.pointerId); }); handle.addEventListener('pointermove', event => { if (!handle.hasPointerCapture(event.pointerId)) return; element.style.left = `${Math.max(0, left + (event.clientX - startX) / applicationScale)}px`; element.style.top = `${Math.max(48, top + (event.clientY - startY) / applicationScale)}px`; }); }

function enableDesktopIcons() {
  const area = qs<HTMLElement>('.desktop-icons');
  area.querySelectorAll<HTMLButtonElement>('[data-open-app]').forEach((icon, index) => {
    const appId = icon.dataset.openApp as AppId;
    const saved = localStorage.getItem(`hedgeweb.icon.${appId}`);
    const position = saved ? JSON.parse(saved) as { x: number; y: number } : { x: 20, y: 70 + index * 104 };
    icon.style.left = `${position.x}px`; icon.style.top = `${position.y}px`;
    let pointerId = -1, startX = 0, startY = 0, originX = 0, originY = 0, dragged = false;
    icon.addEventListener('pointerdown', event => {
      if (event.button !== 0) return;
      pointerId = event.pointerId; startX = event.clientX; startY = event.clientY;
      originX = icon.offsetLeft; originY = icon.offsetTop; dragged = false;
      icon.setPointerCapture(pointerId); icon.classList.add('dragging');
    });
    icon.addEventListener('pointermove', event => {
      if (event.pointerId !== pointerId || !icon.hasPointerCapture(pointerId)) return;
      const dx = event.clientX - startX, dy = event.clientY - startY;
      if (Math.hypot(dx, dy) > 4) dragged = true;
      if (!dragged) return;
      const x = Math.max(4, Math.min(area.clientWidth - icon.offsetWidth - 4, originX + dx));
      const y = Math.max(52, Math.min(area.clientHeight - icon.offsetHeight - 48, originY + dy));
      icon.style.left = `${x}px`; icon.style.top = `${y}px`;
    });
    const finish = (event: PointerEvent) => {
      if (event.pointerId !== pointerId) return;
      if (icon.hasPointerCapture(pointerId)) icon.releasePointerCapture(pointerId);
      icon.classList.remove('dragging'); pointerId = -1;
      if (dragged) localStorage.setItem(`hedgeweb.icon.${appId}`, JSON.stringify({ x: icon.offsetLeft, y: icon.offsetTop }));
    };
    icon.addEventListener('pointerup', finish); icon.addEventListener('pointercancel', finish);
    icon.addEventListener('click', event => { if (dragged) { event.preventDefault(); event.stopImmediatePropagation(); dragged = false; } }, true);
  });
}

function openApp(appId: AppId) {
  qs('#launcher').hidden = true;
  if (appId === 'ssh') { const win = createWindow('app:ssh', '›_', 'SSH Manager', qs<HTMLTemplateElement>('#ssh-manager-template').content.cloneNode(true), { width: 820, height: 560, x: 80, y: 76 }); qs<HTMLButtonElement>('.new-profile', win.element).hidden = !identity?.admin; qs<HTMLButtonElement>('.new-profile', win.element).onclick = openProfileDialog; renderProfiles(); }
  else if (appId === 'rdp') { const win = createWindow('app:rdp', '▣', 'RDP Manager', qs<HTMLTemplateElement>('#rdp-manager-template').content.cloneNode(true), { width: 820, height: 560, x: 95, y: 76 }); qs<HTMLButtonElement>('.new-rdp-profile', win.element).hidden = !identity?.admin; qs<HTMLButtonElement>('.new-rdp-profile', win.element).onclick = () => { qs<HTMLFormElement>('#rdp-profile-form').reset(); qs<HTMLDialogElement>('#rdp-profile-dialog').showModal(); }; renderRdpProfiles(); }
  else if (appId === 'browser') { const win = createWindow('app:browser', '◎', 'Web Browser', qs<HTMLTemplateElement>('#browser-template').content.cloneNode(true), { width: 980, height: 650, x: 105, y: 64 }); setupBrowser(win); }
  else if (appId === 'settings') { const win = createWindow('app:settings', '⚙', 'Settings', qs<HTMLTemplateElement>('#settings-template').content.cloneNode(true), { width: 760, height: 650, x: 150, y: 74 }); setupSettings(win); }
  else createWindow('app:about', 'H', 'About HedgeWeb', qs<HTMLTemplateElement>('#about-template').content.cloneNode(true), { width: 440, height: 440, x: 220, y: 125 });
}

function selectSettingsPage(win: ManagedWindow, page: 'general' | 'vpn') { win.element.querySelectorAll<HTMLButtonElement>('[data-settings-page]').forEach(button => button.classList.toggle('active', button.dataset.settingsPage === page)); win.element.querySelectorAll<HTMLElement>('[data-settings-panel]').forEach(panel => panel.hidden = panel.dataset.settingsPanel !== page); }
async function loadVpnConfig(win: ManagedWindow) { const config = await request<VpnConfigView>('/api/vpn/config'); const form = qs<HTMLFormElement>('#vpn-config-form', win.element); qs('#vpn-config-state', win.element).textContent = config.configured ? `Configured · ${config.endpointLabel}${config.certificateOnly ? ' · TEST MODE' : ''}` : 'Not configured'; if (config.configured) { (form.elements.namedItem('endpointLabel') as HTMLInputElement).value = config.endpointLabel || ''; (form.elements.namedItem('accessScope') as HTMLInputElement).value = config.accessScope || ''; (form.elements.namedItem('leaseMinutes') as HTMLSelectElement).value = String(config.leaseMinutes || 60); (form.elements.namedItem('certificateOnly') as HTMLInputElement).checked = Boolean(config.certificateOnly); (form.elements.namedItem('profile') as HTMLTextAreaElement).required = false; (form.elements.namedItem('profile') as HTMLTextAreaElement).placeholder = 'Encrypted profile saved — paste a replacement profile to update it'; } }
function setupSettings(win: ManagedWindow) {
  qs('#settings-auth', win.element).textContent = `${authMode} mode · signed in through ${identity?.source}`;
  const scaleSelect = qs<HTMLSelectElement>('#application-scale', win.element); scaleSelect.value = String(applicationScale); scaleSelect.onchange = () => { applicationScale = Number(scaleSelect.value); localStorage.setItem('hedgeweb.applicationScale', String(applicationScale)); document.documentElement.style.setProperty('--application-scale', String(applicationScale)); windows.forEach(item => requestAnimationFrame(() => item.fit?.fit())); };
  win.element.querySelectorAll<HTMLButtonElement>('[data-settings-page]').forEach(button => button.onclick = () => selectSettingsPage(win, button.dataset.settingsPage as 'general' | 'vpn'));
  const form = qs<HTMLFormElement>('#vpn-config-form', win.element); if (!identity?.admin) form.querySelectorAll<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLButtonElement>('input,select,textarea,button').forEach(control => control.disabled = true);
  form.onsubmit = async event => { event.preventDefault(); qs('#vpn-config-error', win.element).textContent = ''; try { const values = Object.fromEntries(new FormData(form)); await request('/api/vpn/config', { method: 'PUT', body: JSON.stringify(values) }); (form.elements.namedItem('profile') as HTMLTextAreaElement).value = ''; await loadVpnConfig(win); await refreshVpnStatus(); } catch (error) { qs('#vpn-config-error', win.element).textContent = (error as Error).message; } };
  void loadVpnConfig(win).catch(error => qs('#vpn-config-error', win.element).textContent = error.message);
}
function openVpnSettings() { openApp('settings'); const win = windows.get('app:settings'); if (win) selectSettingsPage(win, 'vpn'); }

function setupBrowser(win: ManagedWindow) {
  const form = qs<HTMLFormElement>('.browser-toolbar', win.element), address = qs<HTMLInputElement>('.browser-address', win.element), frame = qs<HTMLIFrameElement>('.browser-frame', win.element);
  const back = qs<HTMLButtonElement>('[data-browser-back]', win.element), forward = qs<HTMLButtonElement>('[data-browser-forward]', win.element), reload = qs<HTMLButtonElement>('[data-browser-reload]', win.element), external = qs<HTMLButtonElement>('[data-browser-external]', win.element);
  const history = ['https://example.com/']; let position = 0;
  const normalizeAddress = (value: string) => { const candidate = /^[a-z][a-z0-9+.-]*:/i.test(value.trim()) ? value.trim() : `https://${value.trim()}`; const url = new URL(candidate); if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP and HTTPS addresses are supported'); if (url.origin === location.origin) throw new Error('HedgeWeb cannot embed itself'); return url.href; };
  const render = () => { const url = history[position]!; address.value = url; back.disabled = position === 0; forward.disabled = position === history.length - 1; };
  const navigate = (value: string) => { try { const url = normalizeAddress(value); history.splice(position + 1); history.push(url); position = history.length - 1; render(); frame.src = url; } catch (error) { address.setCustomValidity((error as Error).message); address.reportValidity(); } };
  address.oninput = () => address.setCustomValidity(''); form.onsubmit = event => { event.preventDefault(); navigate(address.value); };
  back.onclick = () => { if (position > 0) { position--; render(); } }; forward.onclick = () => { if (position < history.length - 1) { position++; render(); } };
  reload.onclick = () => { const current = frame.src; frame.src = 'about:blank'; requestAnimationFrame(() => frame.src = current); };
  external.onclick = () => { try { frame.src = normalizeAddress(address.value); } catch (error) { address.setCustomValidity((error as Error).message); address.reportValidity(); } }; frame.src = history[0]!; render();
}
async function loadProfiles() { profiles = await request<Profile[]>('/api/profiles'); renderProfiles(); }
function renderProfiles() { const win = windows.get('app:ssh'); if (!win) return; const list = qs('.profile-list', win.element); list.innerHTML = profiles.length ? profiles.map(profile => `<article class="profile-card"><span class="device-status"></span><div><strong>${escapeHtml(profile.name)}</strong><small>${escapeHtml(profile.username)}@${escapeHtml(profile.host)}:${profile.port}</small><em>${profile.shell === 'nu' ? 'Nushell' : 'Default shell'}${profile.folder ? ` · ${escapeHtml(profile.folder)}` : ''}</em></div><button class="connect-button" data-profile-id="${profile.id}">Connect</button></article>`).join('') : '<div class="empty-state"><span class="app-icon terminal-icon">›_</span><h3>No connections yet</h3><p>Add an SSH connection to open your first terminal.</p></div>'; list.querySelectorAll<HTMLButtonElement>('[data-profile-id]').forEach(button => button.onclick = () => openConnection(button.dataset.profileId!)); }
async function loadRdpProfiles() { rdpProfiles = await request<RdpProfile[]>('/api/rdp/profiles'); renderRdpProfiles(); }
function renderRdpProfiles() { const win = windows.get('app:rdp'); if (!win) return; const list = qs('.rdp-profile-list', win.element); list.innerHTML = rdpProfiles.length ? rdpProfiles.map(profile => `<article class="profile-card"><span class="device-status"></span><div><strong>${escapeHtml(profile.name)}</strong><small>${escapeHtml(profile.domain ? `${profile.domain}\\` : '')}${escapeHtml(profile.username || 'Prompt at connection')} · ${escapeHtml(profile.host)}:${profile.port}</small><em>${profile.security === 'nla' ? 'Network Level Authentication' : profile.security === 'tls' ? 'TLS security' : 'Negotiate security'}</em></div><button class="connect-button" data-rdp-profile-id="${profile.id}">Connect</button></article>`).join('') : '<div class="empty-state"><span class="app-icon rdp-icon">▣</span><h3>No RDP connections yet</h3><p>Add a destination now; a Guacamole gateway is required to open sessions.</p></div>'; list.querySelectorAll<HTMLButtonElement>('[data-rdp-profile-id]').forEach(button => button.onclick = () => alert('The RDP profile is ready. Connect a Guacamole gateway to enable browser-based RDP sessions and full screen.')); }
function openProfileDialog() { qs<HTMLFormElement>('#profile-form').reset(); qs<HTMLDialogElement>('#profile-dialog').showModal(); }
function openConnection(id: string) { pendingProfile = profiles.find(profile => profile.id === id)!; const input = qs<HTMLInputElement>('#ssh-password'); input.value = ''; qs('#connect-title').textContent = `Connect to ${pendingProfile.name}`; qs<HTMLDialogElement>('#connect-dialog').showModal(); requestAnimationFrame(() => input.focus()); }

function connect(profile: Profile, password: string) {
  qs<HTMLDialogElement>('#connect-dialog').close(); pendingPassword = password; const id = `terminal:${++terminalSequence}`, host = document.createElement('div'); host.className = 'terminal-host'; const win = createWindow(id, '›_', profile.name, host, { width: Math.round(850 * applicationScale), height: Math.round(540 * applicationScale), x: 125, y: 92 }); win.element.classList.add('terminal-window');
  const terminal = new Terminal({ cursorBlink: true, cursorStyle: 'bar', cursorInactiveStyle: 'bar', cursorWidth: 2, convertEol: true, scrollback: 5000, theme: neonTerminalTheme, fontFamily: '"Cascadia Mono", "JetBrains Mono", "Fira Code", Consolas, monospace', fontSize: Math.max(12, Math.round(14 * applicationScale)), lineHeight: 1.2, letterSpacing: 0.2, fontWeight: '400', fontWeightBold: '700', drawBoldTextInBrightColors: true, minimumContrastRatio: 1, rightClickSelectsWord: true }), fit = new FitAddon(); terminal.loadAddon(fit); terminal.open(host); terminal.options.theme = neonTerminalTheme; terminal.write('\x1b[?25h'); win.fit = fit;
  let fitFrame = 0, lastWidth = 0, lastHeight = 0;
  const scheduleFit = () => { cancelAnimationFrame(fitFrame); fitFrame = requestAnimationFrame(() => { const width = host.clientWidth, height = host.clientHeight; if (!width || !height || (width === lastWidth && height === lastHeight)) return; lastWidth = width; lastHeight = height; fit.fit(); }); };
  const resizeObserver = new ResizeObserver(scheduleFit); resizeObserver.observe(host); win.cleanup = () => { resizeObserver.disconnect(); cancelAnimationFrame(fitFrame); terminal.dispose(); }; scheduleFit(); requestAnimationFrame(() => terminal.focus());
  terminal.attachCustomKeyEventHandler(event => {
    if (event.type !== 'keydown' || !event.ctrlKey || !event.shiftKey) return true;
    if (event.code === 'KeyC' && terminal.hasSelection()) { void navigator.clipboard.writeText(terminal.getSelection()); return false; }
    if (event.code === 'KeyV') { void navigator.clipboard.readText().then(text => terminal.paste(text)).catch(() => undefined); return false; }
    return true;
  });
  host.addEventListener('contextmenu', event => { event.preventDefault(); terminal.focus(); void navigator.clipboard.readText().then(text => terminal.paste(text)).catch(() => undefined); });
  terminal.writeln(`\x1b[95mHEDGE//WEB\x1b[0m  \x1b[96mSECURE SSH CHANNEL\x1b[0m`); terminal.writeln(`\x1b[90mTARGET ::\x1b[0m \x1b[93m${profile.username}@${profile.host}:${profile.port}\x1b[0m`); terminal.writeln('\x1b[90mNEGOTIATING HOST KEY + CIPHER…\x1b[0m');
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:', socket = new WebSocket(`${protocol}//${location.host}/ws/ssh`); win.socket = socket; socket.onopen = () => socket.send(JSON.stringify({ type: 'connect', profileId: profile.id, password, rows: terminal.rows, cols: terminal.cols })); socket.onmessage = async event => { const message = JSON.parse(event.data); if (message.type === 'output') terminal.write(message.data); if (message.type === 'ready') { terminal.writeln(`\r\n\x1b[32mConnected${message.shell === 'nu' ? ' · starting Nushell' : ''}\x1b[0m\r\n`); requestAnimationFrame(() => terminal.focus()); } if (message.type === 'error') terminal.writeln(`\r\n\x1b[31m${message.message}\x1b[0m`); if (message.type === 'hostkey_required') { const approved = confirm(`The host key is not trusted.\n\n${message.fingerprint}\n\nVerify this fingerprint independently. Trust and save it?`); if (approved) { await request(`/api/profiles/${profile.id}/host-key`, { method: 'PUT', body: JSON.stringify({ fingerprint: message.fingerprint }) }); await loadProfiles(); closeWindow(id); connect(profile, pendingPassword); } } }; socket.onclose = () => terminal.writeln('\r\n\x1b[33mConnection closed\x1b[0m'); terminal.onData(data => socket.readyState === WebSocket.OPEN && socket.send(JSON.stringify({ type: 'input', data }))); terminal.onResize(({ rows, cols }) => socket.readyState === WebSocket.OPEN && socket.send(JSON.stringify({ type: 'resize', rows, cols })));
}

qs<HTMLFormElement>('#login-form').onsubmit = async event => { event.preventDefault(); try { await request('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: qs<HTMLInputElement>('#login-username').value, password: qs<HTMLInputElement>('#login-password').value }) }); location.reload(); } catch (error) { qs('#login-error').textContent = (error as Error).message; } };
qs('#logout').onclick = async () => { await request('/api/auth/logout', { method: 'POST' }); location.reload(); }; qs('#launcher-button').onclick = () => qs('#launcher').hidden = !qs('#launcher').hidden; qs('#launcher-close').onclick = () => qs('#launcher').hidden = true; qs('#user-button').onclick = () => qs('#user-menu').hidden = !qs('#user-menu').hidden; document.querySelectorAll<HTMLElement>('[data-open-app]').forEach(button => button.onclick = () => openApp(button.dataset.openApp as AppId)); enableDesktopIcons(); qs('#show-desktop').onclick = () => windows.forEach(win => { win.element.hidden = true; win.task.classList.remove('active'); });
qs<HTMLFormElement>('#profile-form').onsubmit = async event => { event.preventDefault(); try { await request('/api/profiles', { method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget as HTMLFormElement))) }); qs<HTMLDialogElement>('#profile-dialog').close(); await loadProfiles(); } catch (error) { alert((error as Error).message); } }; qs<HTMLFormElement>('#connect-form').onsubmit = event => { event.preventDefault(); if (pendingProfile) connect(pendingProfile, qs<HTMLInputElement>('#ssh-password').value); }; qs<HTMLInputElement>('#ssh-password').addEventListener('keydown', event => event.stopPropagation()); qs<HTMLInputElement>('#ssh-password').addEventListener('keyup', event => event.stopPropagation()); document.querySelectorAll<HTMLElement>('[data-close]').forEach(button => button.onclick = () => qs<HTMLDialogElement>(`#${button.dataset.close}`).close()); boot().catch(error => { qs('#fatal').textContent = error.message; });
qs<HTMLFormElement>('#rdp-profile-form').onsubmit = async event => { event.preventDefault(); try { await request('/api/rdp/profiles', { method: 'POST', body: JSON.stringify(Object.fromEntries(new FormData(event.currentTarget as HTMLFormElement))) }); qs<HTMLDialogElement>('#rdp-profile-dialog').close(); await loadRdpProfiles(); } catch (error) { alert((error as Error).message); } };
qs<HTMLFormElement>('#vpn-connect-form').onsubmit = async event => { event.preventDefault(); qs('#vpn-connect-error').textContent = ''; try { await request('/api/vpn/connect', { method: 'POST', body: JSON.stringify({ username: qs<HTMLInputElement>('#vpn-username').value, password: qs<HTMLInputElement>('#vpn-password').value, otp: qs<HTMLInputElement>('#vpn-otp').value }) }); qs<HTMLInputElement>('#vpn-password').value = ''; qs<HTMLInputElement>('#vpn-otp').value = ''; qs<HTMLDialogElement>('#vpn-connect-dialog').close(); await refreshVpnStatus(); } catch (error) { qs('#vpn-connect-error').textContent = (error as Error).message; } };
qs<HTMLDialogElement>('#vpn-connect-dialog').addEventListener('close', () => { qs<HTMLInputElement>('#vpn-password').value = ''; qs<HTMLInputElement>('#vpn-otp').value = ''; });
