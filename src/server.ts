import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client as SshClient, type ClientChannel } from 'ssh2';
import { WebSocketServer, WebSocket } from 'ws';

type User = { id: string; username: string; salt: string; passwordHash: string; admin: boolean; createdAt: string };
type Profile = { id: string; name: string; host: string; port: number; username: string; folder: string; shell?: 'default' | 'nu'; hostKeySha256?: string; createdAt: string; updatedAt: string };
type RdpProfile = { id: string; name: string; host: string; port: number; username: string; domain: string; security: 'any' | 'nla' | 'tls'; createdAt: string; updatedAt: string };
type VpnConfig = { endpointLabel: string; accessScope: string; leaseMinutes: number; encryptedProfile: string; updatedAt: string };
type Store = { users: User[]; profiles: Profile[]; rdpProfiles: RdpProfile[]; vpn?: VpnConfig };
type Identity = { id: string; username: string; email?: string; groups: string[]; admin: boolean; source: 'local' | 'authentik' };
type LoginSession = { identity: Identity; expiresAt: number };

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..');
const publicDir = join(root, 'public');
const dataDir = process.env.DATA_DIR || join(root, 'data');
const storePath = join(dataDir, 'store.json');
const vpnKeyPath = join(dataDir, 'vpn-config.key');
const port = Number(process.env.PORT || 8080);
const authMode = process.env.AUTH_MODE || 'both';
const publicOrigin = process.env.PUBLIC_ORIGIN || `http://localhost:${port}`;
const trustedProxies = new Set((process.env.TRUSTED_PROXY_IPS || '127.0.0.1,::1').split(',').map(v => v.trim()).filter(Boolean));
const loginSessions = new Map<string, LoginSession>();
const loginAttempts = new Map<string, { failures: number; blockedUntil: number }>();

mkdirSync(dataDir, { recursive: true });
let store: Store = loadStore();
const vpnConfigKey = loadVpnConfigKey();
bootstrapAdmin();

function loadStore(): Store {
  if (!existsSync(storePath)) return { users: [], profiles: [], rdpProfiles: [] };
  const parsed = JSON.parse(readFileSync(storePath, 'utf8')) as Partial<Store>;
  return { users: Array.isArray(parsed.users) ? parsed.users : [], profiles: Array.isArray(parsed.profiles) ? parsed.profiles : [], rdpProfiles: Array.isArray(parsed.rdpProfiles) ? parsed.rdpProfiles : [], vpn: parsed.vpn };
}

function loadVpnConfigKey() {
  const configured = process.env.VPN_CONFIG_KEY_FILE ? readFileSync(process.env.VPN_CONFIG_KEY_FILE, 'utf8').trim() : process.env.VPN_CONFIG_KEY;
  if (configured) { const key = Buffer.from(configured, 'base64'); if (key.length !== 32) throw new Error('VPN_CONFIG_KEY must be 32 bytes encoded as base64'); return key; }
  if (existsSync(vpnKeyPath)) { const key = Buffer.from(readFileSync(vpnKeyPath, 'utf8').trim(), 'base64'); if (key.length === 32) return key; }
  const key = randomBytes(32); writeFileSync(vpnKeyPath, key.toString('base64'), { encoding: 'utf8', mode: 0o600 }); return key;
}
function encryptVpnProfile(profile: string) { const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', vpnConfigKey, iv); const encrypted = Buffer.concat([cipher.update(profile, 'utf8'), cipher.final()]); return [iv, cipher.getAuthTag(), encrypted].map(value => value.toString('base64url')).join('.'); }
function decryptVpnProfile(value: string) { const [iv, tag, encrypted] = value.split('.').map(part => Buffer.from(part!, 'base64url')); if (!iv || !tag || !encrypted) throw new Error('VPN configuration is corrupt'); const decipher = createDecipheriv('aes-256-gcm', vpnConfigKey, iv); decipher.setAuthTag(tag); return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8'); }
async function vpnAgent<T>(path: string, init?: RequestInit): Promise<T> { const response = await fetch(`http://127.0.0.1:9090${path}`, { ...init, headers: { 'content-type': 'application/json', ...(init?.headers || {}) } }); const result = await response.json() as T & { error?: string }; if (!response.ok) throw new Error(result.error || 'VPN agent request failed'); return result; }

function saveStore() {
  const temporary = `${storePath}.tmp`;
  writeFileSync(temporary, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
  renameSync(temporary, storePath);
}

function hashPassword(password: string, salt = randomBytes(16).toString('base64')) {
  return { salt, passwordHash: scryptSync(password, Buffer.from(salt, 'base64'), 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }).toString('base64') };
}

function verifyPassword(password: string, user: User) {
  const candidate = scryptSync(password, Buffer.from(user.salt, 'base64'), 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  const expected = Buffer.from(user.passwordHash, 'base64');
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

function bootstrapAdmin() {
  if (store.users.length) return;
  const username = process.env.BOOTSTRAP_ADMIN_USERNAME;
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!username || !password || password.length < 16) {
    console.warn('No local users exist. Set BOOTSTRAP_ADMIN_USERNAME and a BOOTSTRAP_ADMIN_PASSWORD of at least 16 characters.');
    return;
  }
  const passwordParts = hashPassword(password);
  store.users.push({ id: randomUUID(), username, ...passwordParts, admin: true, createdAt: new Date().toISOString() });
  saveStore();
  console.warn('Bootstrap administrator created. Remove BOOTSTRAP_ADMIN_PASSWORD from the environment.');
}

function clientIp(req: IncomingMessage) { return req.socket.remoteAddress?.replace(/^::ffff:/, '') || ''; }
function header(req: IncomingMessage, name: string) { const value = req.headers[name.toLowerCase()]; return Array.isArray(value) ? value[0] : value; }

function authentikIdentity(req: IncomingMessage): Identity | null {
  if (authMode === 'local' || !trustedProxies.has(clientIp(req))) return null;
  const username = header(req, process.env.AUTHENTIK_USER_HEADER || 'x-authentik-username')?.trim();
  if (!username) return null;
  const groups = (header(req, process.env.AUTHENTIK_GROUPS_HEADER || 'x-authentik-groups') || '').split(/[|,]/).map(v => v.trim()).filter(Boolean);
  return {
    id: `authentik:${username}`,
    username,
    email: header(req, process.env.AUTHENTIK_EMAIL_HEADER || 'x-authentik-email'),
    groups,
    admin: groups.includes(process.env.AUTHENTIK_ADMIN_GROUP || 'HedgeWeb Admins'),
    source: 'authentik'
  };
}

function cookies(req: IncomingMessage) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(v => v.trim().split('=').map(decodeURIComponent)).filter(v => v.length === 2) as [string, string][]);
}

function identity(req: IncomingMessage): Identity | null {
  const forwarded = authentikIdentity(req);
  if (forwarded) return forwarded;
  if (authMode === 'authentik') return null;
  const token = cookies(req).hedgeweb_session;
  const session = token ? loginSessions.get(token) : undefined;
  if (!session) return null;
  if (session.expiresAt <= Date.now()) { loginSessions.delete(token!); return null; }
  return session.identity;
}

function securityHeaders(res: ServerResponse) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self' ws: wss:; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-src http: https:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cache-Control', 'no-store');
}

function json(res: ServerResponse, status: number, value: unknown) {
  securityHeaders(res); res.statusCode = status; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.end(JSON.stringify(value));
}

async function body(req: IncomingMessage) {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > 64 * 1024) throw new Error('Request too large'); chunks.push(chunk); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>;
}

function sameOrigin(req: IncomingMessage) {
  const origin = req.headers.origin;
  if (!origin || origin === publicOrigin) return true;
  const forwardedProto = header(req, 'x-forwarded-proto')?.split(',')[0]?.trim();
  const protocol = forwardedProto === 'https' ? 'https' : 'http';
  const host = req.headers.host;
  return Boolean(host && origin === `${protocol}://${host}`);
}

function validProfile(input: Record<string, unknown>, current?: Profile): Profile {
  const name = String(input.name || '').trim(); const host = String(input.host || '').trim(); const username = String(input.username || '').trim();
  const folder = String(input.folder || '').trim().slice(0, 80); const requestedPort = Number(input.port || 22);
  if (!name || name.length > 120 || !host || host.length > 255 || !username || username.length > 128 || !Number.isInteger(requestedPort) || requestedPort < 1 || requestedPort > 65535) throw new Error('Invalid connection profile');
  if (/\s|[/?#@]/.test(host)) throw new Error('Host must be a hostname or IP address');
  const now = new Date().toISOString();
  const shell = input.shell === 'nu' ? 'nu' : 'default';
  return { id: current?.id || randomUUID(), name, host, port: requestedPort, username, folder, shell, hostKeySha256: current?.hostKeySha256, createdAt: current?.createdAt || now, updatedAt: now };
}

function validRdpProfile(input: Record<string, unknown>, current?: RdpProfile): RdpProfile {
  const name = String(input.name || '').trim(); const host = String(input.host || '').trim(); const username = String(input.username || '').trim(); const domain = String(input.domain || '').trim(); const requestedPort = Number(input.port || 3389);
  if (!name || name.length > 120 || !host || host.length > 255 || username.length > 128 || domain.length > 128 || !Number.isInteger(requestedPort) || requestedPort < 1 || requestedPort > 65535) throw new Error('Invalid RDP connection profile');
  if (/\s|[/?#@]/.test(host)) throw new Error('Host must be a hostname or IP address');
  const security = input.security === 'nla' || input.security === 'tls' ? input.security : 'any'; const now = new Date().toISOString();
  return { id: current?.id || randomUUID(), name, host, port: requestedPort, username, domain, security, createdAt: current?.createdAt || now, updatedAt: now };
}

async function api(req: IncomingMessage, res: ServerResponse, pathname: string) {
  if (!sameOrigin(req) && req.method !== 'GET') return json(res, 403, { error: 'Origin rejected' });
  if (pathname === '/api/auth/status' && req.method === 'GET') return json(res, 200, { identity: identity(req), authMode });
  if (pathname === '/api/auth/login' && req.method === 'POST' && authMode !== 'authentik') {
    const input = await body(req); const username = String(input.username || ''); const password = String(input.password || '');
    const attemptKey = `${clientIp(req)}:${username.toLowerCase()}`; const attempt = loginAttempts.get(attemptKey);
    if (attempt && attempt.blockedUntil > Date.now()) return json(res, 429, { error: 'Too many failed attempts. Try again later.' });
    const user = store.users.find(item => item.username.toLowerCase() === username.toLowerCase());
    if (!user || !verifyPassword(password, user)) {
      const failures = (attempt?.failures || 0) + 1; loginAttempts.set(attemptKey, { failures, blockedUntil: failures >= 5 ? Date.now() + 15 * 60_000 : 0 });
      return json(res, 401, { error: 'Invalid username or password' });
    }
    loginAttempts.delete(attemptKey);
    const token = randomBytes(32).toString('base64url'); const ttl = Number(process.env.SESSION_TTL_HOURS || 12) * 3600_000;
    loginSessions.set(token, { identity: { id: user.id, username: user.username, groups: [], admin: user.admin, source: 'local' }, expiresAt: Date.now() + ttl });
    const secure = process.env.COOKIE_SECURE !== 'false' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `hedgeweb_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(ttl / 1000)}${secure}`);
    return json(res, 200, { ok: true });
  }
  if (pathname === '/api/auth/logout' && req.method === 'POST') {
    const signingOut = identity(req);
    const token = cookies(req).hedgeweb_session; if (token) loginSessions.delete(token);
    try { const vpn = await vpnAgent<{ identity?: string; state: string }>('/status'); if (vpn.identity && vpn.identity === signingOut?.username && vpn.state !== 'disconnected') await vpnAgent('/disconnect', { method: 'POST' }); } catch { /* VPN agent is optional during logout. */ }
    res.setHeader('Set-Cookie', 'hedgeweb_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'); return json(res, 200, { ok: true });
  }
  const actor = identity(req); if (!actor) return json(res, 401, { error: 'Authentication required' });
  if (pathname === '/api/vpn/status' && req.method === 'GET') {
    if (!store.vpn) return json(res, 200, { configured: false, state: 'not_configured', identity: actor.username, endpoint: null, address: null, accessScope: 'No elevated routes', connectedAt: null, expiresAt: null, bytesReceived: 0, bytesSent: 0 });
    try { return json(res, 200, { configured: true, ...(await vpnAgent<Record<string, unknown>>('/status')) }); } catch (error) { return json(res, 200, { configured: true, state: 'error', identity: actor.username, endpoint: store.vpn.endpointLabel, address: null, accessScope: store.vpn.accessScope, connectedAt: null, expiresAt: null, bytesReceived: 0, bytesSent: 0, error: (error as Error).message }); }
  }
  if (pathname === '/api/vpn/config' && req.method === 'GET') return json(res, 200, store.vpn ? { configured: true, endpointLabel: store.vpn.endpointLabel, accessScope: store.vpn.accessScope, leaseMinutes: store.vpn.leaseMinutes, updatedAt: store.vpn.updatedAt } : { configured: false });
  if (pathname === '/api/vpn/config' && req.method === 'PUT') {
    if (!actor.admin) return json(res, 403, { error: 'Administrator access required' });
    const input = await body(req); const profile = String(input.profile || ''); const endpointLabel = String(input.endpointLabel || '').trim().slice(0, 120); const accessScope = String(input.accessScope || '').trim().slice(0, 180); const leaseMinutes = Number(input.leaseMinutes || 60);
    if (!endpointLabel || !accessScope || profile.length < 20 || profile.length > 256 * 1024 || !/^\s*client\b/im.test(profile) || !/^\s*remote\b/im.test(profile)) return json(res, 400, { error: 'A valid OpenVPN client profile, endpoint name and access scope are required' });
    if (/^\s*(up|down|route-up|ipchange|tls-verify|auth-user-pass-verify|client-connect|client-disconnect|learn-address|plugin|management|management-client|daemon|log|log-append|status|writepid|chroot|cd|setenv|setenv-safe|askpass|pkcs11-providers|pkcs11-id|script-security)\b/im.test(profile) || /<auth-user-pass>/i.test(profile)) return json(res, 400, { error: 'The profile contains a prohibited executable, credential or management directive' });
    if (!Number.isInteger(leaseMinutes) || leaseMinutes < 5 || leaseMinutes > 480) return json(res, 400, { error: 'Lease must be between 5 and 480 minutes' });
    store.vpn = { endpointLabel, accessScope, leaseMinutes, encryptedProfile: encryptVpnProfile(profile), updatedAt: new Date().toISOString() }; saveStore(); return json(res, 200, { configured: true, endpointLabel, accessScope, leaseMinutes, updatedAt: store.vpn.updatedAt });
  }
  if (pathname === '/api/vpn/connect' && req.method === 'POST') {
    if (!store.vpn) return json(res, 409, { error: 'Configure an OpenVPN profile first' });
    const current = await vpnAgent<{ state: string; identity?: string }>('/status'); if (current.state !== 'disconnected' && current.state !== 'error' && current.identity && current.identity !== actor.username) return json(res, 409, { error: `VPN is currently in use by ${current.identity}` });
    const input = await body(req); const username = String(input.username || '').trim(); const password = String(input.password || ''); const otp = String(input.otp || '').trim();
    if (!username || !password || (otp && !/^\d{6,8}$/.test(otp))) return json(res, 400, { error: 'Enter a username, password and a valid authenticator code' });
    const result = await vpnAgent('/connect', { method: 'POST', body: JSON.stringify({ profile: decryptVpnProfile(store.vpn.encryptedProfile), username, password, otp, identity: actor.username, endpoint: store.vpn.endpointLabel, accessScope: store.vpn.accessScope, leaseMinutes: store.vpn.leaseMinutes }) }); return json(res, 202, result);
  }
  if (pathname === '/api/vpn/disconnect' && req.method === 'POST') {
    const current = await vpnAgent<{ identity?: string }>('/status'); if (current.identity && current.identity !== actor.username && !actor.admin) return json(res, 403, { error: 'This VPN session belongs to another user' }); return json(res, 200, await vpnAgent('/disconnect', { method: 'POST' }));
  }
  if (pathname === '/api/profiles' && req.method === 'GET') return json(res, 200, store.profiles);
  if (pathname === '/api/rdp/profiles' && req.method === 'GET') return json(res, 200, store.rdpProfiles);
  if (req.method !== 'GET' && !actor.admin) return json(res, 403, { error: 'Administrator access required' });
  if (pathname === '/api/profiles' && req.method === 'POST') {
    const profile = validProfile(await body(req)); store.profiles.push(profile); saveStore(); return json(res, 201, profile);
  }
  if (pathname === '/api/rdp/profiles' && req.method === 'POST') { const profile = validRdpProfile(await body(req)); store.rdpProfiles.push(profile); saveStore(); return json(res, 201, profile); }
  const match = pathname.match(/^\/api\/profiles\/([0-9a-f-]+)$/);
  if (match && req.method === 'PUT') {
    const index = store.profiles.findIndex(item => item.id === match[1]); if (index < 0) return json(res, 404, { error: 'Profile not found' });
    store.profiles[index] = validProfile(await body(req), store.profiles[index]); saveStore(); return json(res, 200, store.profiles[index]);
  }
  if (match && req.method === 'DELETE') {
    const index = store.profiles.findIndex(item => item.id === match[1]); if (index < 0) return json(res, 404, { error: 'Profile not found' });
    store.profiles.splice(index, 1); saveStore(); return json(res, 200, { ok: true });
  }
  const keyMatch = pathname.match(/^\/api\/profiles\/([0-9a-f-]+)\/host-key$/);
  if (keyMatch && req.method === 'PUT') {
    const profile = store.profiles.find(item => item.id === keyMatch[1]); if (!profile) return json(res, 404, { error: 'Profile not found' });
    const input = await body(req); const fingerprint = String(input.fingerprint || '');
    if (!/^SHA256:[A-Za-z0-9+/]{43}=?$/.test(fingerprint)) return json(res, 400, { error: 'Invalid fingerprint' });
    profile.hostKeySha256 = fingerprint; profile.updatedAt = new Date().toISOString(); saveStore(); return json(res, 200, profile);
  }
  return json(res, 404, { error: 'Not found' });
}

function staticFile(req: IncomingMessage, res: ServerResponse, pathname: string) {
  const relative = pathname === '/' ? 'index.html' : pathname.slice(1);
  const target = normalize(join(publicDir, relative));
  if (!target.startsWith(publicDir) || !existsSync(target)) { res.statusCode = 404; return res.end('Not found'); }
  const types: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' };
  securityHeaders(res); res.setHeader('Content-Type', types[extname(target)] || 'application/octet-stream'); res.setHeader('Cache-Control', 'no-cache'); res.end(readFileSync(target));
}

const server = createServer(async (req, res) => {
  try { const pathname = new URL(req.url || '/', publicOrigin).pathname; if (pathname.startsWith('/api/')) await api(req, res, pathname); else staticFile(req, res, pathname); }
  catch (error) { console.error(error); json(res, 400, { error: error instanceof Error ? error.message : 'Bad request' }); }
});

const sockets = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
server.on('upgrade', (req, socket, head) => {
  const pathname = new URL(req.url || '/', publicOrigin).pathname;
  if (pathname !== '/ws/ssh' || !identity(req) || !sameOrigin(req)) return socket.destroy();
  sockets.handleUpgrade(req, socket, head, ws => sockets.emit('connection', ws, req));
});

sockets.on('connection', (ws: WebSocket) => {
  let ssh: SshClient | undefined; let channel: ClientChannel | undefined; let started = false; let observedFingerprint = '';
  const send = (value: unknown) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(value)); };
  ws.on('message', raw => {
    let message: Record<string, unknown>; try { message = JSON.parse(raw.toString()); } catch { return ws.close(1003, 'Invalid message'); }
    if (message.type === 'input' && channel) return channel.write(String(message.data || '').slice(0, 65536));
    if (message.type === 'resize' && channel) return channel.setWindow(Number(message.rows) || 24, Number(message.cols) || 80, 0, 0);
    if (message.type !== 'connect' || started) return;
    started = true; const profile = store.profiles.find(item => item.id === message.profileId); if (!profile) return ws.close(1008, 'Profile not found');
    const password = String(message.password || ''); if (!password || password.length > 4096) return ws.close(1008, 'Password required');
    ssh = new SshClient();
    ssh.on('ready', () => ssh!.shell({ term: 'xterm-256color', rows: Number(message.rows) || 24, cols: Number(message.cols) || 80 }, { env: { TERM: 'xterm-256color', COLORTERM: 'truecolor', CLICOLOR: '1' } }, (error, stream) => {
      if (error) { send({ type: 'error', message: 'Unable to open terminal' }); return ws.close(); }
      channel = stream; send({ type: 'ready', shell: profile.shell || 'default' }); stream.on('data', (data: Buffer) => send({ type: 'output', data: data.toString('utf8') })); stream.stderr.on('data', (data: Buffer) => send({ type: 'output', data: data.toString('utf8') })); stream.on('close', () => ws.close(1000));
      if (profile.shell === 'nu') stream.write("exec nu\r");
      else stream.write("if [ -n \"$BASH_VERSION\" ]; then export PS1='\\[\\e[38;5;46m\\]\\u\\[\\e[38;5;51m\\]@\\h \\[\\e[38;5;201m\\]\\w \\[\\e[38;5;226m\\]\\t \\[\\e[38;5;196m\\]\\$ \\[\\e[0m\\]'; fi\r");
    }));
    ssh.on('error', error => { if (observedFingerprint && !profile.hostKeySha256) send({ type: 'hostkey_required', fingerprint: observedFingerprint }); else send({ type: 'error', message: error.message.replace(password, '[redacted]') }); });
    ssh.on('close', () => { if (ws.readyState === WebSocket.OPEN) ws.close(); });
    ssh.connect({ host: profile.host, port: profile.port, username: profile.username, password, readyTimeout: 15000, keepaliveInterval: 15000, keepaliveCountMax: 3, hostHash: 'sha256', hostVerifier: (hash: string) => {
      observedFingerprint = `SHA256:${Buffer.from(hash, 'hex').toString('base64').replace(/=$/, '')}`;
      return profile.hostKeySha256 === observedFingerprint;
    }});
  });
  ws.on('close', () => { try { channel?.close(); } catch {} try { ssh?.end(); } catch {} });
});

setInterval(() => { const now = Date.now(); for (const [token, session] of loginSessions) if (session.expiresAt <= now) loginSessions.delete(token); }, 60_000).unref();
server.listen(port, '0.0.0.0', () => console.log(`HedgeWeb listening on port ${port}`));
