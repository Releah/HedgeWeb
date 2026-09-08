import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { readFile, rm, writeFile } from 'node:fs/promises';

const port = 9090;
let processHandle = null;
let state = 'disconnected';
let errorMessage = null;
let connectedAt = null;
let identity = null;
let endpoint = null;
let accessScope = 'No elevated routes';
let address = null;
let expiresAt = null;
let logTail = [];
let leaseTimer = null;

const forbidden = /^\s*(up|down|route-up|ipchange|tls-verify|auth-user-pass-verify|client-connect|client-disconnect|learn-address|plugin|management|management-client|daemon|log|log-append|status|writepid|chroot|cd|setenv|setenv-safe|askpass|pkcs11-providers|pkcs11-id|script-security)\b/im;
function validateProfile(profile) {
  if (typeof profile !== 'string' || profile.length < 20 || profile.length > 256 * 1024) throw new Error('Invalid OpenVPN profile');
  if (!/^\s*client\b/im.test(profile) || !/^\s*(remote|remote-random-hostname)\b/im.test(profile)) throw new Error('Profile must be an OpenVPN client profile with a remote endpoint');
  if (forbidden.test(profile) || /<auth-user-pass>/i.test(profile)) throw new Error(`Profile contains a prohibited directive: ${profile.match(forbidden)?.[1] || 'embedded auth-user-pass'}`);
  const sanitized = profile.split(/\r?\n/).filter(line => !/^\s*auth-user-pass(?:\s+.*)?$/i.test(line)).join('\n');
  return `${sanitized.trim()}\n\nauth-nocache\nauth-retry none\npull-filter ignore redirect-gateway\nscript-security 1\n`;
}
function json(res, statusCode, value) { res.writeHead(statusCode, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(value)); }
async function body(req) { const chunks = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > 300 * 1024) throw new Error('Request too large'); chunks.push(chunk); } return JSON.parse(Buffer.concat(chunks).toString() || '{}'); }
async function interfaceStats() {
  try {
    const [rx, tx] = await Promise.all([readFile('/sys/class/net/tun0/statistics/rx_bytes', 'utf8'), readFile('/sys/class/net/tun0/statistics/tx_bytes', 'utf8')]);
    return { bytesReceived: Number(rx.trim()) || 0, bytesSent: Number(tx.trim()) || 0 };
  } catch { return { bytesReceived: 0, bytesSent: 0 }; }
}
async function status() { return { configured: true, state, identity, endpoint, address, accessScope, connectedAt, expiresAt, error: errorMessage, ...(await interfaceStats()) }; }
async function disconnect() {
  if (leaseTimer) { clearTimeout(leaseTimer); leaseTimer = null; }
  if (processHandle) { processHandle.kill('SIGTERM'); processHandle = null; }
  state = 'disconnected'; connectedAt = null; address = null; expiresAt = null; identity = null;
  await Promise.allSettled([rm('/run/vpn/client.ovpn', { force: true }), rm('/run/vpn/auth', { force: true })]);
}
async function connect(input) {
  if (processHandle) await disconnect();
  const profile = validateProfile(input.profile);
  const username = String(input.username || '').trim(); const password = String(input.password || ''); const otp = String(input.otp || '').trim(); const certificateOnly = input.certificateOnly === true;
  if (!certificateOnly && (!username || !password)) throw new Error('VPN username and password are required');
  if (/[\r\n]/.test(username + password + otp)) throw new Error('Credentials contain invalid characters');
  const packedPassword = otp ? `SCRV1:${Buffer.from(password).toString('base64')}:${Buffer.from(otp).toString('base64')}` : password;
  await writeFile('/run/vpn/client.ovpn', profile, { mode: 0o600 }); if (!certificateOnly) await writeFile('/run/vpn/auth', `${username}\n${packedPassword}\n`, { mode: 0o600 });
  state = 'connecting'; errorMessage = null; identity = String(input.identity || username); endpoint = String(input.endpoint || 'OpenVPN'); accessScope = String(input.accessScope || 'Elevated routes'); expiresAt = new Date(Date.now() + Math.min(Math.max(Number(input.leaseMinutes) || 60, 5), 480) * 60_000).toISOString(); logTail = [];
  const args = ['--config', '/run/vpn/client.ovpn', '--dev', 'tun0', '--verb', '3']; if (!certificateOnly) args.push('--auth-user-pass', '/run/vpn/auth');
  const child = spawn('openvpn', args, { stdio: ['ignore', 'pipe', 'pipe'] }); processHandle = child;
  const consume = data => {
    for (const line of data.toString().split(/\r?\n/).filter(Boolean)) {
      const safe = line.replace(/(password|token|auth)[^ ]*/ig, '[redacted]'); logTail.push(safe.slice(-240)); if (logTail.length > 8) logTail.shift();
      if (/Initialization Sequence Completed/.test(line)) { state = 'connected'; connectedAt = new Date().toISOString(); }
      const ip = line.match(/net_addr_v4_add: ([0-9.]+)/)?.[1] || line.match(/ifconfig ([0-9.]+)/)?.[1]; if (ip) address = ip;
      if (/AUTH_FAILED|Options error|Exiting due to fatal error|TLS Error/.test(line)) { state = 'error'; errorMessage = safe.slice(-180); }
    }
  };
  child.stdout.on('data', consume); child.stderr.on('data', consume);
  child.on('exit', code => { if (processHandle === child) { processHandle = null; if (state !== 'error') state = code === 0 ? 'disconnected' : 'error'; if (code && !errorMessage) errorMessage = `OpenVPN exited with code ${code}`; connectedAt = null; address = null; void rm('/run/vpn/auth', { force: true }); } });
  leaseTimer = setTimeout(() => void disconnect(), Date.parse(expiresAt) - Date.now()); leaseTimer.unref();
  setTimeout(() => { if (processHandle === child && state === 'connecting') { errorMessage = 'VPN connection timed out'; state = 'error'; child.kill('SIGTERM'); } }, 45_000).unref();
}

createServer(async (req, res) => {
  try {
    if (req.url === '/status' && req.method === 'GET') return json(res, 200, await status());
    if (req.url === '/connect' && req.method === 'POST') { await connect(await body(req)); return json(res, 202, await status()); }
    if (req.url === '/disconnect' && req.method === 'POST') { await disconnect(); return json(res, 200, await status()); }
    return json(res, 404, { error: 'Not found' });
  } catch (error) { errorMessage = error.message; state = 'error'; return json(res, 400, { error: error.message }); }
}).listen(port, '127.0.0.1', () => console.log(`VPN agent listening on ${port}`));
