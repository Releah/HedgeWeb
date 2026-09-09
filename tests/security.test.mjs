import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('local secrets and diagnostic data are ignored', async () => {
  const ignore = await read('.gitignore');
  for (const entry of ['.diagnostic-data/', 'secrets/', '.env', '.env.docker', '*.ovpn', '*.key', '*.pem', '*.p12', '*.pfx']) assert.ok(ignore.split(/\r?\n/).includes(entry), `${entry} must be ignored`);
});

test('VPN profiles and encrypted runtime data cannot be committed by default', async () => {
  const ignore = await read('.gitignore'); const compose = await read('compose.yaml');
  assert.ok(ignore.split(/\r?\n/).includes('*.ovpn'));
  assert.ok(ignore.split(/\r?\n/).includes('data/'));
  assert.match(compose, /hedgeweb-data:\/data/);
  assert.doesNotMatch(compose, /\.ovpn:/);
});

test('VPN agent drops capabilities except NET_ADMIN', async () => {
  for (const file of ['compose.yaml', 'compose.local.yaml']) {
    const compose = await read(file);
    const agent = compose.split(/^  hedgeweb:/m)[0];
    assert.match(agent, /cap_drop:\s*\n\s*- ALL/);
    assert.match(agent, /cap_add:\s*\n\s*- NET_ADMIN/);
    assert.match(agent, /no-new-privileges:true/);
    assert.doesNotMatch(agent, /privileged:\s*true/);
  }
});

test('production VPN key is required from the deployment environment', async () => {
  const compose = await read('compose.yaml');
  const server = await read('src/server.ts');
  assert.match(compose, /VPN_CONFIG_KEY:\s*\$\{VPN_CONFIG_KEY:\?/);
  assert.doesNotMatch(compose, /VPN_CONFIG_KEY_FILE|file:\s*\.\/secrets\/vpn_config_key/);
  assert.match(server, /process\.env\.VPN_CONFIG_KEY_FILE/);
});

test('dangerous OpenVPN directives remain blocked', async () => {
  const agent = await read('vpn-agent/server.mjs');
  for (const directive of ['plugin', 'management', 'script-security', 'tls-verify', 'pkcs11-providers']) assert.ok(agent.includes(directive), `${directive} must remain blocked`);
  assert.match(agent, /pull-filter ignore redirect-gateway/);
});

test('isolated browser is pinned, unexposed and capability constrained', async () => {
  for (const file of ['compose.yaml', 'compose.local.yaml']) {
    const compose = await read(file); const browser = compose.split(/^  browser:/m)[1];
    assert.ok(browser, `${file} must define the browser worker`);
    assert.match(browser, /chromium:[^\s]+@sha256:[a-f0-9]{64}/);
    assert.match(browser, /network_mode:\s*"service:vpn-agent"/);
    assert.match(browser, /cap_drop:\s*\n\s*- ALL/);
    assert.match(browser, /no-new-privileges:true/);
    assert.match(browser, /SELKIES_ENABLE_SHARING:\s*"false"/);
    assert.match(browser, /SELKIES_FILE_TRANSFERS:\s*none/);
    assert.doesNotMatch(browser, /privileged:\s*true|docker\.sock|\n\s+ports:/);
  }
});

test('browser WebSocket proxy strips session headers without undefined values', async () => {
  const server = await read('src/server.ts');
  assert.match(server, /function browserUpgradeHeaders/);
  assert.match(server, /value !== undefined/);
  assert.doesNotMatch(server, /cookie:\s*undefined|authorization:\s*undefined/);
});
