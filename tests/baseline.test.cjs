const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const entry = path.resolve(__dirname, '..', 'index.js');
const source = fs.readFileSync(entry, 'utf8');

function embeddedAsset(name) {
  const line = source.split('\n').find((item) => item.startsWith('  ' + name + ': '));
  assert.ok(line, 'Missing embedded asset: ' + name);
  const raw = line.slice(line.indexOf(': ') + 2).replace(/,$/, '');
  return JSON.parse(raw);
}

test('NovaPanel keeps the V3 primary protocol defaults', () => {
  const { BK_CONFIG } = require(entry);
  assert.equal(BK_CONFIG.brand, 'NovaPanel');
  assert.equal(BK_CONFIG.product, 'NovaPanel');
  assert.equal(BK_CONFIG.panelPath, 'knight');
  assert.equal(BK_CONFIG.enable.vlessWs, true);
  assert.equal(BK_CONFIG.enable.vlessWsTls, true);
  assert.equal(BK_CONFIG.enable.vmessWs, true);
  assert.equal(BK_CONFIG.enable.vmessWsTls, true);
  assert.equal(BK_CONFIG.enable.trojanWs, true);
  assert.equal(BK_CONFIG.enable.trojanWsTls, true);
  assert.equal(BK_CONFIG.enable.vlessHttpUpgrade, true);
  assert.equal(BK_CONFIG.enable.vlessGrpc, true);
  assert.equal(BK_CONFIG.enable.vlessXhttp, true);
  assert.equal(BK_CONFIG.enable.ssWs, true);
  assert.equal(BK_CONFIG.enable.reality, false);
  assert.equal(BK_CONFIG.enable.shadowsocks, false);
  assert.equal(BK_CONFIG.enable.wireguard, false);
});

test('the assigned PORT takes precedence over SERVER_PORT', () => {
  const script = 'process.stdout.write(String(require(' + JSON.stringify(entry) + ').BK_CONFIG.publicPort));';
  const result = spawnSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    timeout: 15000,
    env: { ...process.env, PORT: '18473', SERVER_PORT: '29091' }
  });
  assert.equal(result.status, 0, result.stderr || 'The config probe exited unsuccessfully.');
  assert.equal(result.stdout, '18473');
});

test('the embedded dashboard uses NovaPanel branding and the navy/jade palette', () => {
  const html = embeddedAsset('indexHtml');
  const css = embeddedAsset('appCss');
  const appJs = embeddedAsset('appJs');
  assert.match(html, /NovaPanel/);
  assert.match(html, /hero-abstract-art/);
  assert.doesNotMatch(html, /Blue Knight|WhiteDNS|whitedns|@BlueKnight_Net|BlueKnight-Net/);
  assert.match(css, /--bg-color: #071923;/);
  assert.match(css, /--primary-red: #34d399;/);
  assert.match(appJs, /NovaPanel/);
  assert.doesNotMatch(appJs, /Blue Knight|WhiteDNS|whitedns|@BlueKnight_Net|BlueKnight-Net/);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'novapanel-ui-test-'));
  try {
    const assetPath = path.join(tempDir, 'app.js');
    fs.writeFileSync(assetPath, appJs);
    const result = spawnSync(process.execPath, ['--check', assetPath], { encoding: 'utf8', timeout: 15000 });
    assert.equal(result.status, 0, result.stderr || 'The embedded browser JavaScript did not pass syntax validation.');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
