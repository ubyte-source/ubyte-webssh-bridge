import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { UTerminal } from '../public/javascript/terminal.js';

const modules = new URL('../public/javascript/', import.meta.url);

async function ours() {
  return (await readdir(modules)).filter((name) => name.endsWith('.js')).sort();
}

test('terminal: framed is true for a window whose top is another window', () => {
  const win = {};
  win.self = win;
  win.top = {};
  assert.equal(UTerminal.framed(win), true);
});

test('terminal: framed is false for a window that is its own top', () => {
  const win = {};
  win.self = win;
  win.top = win;
  assert.equal(UTerminal.framed(win), false);
});

test('terminal: linkable refuses javascript:, file:, data:, a custom scheme and text that is no URL', () => {
  for (const uri of ['javascript:alert(1)', 'JavaScript:alert(1)', 'file:///etc/passwd', 'data:text/html,x',
    'ssh://user01@example.test', 'vbscript:x', 'not a url', '//example.test/', '']) {
    assert.equal(UTerminal.linkable(uri), false, uri);
  }
});

test('terminal: linkable accepts http: and https: URLs', () => {
  for (const uri of ['http://example.test/', 'https://example.test:8443/path?q=1#f', 'HTTPS://EXAMPLE.TEST/',
    'http://192.0.2.10/', 'https://[2001:db8::1]/']) {
    assert.equal(UTerminal.linkable(uri), true, uri);
  }
});

test('terminal: no file of frontend/public/javascript calls console', async () => {
  const names = await ours();
  assert.ok(names.includes('terminal.js'));
  for (const name of names) {
    const source = await readFile(new URL(name, modules), 'utf8');
    assert.doesNotMatch(source, /\bconsole\b/, name);
  }
});

test('terminal: no file of frontend/public/javascript holds a class static block or calls requestSubmit', async () => {
  for (const name of await ours()) {
    const source = await readFile(new URL(name, modules), 'utf8');
    assert.doesNotMatch(source, /\bstatic\s*\{/, name);
    assert.doesNotMatch(source, /\brequestSubmit\b/, name);
  }
});

test('terminal: every module but main.js imports without a document or a window', async () => {
  assert.equal(globalThis.document, undefined);
  assert.equal(globalThis.window, undefined);
  for (const name of await ours()) {
    if (name === 'main.js') continue;
    const module = await import(new URL(name, modules));
    assert.ok(Object.keys(module).length > 0, name);
  }
});

test('terminal: the nested classes hang on UTerminal, none on the global object', () => {
  const { UAuthentication } = UTerminal;
  assert.deepEqual([UTerminal.UWebSocket, UTerminal.UGesture, UTerminal.UKeyBar, UTerminal.UStorage]
    .map((nested) => nested.name), ['UWebSocket', 'UGesture', 'UKeyBar', 'UStorage']);
  assert.deepEqual([UAuthentication.UElement, UAuthentication.UKeyZone, UAuthentication.UChallenge,
    UAuthentication.UAgent, UAuthentication.UAgent.UKey].map((nested) => nested.name),
  ['UElement', 'UKeyZone', 'UChallenge', 'UAgent', 'UKey']);
  for (const name of ['UTerminal', 'UAuthentication', 'UWebSocket', 'UKey', 'Terminal']) {
    assert.equal(name in globalThis, false, name);
  }
});

test('terminal: size bounds the columns and rows the page sends to 1-999 each', () => {
  const cases = [
    [{ cols: 80, rows: 24 }, { cols: 80, rows: 24 }],
    [{ cols: 999, rows: 999 }, { cols: 999, rows: 999 }],
    [{ cols: 1000, rows: 1190 }, { cols: 999, rows: 999 }],
    [{ cols: 0, rows: -1 }, { cols: 1, rows: 1 }],
    [{ cols: 1, rows: 2 }, { cols: 1, rows: 2 }],
  ];
  for (const [fitted, sent] of cases) assert.deepEqual(UTerminal.size(fitted), sent, JSON.stringify(fitted));
});

test('terminal: the connect message carries the bounded size of the new terminal, fitted to a wide window', (t) => {
  const terminal = new UTerminal();
  const begun = [];
  const agent = { begin: (user) => begun.push(user), identity: () => undefined };
  t.mock.method(terminal, 'getAuthentication', () => ({
    credentials: () => ({ user: 'user01', password: 'password-01' }),
    getAgent: () => agent,
  }));
  let built = null;
  t.mock.method(terminal, 'instance', () => built ??= { cols: 80, rows: 24 });
  t.mock.method(terminal, 'getFitAddon', () => ({
    fit: () => built !== null && Object.assign(built, { cols: 1190, rows: 40 }),
  }));
  const sent = [];
  terminal.opened({ send: (type, fields) => sent.push([type, fields]) });
  assert.deepEqual(begun, ['user01']);
  assert.deepEqual(sent, [['connect', { user: 'user01', password: 'password-01', key: undefined, cols: 999,
    rows: 40 }]]);
});

test('terminal: a font size set holds for the terminals of the next connections, the storage blocked', (t) => {
  globalThis.window = {
    matchMedia: () => ({ matches: true }),
    get localStorage() {
      throw new DOMException('The operation is insecure.', 'SecurityError');
    },
  };
  t.after(() => delete globalThis.window);
  const terminal = new UTerminal();
  const shown = { options: {} };
  t.mock.method(terminal, 'instance', () => shown);
  t.mock.method(terminal, 'fit', () => undefined);
  assert.equal(terminal.fontSize(), 13);
  terminal.setFontSize(21);
  assert.equal(shown.options.fontSize, 21);
  t.mock.method(terminal, 'instance', () => ({ options: {} }));
  assert.equal(terminal.fontSize(), 21);
});
