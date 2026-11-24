import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { UWebSocket } from '../public/javascript/websocket.js';

const corpus = JSON.parse(await readFile(new URL('./fixtures/protocol.json', import.meta.url), 'utf8'));

function socket() {
  const listeners = new Map();
  const fake = {
    sent: [],
    closed: [],
    addEventListener: (type, listener) => listeners.set(type, listener),
    send: (data) => fake.sent.push(data),
    close: (code) => fake.closed.push(code),
    emit: (type, event) => listeners.get(type)(event),
  };
  return fake;
}

function listener() {
  const heard = [];
  return {
    heard: heard,
    opened: (ws) => heard.push(['opened', ws]),
    received: (ws, message) => heard.push(['received', message]),
    output: (ws, bytes) => heard.push(['output', [...bytes]]),
    closed: (ws, code) => heard.push(['closed', code]),
  };
}

test('websocket: encode writes every valid page frame of the corpus from its fields, byte for byte in protocol order',
  () => {
    const valid = corpus.page.filter((entry) => entry.valid);
    assert.ok(valid.length > 0);
    for (const { name, frame, fields } of valid) {
      const written = UWebSocket.encode(fields.type, fields);
      const order = (text) => Object.keys(JSON.parse(text)).join();
      if (order(written) === order(frame)) assert.equal(written, frame, name);
      else assert.deepEqual(JSON.parse(written), JSON.parse(frame), name);
    }
  });

test('websocket: parse reads every bridge frame of the corpus into its fields', () => {
  assert.deepEqual(new Set(corpus.bridge.map((entry) => entry.fields.type)),
    new Set(['banner', 'challenge', 'sign', 'ready', 'exit']));
  for (const { name, frame, fields } of corpus.bridge) assert.deepEqual(UWebSocket.parse(frame), fields, name);
});

test('websocket: parse refuses every page frame of the corpus that is not a bridge frame', () => {
  const bridge = new Set(corpus.bridge.map((entry) => entry.frame));
  const frames = corpus.page.filter((entry) => entry.frame !== undefined && !bridge.has(entry.frame));
  assert.ok(frames.length > 0);
  for (const { name, frame } of frames) assert.equal(UWebSocket.parse(frame), null, name);
});

test('websocket: parse refuses bridge messages with a member unknown, missing, of the wrong kind or past its bound',
  () => {
    const prompt = { text: '', echo: true };
    const refused = [
      '{"type":"ready","extra":1}',
      '{"type":"banner"}',
      '{"type":"banner","text":1}',
      `{"type":"banner","text":"${'b'.repeat(16385)}"}`,
      '{"type":"challenge","name":"","instruction":"","prompts":[]}',
      `{"type":"challenge","name":"","instruction":"","prompts":${JSON.stringify(Array(17).fill(prompt))}}`,
      '{"type":"challenge","name":"","instruction":"","prompts":[{"text":"","echo":1}]}',
      '{"type":"challenge","name":"","instruction":"","prompts":[{"text":""}]}',
      '{"type":"challenge","name":"","instruction":"","prompts":[{"text":"","echo":true,"hint":""}]}',
      '{"type":"challenge","name":"","instruction":"","prompts":[null]}',
      '{"type":"challenge","name":"","instruction":"","prompts":["Password: "]}',
      '{"type":"challenge","name":"","instruction":"","prompts":[[{"text":"","echo":true}]]}',
      `{"type":"challenge","name":"${'n'.repeat(4097)}","instruction":"","prompts":[{"text":"","echo":true}]}`,
      `{"type":"challenge","name":"","instruction":"","prompts":[{"text":"${'é'.repeat(513)}","echo":true}]}`,
      '{"type":"sign","id":0,"data":"AA==","flags":0}',
      '{"type":"sign","id":4294967296,"data":"AA==","flags":0}',
      '{"type":"sign","id":1.5,"data":"AA==","flags":0}',
      '{"type":"sign","id":1,"data":"AA=","flags":0}',
      '{"type":"sign","id":1,"data":"A*==","flags":0}',
      '{"type":"sign","id":1,"data":"","flags":0}',
      '{"type":"sign","id":1,"data":"AA==","flags":1}',
      '{"type":"exit","status":-1}',
      '{"type":"exit","status":"0"}',
      `{"type":"exit","signal":"${'S'.repeat(33)}"}`,
      '{"type":"exit","__proto__":{}}',
      '{"type":"hostkey"}',
      'null',
      '[]',
      '"ready"',
    ];
    for (const frame of refused) assert.equal(UWebSocket.parse(frame), null, frame.slice(0, 80));
  });

test('websocket: encode omits an empty password and an absent key', () => {
  const fields = { user: 'user01', password: '', cols: 80, rows: 24 };
  assert.equal(UWebSocket.encode('connect', fields), '{"type":"connect","user":"user01","cols":80,"rows":24}');
  assert.equal(UWebSocket.encode('connect', { ...fields, password: undefined, key: 'AAAA' }),
    '{"type":"connect","user":"user01","key":"AAAA","cols":80,"rows":24}');
});

test("websocket: text gives README's page text for every close code, and Connection lost. for 1006", async () => {
  const readme = await readFile(new URL('../../README.md', import.meta.url), 'utf8');
  const rows = readme.split('\n').filter((line) => /^\| \d{4} \| /.test(line));
  assert.equal(rows.length, 13);
  for (const row of rows) {
    const cells = row.split(' | ');
    const code = Number(cells[0].slice(2));
    assert.equal(UWebSocket.text(code), cells.at(-1).match(/^`([^`]+)`/)[1], String(code));
  }
  assert.equal(UWebSocket.text(1006), 'Connection lost.');
});

test('websocket: ended adds the exit status and signal to the text of 1000', () => {
  assert.equal(UWebSocket.ended({}), 'Session ended.');
  assert.equal(UWebSocket.ended({ status: 0 }), 'Session ended. Exit status 0.');
  assert.equal(UWebSocket.ended({ type: 'exit', status: 130, signal: 'INT' }),
    'Session ended. Exit status 130, signal INT.');
  assert.equal(UWebSocket.ended({ signal: 'KILL' }), 'Session ended. Signal KILL.');
});

test('websocket: url opens /ws on the page host, wss for https and ws for http', () => {
  assert.equal(UWebSocket.url(new URL('https://example.test:8443/index.html?x=1')), 'wss://example.test:8443/ws');
  assert.equal(UWebSocket.url(new URL('http://127.0.0.1:8080/')), 'ws://127.0.0.1:8080/ws');
});

test('websocket: sendInput cuts 20000 bytes into frames of 8192, 8192 and 3616 bytes, in order', () => {
  const fake = socket();
  const bytes = Uint8Array.from({ length: 20000 }, (_, index) => index % 251);
  new UWebSocket(fake, listener()).sendInput(bytes);
  assert.deepEqual(fake.sent.map((frame) => frame.length), [8192, 8192, 3616]);
  assert.deepEqual(Uint8Array.from(fake.sent.flatMap((frame) => [...frame])), bytes);
});

test('websocket: the listener hears the open, messages, binary output and the close code', () => {
  const fake = socket();
  const heard = listener();
  const ws = new UWebSocket(fake, heard);
  assert.equal(fake.binaryType, 'arraybuffer');
  fake.emit('open', {});
  fake.emit('message', { data: '{"type":"ready"}' });
  fake.emit('message', { data: Uint8Array.of(104, 105).buffer });
  fake.emit('close', { code: 4002 });
  fake.emit('close', { code: 1006 });
  assert.deepEqual(heard.heard, [['opened', ws], ['received', { type: 'ready' }], ['output', [104, 105]],
    ['closed', 4002]]);
});

test('websocket: a frame that is not the bridge closes with 1000 and reports 1008 once', () => {
  const fake = socket();
  const heard = listener();
  new UWebSocket(fake, heard);
  fake.emit('message', { data: '{"type":"hostkey"}' });
  fake.emit('message', { data: '{"type":"ready"}' });
  fake.emit('close', { code: 1000 });
  assert.deepEqual(fake.closed, [1000]);
  assert.deepEqual(heard.heard, [['closed', 1008]]);
});

test('websocket: after close the listener hears nothing more', () => {
  const fake = socket();
  const heard = listener();
  const ws = new UWebSocket(fake, heard);
  ws.send('resize', { cols: 132, rows: 43 });
  ws.close();
  fake.emit('open', {});
  fake.emit('message', { data: '{"type":"ready"}' });
  fake.emit('close', { code: 1000 });
  assert.deepEqual(fake.sent, ['{"type":"resize","cols":132,"rows":43}']);
  assert.deepEqual(fake.closed, [1000]);
  assert.deepEqual(heard.heard, []);
});

test('websocket: parse accepts bridge messages at every bound', () => {
  const prompts = (count, text) => Array.from({ length: count }, () => ({ text: text, echo: false }));
  const accepted = [
    { type: 'banner', text: 'é'.repeat(8192) },
    { type: 'challenge', name: 'n'.repeat(4096), instruction: 'i'.repeat(4096), prompts: prompts(16, '') },
    { type: 'challenge', name: '', instruction: '', prompts: prompts(1, 'é'.repeat(512)) },
    { type: 'sign', id: 1, data: 'AAAA', flags: 2 },
    { type: 'exit', status: 0, signal: 'S'.repeat(32) },
    { type: 'exit', status: 4294967295 },
  ];
  for (const message of accepted) {
    assert.deepEqual(UWebSocket.parse(JSON.stringify(message)), message, JSON.stringify(message).slice(0, 80));
  }
  const refused = [
    { type: 'challenge', name: '', instruction: 'i'.repeat(4097), prompts: prompts(1, '') },
    { type: 'challenge', name: '', instruction: '', prompts: prompts(1, 'é'.repeat(512)).concat({ text: '' }) },
    { type: 'sign', id: 1, data: 'AAAA', flags: 3 },
    { type: 'sign', id: 1, data: 'AAA=A===', flags: 0 },
    { type: 'sign', id: 1, data: 'AAA*', flags: 0 },
    { type: 'sign', id: 1, data: 'AAAA' },
    { type: 'sign', data: 'AAAA', flags: 0 },
    { type: 'sign', id: '1', data: 'AAAA', flags: 0 },
    { type: 'exit', status: 4294967296 },
    { type: 'exit', signal: 15 },
    { type: 'banner', text: 'é'.repeat(8193) },
    { type: 'challenge', name: 1, instruction: '', prompts: prompts(1, '') },
    { type: 'challenge', name: '', instruction: '', prompts: { text: '', echo: true } },
  ];
  for (const message of refused) assert.equal(UWebSocket.parse(JSON.stringify(message)), null, JSON.stringify(message));
});

test('websocket: sendInput sends nothing for no bytes and one frame for 8192', () => {
  const fake = socket();
  const ws = new UWebSocket(fake, listener());
  ws.sendInput(new Uint8Array(0));
  assert.deepEqual(fake.sent, []);
  ws.sendInput(new Uint8Array(8192).fill(7));
  ws.sendInput(new Uint8Array(16384).fill(8));
  assert.deepEqual(fake.sent.map((frame) => [frame.length, frame[0]]), [[8192, 7], [8192, 8], [8192, 8]]);
});

test('websocket: encode writes each message type of the page with its members in the protocol order', () => {
  const messages = [
    ['answers', { answers: ['secret-01'] }, '{"type":"answers","answers":["secret-01"]}'],
    ['signature', { signature: 'AAAA', id: 7 }, '{"type":"signature","id":7,"signature":"AAAA"}'],
    ['refusal', { id: 7 }, '{"type":"refusal","id":7}'],
    ['resize', { rows: 43, cols: 132 }, '{"type":"resize","cols":132,"rows":43}'],
    ['connect', { rows: 24, cols: 80, key: 'AAAA', password: 'pw', user: 'user01' },
      '{"type":"connect","user":"user01","password":"pw","key":"AAAA","cols":80,"rows":24}'],
  ];
  for (const [type, fields, frame] of messages) assert.equal(UWebSocket.encode(type, fields), frame, type);
});

test('websocket: parse refuses a challenge, sign or prompt that lacks a member', () => {
  const prompt = { text: 'Password: ', echo: false };
  const refused = [
    { type: 'challenge', instruction: '', prompts: [prompt] },
    { type: 'challenge', name: '', prompts: [prompt] },
    { type: 'challenge', name: '', instruction: '' },
    { type: 'challenge', name: '', instruction: '', prompts: [{ echo: false }] },
    { type: 'sign', id: 1, flags: 0 },
  ];
  for (const message of refused) assert.equal(UWebSocket.parse(JSON.stringify(message)), null, JSON.stringify(message));
});

test('websocket: encode omits an empty key', () => {
  assert.equal(UWebSocket.encode('connect', { user: 'user01', password: 'pw', key: '', cols: 80, rows: 24 }),
    '{"type":"connect","user":"user01","password":"pw","cols":80,"rows":24}');
});

test('websocket: url replaces only a leading http of the address', () => {
  assert.equal(UWebSocket.url(new URL('ftp://http.example.test/')), 'ftp://http.example.test/ws');
});

test('websocket: encode omits a password or key that is null', () => {
  assert.equal(UWebSocket.encode('connect', { user: 'user01', password: null, key: null, cols: 80, rows: 24 }),
    '{"type":"connect","user":"user01","cols":80,"rows":24}');
});
